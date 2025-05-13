use crate::common::WebAppData;
use crate::config::Configuration;
use crate::config::EmailOnSignup;
use crate::database::SqliteDatabase;
use crate::mailer;
use crate::mailer::VerifyClaims;
use crate::models::response::OkResponse;
use crate::models::response::TokenResponse;
use crate::models::user::UserCompact;
use crate::models::user::UserId;
use crate::utils::random::random_string;
use crate::{
    errors::{ServiceError, ServiceResult},
    utils::time::current_time,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use async_trait::async_trait;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::log;
use log::Level;
use pbkdf2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .service(web::resource("/register").route(web::post().to(register)))
            .service(web::resource("/login").route(web::post().to(login)))
            .service(web::resource("/ban/{user}").route(web::delete().to(ban_user)))
            .service(web::resource("/token/verify").route(web::post().to(verify_token)))
            .service(web::resource("/token/renew").route(web::post().to(renew_token_handler)))
            .service(web::resource("/email/verify/{token}").route(web::get().to(verify_email))),
    );
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Register {
    pub username: String,
    pub email: Option<String>,
    pub password: String,
    pub confirm_password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Login {
    pub login: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Token {
    pub token: String,
}

pub struct RegistrationService {
    configuration: Arc<Configuration>,
    #[allow(unused)]
    mailer: Arc<mailer::MailerService>,
    user_repository: Arc<Box<dyn Repository>>,
    // V3 feature
    // user_profile_repository: Arc<DbUserProfileRepository>,
}

impl RegistrationService {
    #[must_use]
    pub fn new(
        configuration: Arc<Configuration>,
        mailer: Arc<mailer::MailerService>,
        user_repository: Arc<Box<dyn Repository>>,
        // user_profile_repository: Arc<DbUserProfileRepository>,
    ) -> Self {
        Self {
            configuration,
            mailer,
            user_repository,
            // user_profile_repository,
        }
    }

    pub async fn renew_token(
        &self,
        payload: web::Json<Token>,
        app_data: &WebAppData,
    ) -> Result<(String, UserCompact), ServiceError> {
        // verify if token is valid
        let claims = app_data.auth.verify_jwt(&payload.token).await;

        // If claims are valid, we will return the original token with the compact user
        // Else we retrieve the JWT if the grace period has not expired
        let claims = match claims {
            Ok(claims) => claims,
            Err(_) => app_data.auth.decode_jwt(&payload.token).await?,
        };

        let user_compact = self
            .user_repository
            .get_compact(&claims.user.user_id)
            .await
            .map_err(|_| ServiceError::UsernameNotFound)?;

        let settings = self.configuration.settings.read().await;

        // renew token if it is invalid for less than grace period
        let time_checked = current_time();
        let grace_time = settings.auth.renewal_grace_time;
        drop(settings);
        let token: String;
        if claims.exp + grace_time < time_checked {
            Err(ServiceError::TokenExpired)
        } else {
            if claims.exp < time_checked {
                token = app_data.auth.sign_jwt(user_compact.clone()).await
            } else {
                token = payload.token.clone()
            }
            Ok((token, user_compact))
        }
    }
}

pub async fn register(
    req: HttpRequest,
    mut payload: web::Json<Register>,
    app_data: WebAppData,
) -> ServiceResult<impl Responder> {
    let settings = app_data.cfg.settings.read().await;

    match settings.auth.email_on_signup {
        EmailOnSignup::Required => {
            if payload.email.is_none() {
                return Err(ServiceError::EmailMissing);
            }
        }
        EmailOnSignup::None => payload.email = None,
        _ => {}
    }

    if payload.password != payload.confirm_password {
        return Err(ServiceError::PasswordsDontMatch);
    }

    let password_length = payload.password.len();
    if password_length <= settings.auth.min_password_length {
        return Err(ServiceError::PasswordTooShort);
    }
    if password_length >= settings.auth.max_password_length {
        return Err(ServiceError::PasswordTooLong);
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash;
    if let Ok(password) = Pbkdf2.hash_password(payload.password.as_bytes(), &salt) {
        password_hash = password.to_string();
    } else {
        return Err(ServiceError::InternalServerError);
    }

    if payload.username.contains('@') {
        return Err(ServiceError::UsernameInvalid);
    }

    // can't drop not null constraint on sqlite, so we fill the email with unique junk :)
    let email = payload
        .email
        .as_ref()
        .unwrap_or(&format!("EMPTY_EMAIL_{}", random_string(16)))
        .to_string();

    let res = sqlx::query!(
        "INSERT INTO torrust_users (username, email, password) VALUES ($1, $2, $3)",
        payload.username,
        email,
        password_hash,
    )
    .execute(&app_data.database.pool)
    .await;

    if let Err(sqlx::Error::Database(err)) = res {
        return if err.code() == Some(Cow::from("2067")) {
            if err.message().contains("torrust_users.username") {
                Err(ServiceError::UsernameTaken)
            } else if err.message().contains("torrust_users.email") {
                Err(ServiceError::EmailTaken)
            } else {
                Err(ServiceError::InternalServerError)
            }
        } else {
            Err(sqlx::Error::Database(err).into())
        };
    }

    // count accounts
    let res_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM torrust_users")
        .fetch_one(&app_data.database.pool)
        .await?;

    // make admin if first account
    if res_count.0 == 1 {
        let _res_make_admin = sqlx::query!("UPDATE torrust_users SET administrator = 1")
            .execute(&app_data.database.pool)
            .await;
    }

    let conn_info = req.connection_info();

    if settings.mail.email_verification_enabled && payload.email.is_some() {
        let mail_res = app_data
            .mailer
            .send_verification_mail(
                &payload.email.as_ref().unwrap(),
                &payload.username,
                format!("{}://{}", conn_info.scheme(), conn_info.host()).as_str(),
            )
            .await;

        // get user id from user insert res
        let user_id = res.unwrap().last_insert_rowid();

        if mail_res.is_err() {
            let _ = app_data.database.delete_user(user_id).await;
            return Err(ServiceError::FailedToSendVerificationEmail);
        }
    } else {
    }

    Ok(HttpResponse::Ok())
}

pub async fn login(
    payload: web::Json<Login>,
    app_data: WebAppData,
) -> ServiceResult<impl Responder> {
    let settings = app_data.cfg.settings.read().await;

    let res = app_data
        .database
        .get_user_with_username(&payload.login)
        .await;

    match res {
        Some(user) => {
            if settings.mail.email_verification_enabled && !user.email_verified {
                return Err(ServiceError::EmailNotVerified);
            }
            log!(Level::Debug, "User email ok.");
            drop(settings);

            let parsed_hash = PasswordHash::new(&user.password)?;

            if !Pbkdf2
                .verify_password(payload.password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                return Err(ServiceError::WrongPasswordOrUsername);
            }
            log!(Level::Debug, "Password ok.");

            let user_compact = app_data
                .database
                .get_user_compact_from_id(user.user_id)
                .await
                .map_err(|_| ServiceError::UsernameNotFound)?;

            log!(Level::Debug, "Compact user ok.");

            let token = app_data.auth.sign_jwt(user_compact.clone()).await;

            log!(Level::Debug, "Token ok.");
            // let username = user_compact.username;

            Ok(HttpResponse::Ok().json(OkResponse {
                data: TokenResponse {
                    token,
                    username: user_compact.username,
                    admin: user.administrator,
                },
            }))
        }
        None => Err(ServiceError::WrongPasswordOrUsername),
    }
}
pub async fn verify_token(
    payload: web::Json<Token>,
    app_data: WebAppData,
) -> ServiceResult<impl Responder> {
    // verify if token is valid
    let _claims = app_data.auth.verify_jwt(&payload.token).await?;

    Ok(HttpResponse::Ok().json(OkResponse {
        data: format!("Token is valid."),
    }))
}

/// It renews the JWT.
///
/// # Errors
///
/// It returns an error if:
///
/// - Unable to parse the supplied payload as a valid JWT.
/// - The JWT is not invalid or expired.
#[allow(clippy::unused_async)]
pub async fn renew_token_handler(
    payload: web::Json<Token>,
    app_data: WebAppData,
) -> ServiceResult<impl Responder> {
    match app_data
        .registration_service
        .renew_token(payload, &app_data)
        .await
    {
        Ok((token, user_compact)) => Ok(HttpResponse::Ok().json(OkResponse {
            data: TokenResponse {
                token,
                username: user_compact.username,
                admin: user_compact.administrator,
            },
        })),
        Err(error) => Err(error),
    }
}

pub async fn verify_email(req: HttpRequest, app_data: WebAppData) -> String {
    let settings = app_data.cfg.settings.read().await;
    let token = req.match_info().get("token").unwrap();

    let token_data = match decode::<VerifyClaims>(
        token,
        &DecodingKey::from_secret(settings.auth.secret_key.as_bytes()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(token_data) => {
            if !token_data.claims.iss.eq("email-verification") {
                return ServiceError::TokenInvalid.to_string();
            }

            token_data.claims
        }
        Err(_) => return ServiceError::TokenInvalid.to_string(),
    };

    drop(settings);

    let res = sqlx::query!(
        "UPDATE torrust_users SET email_verified = TRUE WHERE username = ?",
        token_data.sub
    )
    .execute(&app_data.database.pool)
    .await;

    if let Err(_) = res {
        return ServiceError::InternalServerError.to_string();
    }

    String::from("Email verified, you can close this page.")
}

pub async fn ban_user(req: HttpRequest, app_data: WebAppData) -> ServiceResult<impl Responder> {
    let user = app_data.auth.get_user_from_request(&req).await?;

    // check if user is administrator
    if !user.administrator {
        return Err(ServiceError::Unauthorized);
    }

    let to_be_banned_username = req.match_info().get("user").unwrap();

    let res = sqlx::query!(
        "DELETE FROM torrust_users WHERE username = ? AND administrator = 0",
        to_be_banned_username
    )
    .execute(&app_data.database.pool)
    .await;

    if let Err(_) = res {
        return Err(ServiceError::UsernameNotFound);
    }
    if res.unwrap().rows_affected() == 0 {
        return Err(ServiceError::UsernameNotFound);
    }

    Ok(HttpResponse::Ok().json(OkResponse {
        data: format!("Banned user: {}", to_be_banned_username),
    }))
}

pub async fn me(req: HttpRequest, app_data: WebAppData) -> ServiceResult<impl Responder> {
    let user = match app_data.auth.get_user_from_request(&req).await {
        Ok(user) => Ok(user),
        Err(e) => Err(e),
    }?;

    let user_compact = app_data
        .database
        .get_user_compact_from_id(user.user_id)
        .await
        .map_err(|_| ServiceError::UsernameNotFound)?;

    let token = app_data.auth.sign_jwt(user_compact.clone()).await;

    Ok(HttpResponse::Ok().json(OkResponse {
        data: TokenResponse {
            token,
            username: user_compact.username,
            admin: user.administrator,
        },
    }))
}

// #[cfg_attr(test, automock)]
#[async_trait]
pub trait Repository: Sync + Send {
    async fn get_compact(&self, user_id: &UserId) -> Result<UserCompact, ServiceError>;
    // async fn grant_admin_role(&self, user_id: &UserId) -> Result<(), Error>;
    // async fn delete(&self, user_id: &UserId) -> Result<(), Error>;
    // async fn add(&self, username: &str, email: &str, password_hash: &str) -> Result<UserId, Error>;
}

pub struct DbUserRepository {
    database: Arc<SqliteDatabase>,
}

impl DbUserRepository {
    #[must_use]
    pub fn new(database: Arc<SqliteDatabase>) -> Self {
        Self { database }
    }
}

#[async_trait]
impl Repository for DbUserRepository {
    /// It returns the compact user.
    ///
    /// # Errors
    ///
    /// It returns an error if there is a database error.
    async fn get_compact(&self, user_id: &UserId) -> Result<UserCompact, ServiceError> {
        // todo: persistence layer should have its own errors instead of
        // returning a `ServiceError`.
        self.database
            .get_user_compact_from_id(*user_id)
            .await
            .map_err(|_| ServiceError::UsernameNotFound)
    }

    // It grants the admin role to the user.
    //
    // # Errors
    //
    // It returns an error if there is a database error.
    // async fn grant_admin_role(&self, user_id: &UserId) -> Result<(), Error> {
    //     self.database.grant_admin_role(*user_id).await
    // }

    // It deletes the user.
    //
    // # Errors
    //
    // It returns an error if there is a database error.
    // async fn delete(&self, user_id: &UserId) -> Result<(), Error> {
    //     self.database.delete_user(*user_id).await
    // }

    // It adds a new user.
    //
    // # Errors
    //
    // It returns an error if there is a database error.
    // async fn add(&self, username: &str, email: &str, password_hash: &str) -> Result<UserId, Error> {
    //     self.database
    //         .insert_user_and_get_id(username, email, password_hash)
    //         .await
    // }
}

#[cfg(test)]
mod tests {
    use pbkdf2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Pbkdf2,
    };

    #[test]
    fn password_hash() {
        // dotenvy::dotenv().ok();
        // let connection_string = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        // let pool = SqlitePoolOptions::new()
        //     .connect(database_url)
        //     .await
        //     .expect("Unable to create database pool");

        let salt = SaltString::generate(&mut OsRng);
        let password_hash;
        if let Ok(password) = Pbkdf2.hash_password("toto".as_bytes(), &salt) {
            password_hash = password.to_string();
        } else {
            password_hash = "".to_owned();
            assert!(false);
        }
        println!("{}", password_hash);
        assert!(true);
    }
}
