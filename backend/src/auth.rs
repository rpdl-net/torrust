use crate::config::Configuration;
use crate::database::SqliteDatabase;
use crate::errors::ServiceError;
use crate::models::user::{User, UserClaims, UserCompact};
use crate::utils::time::current_time;
use actix_web::HttpRequest;
use jsonwebtoken::{
    dangerous_insecure_decode, decode, encode, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use log::{log, Level};
use std::sync::Arc;

pub struct AuthorizationService {
    cfg: Arc<Configuration>,
    database: Arc<SqliteDatabase>,
}

impl AuthorizationService {
    pub fn new(cfg: Arc<Configuration>, database: Arc<SqliteDatabase>) -> AuthorizationService {
        AuthorizationService { cfg, database }
    }

    pub async fn sign_jwt(&self, user: UserCompact) -> String {
        let settings = self.cfg.settings.read().await;

        // create JWT that expires in two weeks
        let key = settings.auth.secret_key.as_bytes();
        let exp_date = current_time() + settings.auth.session_duration_seconds; // two weeks from now

        let claims = UserClaims {
            user: user,
            exp: exp_date,
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(key)).unwrap();

        token
    }

    pub async fn verify_jwt(&self, token: &str) -> Result<UserClaims, ServiceError> {
        match self.decode_token(token).await {
            Ok(claims) => {
                if claims.exp < current_time() {
                    log!(Level::Debug, "Token validity expired");
                    return Err(ServiceError::TokenExpired);
                }
                Ok(claims)
            }
            Err(_) => Err(ServiceError::TokenInvalid),
        }
    }

    pub async fn decode_jwt(&self, token: &str) -> Result<UserClaims, ServiceError> {
        let settings = self.cfg.settings.read().await;

        match self.decode_token(token).await {
            Ok(claims) => {
                if claims.exp + settings.auth.renewal_grace_time < current_time() {
                    log!(Level::Debug, "Token extended validity expired");
                    return Err(ServiceError::TokenExpired);
                }
                Ok(claims)
            }
            Err(_) => Err(ServiceError::TokenInvalid),
        }
    }

    async fn decode_token(&self, token: &str) -> Result<UserClaims, ServiceError> {
        let settings = self.cfg.settings.read().await;

        match decode::<UserClaims>(
            token,
            &DecodingKey::from_secret(settings.auth.secret_key.as_bytes()),
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(claims) => Ok(claims.claims),
            Err(e) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    Ok(dangerous_insecure_decode::<UserClaims>(token)
                        .unwrap()
                        .claims)
                }
                _ => {
                    log!(Level::Debug, "{:#?}", e.kind());
                    Err(ServiceError::TokenInvalid)
                }
            },
        }
    }

    pub async fn get_claims_from_request(
        &self,
        req: &HttpRequest,
    ) -> Result<UserClaims, ServiceError> {
        let _auth = req.headers().get("Authorization");
        match _auth {
            Some(_) => {
                let _split: Vec<&str> = _auth.unwrap().to_str().unwrap().split("Bearer").collect();
                let token = _split[1].trim();

                match self.verify_jwt(token).await {
                    Ok(claims) => Ok(claims),
                    Err(e) => Err(e),
                }
            }
            None => Err(ServiceError::TokenNotFound),
        }
    }

    pub async fn get_user_from_request(&self, req: &HttpRequest) -> Result<User, ServiceError> {
        let claims = match self.get_claims_from_request(req).await {
            Ok(claims) => Ok(claims),
            Err(e) => Err(e),
        }?;

        match self
            .database
            .get_user_with_username(&claims.user.username)
            .await
        {
            Some(user) => Ok(user),
            None => Err(ServiceError::AccountNotFound),
        }
    }
}
