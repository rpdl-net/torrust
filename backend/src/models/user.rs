use serde::{Deserialize, Serialize};

#[allow(clippy::module_name_repetitions)]
pub type UserId = i64;

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct User {
    pub user_id: UserId,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub password: String,
    pub administrator: bool,
}

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct Claims {
//     pub sub: String, // username
//     pub admin: bool,
//     pub exp: u64, // epoch in seconds
// }

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserClaims {
    pub user: UserCompact,
    pub exp: u64, // epoch in seconds
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct UserCompact {
    pub user_id: UserId,
    pub username: String,
    pub administrator: bool,
}
