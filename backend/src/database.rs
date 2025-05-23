use crate::errors::ServiceError;
use crate::models::torrent::TorrentListing;
use crate::models::tracker_key::TrackerKey;
use crate::models::user::{User, UserCompact};
use crate::utils::time::current_time;
use serde::Serialize;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{query_as, SqlitePool};

/// Database errors.
#[derive(Debug)]
pub enum Error {
    Error,
    ErrorWithText(String),
    UnrecognizedDatabaseDriver, // when the db path does not start with sqlite or mysql
    UsernameTaken,
    EmailTaken,
    UserNotFound,
    CategoryNotFound,
    TagAlreadyExists,
    TagNotFound,
    TorrentNotFound,
    TorrentAlreadyExists, // when uploading an already uploaded info_hash
    TorrentTitleAlreadyExists,
    TorrentInfoHashNotFound,
}

#[derive(Debug, Serialize)]
pub struct TorrentCompact {
    pub torrent_id: i64,
    pub info_hash: String,
}

// pub trait Database: Sync + Send {
//     async fn get_user_with_username(&self, username: &str) -> Option<User>;
//     async fn delete_user(&self, user_id: i64) -> Result<(), sqlx::Error>;
//     async fn insert_torrent_and_get_id(
//         &self,
//         username: String,
//         info_hash: String,
//         title: String,
//         category_id: i64,
//         description: String,
//         file_size: i64,
//         seeders: i64,
//         leechers: i64,
//     ) -> Result<i64, sqlx::Error>;
//     async fn get_torrent_by_id(&self, torrent_id: i64) -> Result<TorrentListing, ServiceError>;
//     async fn get_all_torrent_ids(&self) -> Result<Vec<TorrentCompact>, ()>;
//     async fn update_tracker_info(
//         &self,
//         info_hash: &str,
//         seeders: i64,
//         leechers: i64,
//     ) -> Result<(), ()>;
//     async fn get_valid_tracker_key(&self, user_id: i64) -> Option<TrackerKey>;
//     async fn issue_tracker_key(
//         &self,
//         tracker_key: &TrackerKey,
//         user_id: i64,
//     ) -> Result<(), ServiceError>;
//     async fn verify_category(&self, category: &str) -> Option<String>;
//     async fn get_user_compact_from_id(&self, user_id: i64) -> Result<UserCompact, Error>;
// }

pub struct SqliteDatabase {
    pub pool: SqlitePool,
}

pub struct Category {
    pub name: String,
}

impl SqliteDatabase {
    pub async fn new(database_url: &str) -> SqliteDatabase {
        let db = SqlitePoolOptions::new()
            .connect(database_url)
            .await
            .expect("Unable to create database pool");

        SqliteDatabase { pool: db }
    }

    pub async fn get_user_with_username(&self, username: &str) -> Option<User> {
        let res = sqlx::query_as!(
            User,
            "SELECT * FROM torrust_users WHERE username = ?",
            username,
        )
        .fetch_one(&self.pool)
        .await;

        match res {
            Ok(user) => Some(user),
            _ => None,
        }
    }

    pub async fn delete_user(&self, user_id: i64) -> Result<(), sqlx::Error> {
        let _res = sqlx::query!("DELETE FROM torrust_users WHERE rowid = ?", user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn insert_torrent_and_get_id(
        &self,
        username: String,
        info_hash: String,
        title: String,
        category_id: i64,
        description: String,
        file_size: i64,
        seeders: i64,
        leechers: i64,
    ) -> Result<i64, sqlx::Error> {
        let current_time = current_time() as i64;

        let res = sqlx::query!(
            r#"INSERT INTO torrust_torrents (uploader, info_hash, title, category_id, description, upload_date, file_size, seeders, leechers)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING torrent_id as "torrent_id: i64""#,
            username,
            info_hash,
            title,
            category_id,
            description,
            current_time,
            file_size,
            seeders,
            leechers
        )
            .fetch_one(&self.pool)
            .await?;

        Ok(res.torrent_id)
    }

    pub async fn get_torrent_by_id(&self, torrent_id: i64) -> Result<TorrentListing, ServiceError> {
        let res = sqlx::query_as!(
            TorrentListing,
            r#"SELECT * FROM torrust_torrents
               WHERE torrent_id = ?"#,
            torrent_id
        )
        .fetch_one(&self.pool)
        .await;

        match res {
            Ok(torrent) => Ok(torrent),
            _ => Err(ServiceError::TorrentNotFound),
        }
    }

    pub async fn get_all_torrent_ids(&self) -> Result<Vec<TorrentCompact>, ()> {
        let res = sqlx::query_as!(
            TorrentCompact,
            r#"SELECT torrent_id, info_hash FROM torrust_torrents"#
        )
        .fetch_all(&self.pool)
        .await;

        match res {
            Ok(torrents) => Ok(torrents),
            Err(e) => {
                println!("{:?}", e);
                Err(())
            }
        }
    }

    pub async fn update_tracker_info(
        &self,
        info_hash: &str,
        seeders: i64,
        leechers: i64,
    ) -> Result<(), ()> {
        let res = sqlx::query!(
            "UPDATE torrust_torrents SET seeders = $1, leechers = $2 WHERE info_hash = $3",
            seeders,
            leechers,
            info_hash
        )
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok(()),
            _ => Err(()),
        }
    }

    pub async fn get_valid_tracker_key(&self, user_id: i64) -> Option<TrackerKey> {
        const WEEK: i64 = 604_800;
        let current_time_plus_week = (current_time() as i64) + WEEK;

        let res = sqlx::query_as!(
            TrackerKey,
            r#"SELECT key, valid_until FROM torrust_tracker_keys
               WHERE user_id = $1 AND valid_until > $2"#,
            user_id,
            current_time_plus_week
        )
        .fetch_one(&self.pool)
        .await;

        match res {
            Ok(tracker_key) => Some(tracker_key),
            _ => None,
        }
    }

    pub async fn issue_tracker_key(
        &self,
        tracker_key: &TrackerKey,
        user_id: i64,
    ) -> Result<(), ServiceError> {
        let res = sqlx::query!(
            "INSERT INTO torrust_tracker_keys (user_id, key, valid_until) VALUES ($1, $2, $3)",
            user_id,
            tracker_key.key,
            tracker_key.valid_until,
        )
        .execute(&self.pool)
        .await;

        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(ServiceError::InternalServerError),
        }
    }

    pub async fn verify_category(&self, category: &str) -> Option<String> {
        let res = sqlx::query_as!(
            Category,
            "SELECT name FROM torrust_categories WHERE name = ?",
            category
        )
        .fetch_one(&self.pool)
        .await;

        match res {
            Ok(v) => Some(v.name),
            Err(_) => None,
        }
    }

    pub async fn get_user_compact_from_id(&self, user_id: i64) -> Result<UserCompact, Error> {
        query_as::<_, UserCompact>("SELECT tu.user_id, tu.username, tu.administrator FROM torrust_users tu WHERE tu.user_id = ?")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| Error::UserNotFound)
    }
}
