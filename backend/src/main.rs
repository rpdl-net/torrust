use actix_contrib_logger::middleware::Logger;
use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use log::Level;
use reqwest::StatusCode;
use std::sync::Arc;
use torrust::auth::AuthorizationService;
use torrust::common::AppData;
use torrust::config::Configuration;
use torrust::database::SqliteDatabase;
use torrust::handlers;
use torrust::handlers::user::{DbUserRepository, RegistrationService, Repository};
use torrust::mailer::MailerService;
use torrust::tracker::TrackerService;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cfg = match Configuration::load_from_file().await {
        Ok(config) => Arc::new(config),
        Err(error) => {
            panic!("{}", error)
        }
    };

    let settings = cfg.settings.read().await;

    let database = Arc::new(SqliteDatabase::new(&settings.database.connect_url).await);
    let auth = Arc::new(AuthorizationService::new(cfg.clone(), database.clone()));
    let tracker_service = Arc::new(TrackerService::new(cfg.clone(), database.clone()));
    let mailer_service = Arc::new(MailerService::new(cfg.clone()).await);
    let user_repository: Arc<Box<dyn Repository>> =
        Arc::new(Box::new(DbUserRepository::new(database.clone())));

    let registration_service = Arc::new(RegistrationService::new(
        cfg.clone(),
        mailer_service.clone(),
        user_repository.clone(),
        // user_profile_repository.clone(),
    ));

    let app_data = Arc::new(AppData::new(
        cfg.clone(),
        database.clone(),
        auth.clone(),
        tracker_service.clone(),
        mailer_service.clone(),
        registration_service.clone(),
    ));

    // create/update database tables
    let _ = sqlx::migrate!().run(&database.pool).await;

    // create torrent upload folder
    async_std::fs::create_dir_all(&settings.storage.upload_path).await?;

    let interval = settings.database.torrent_info_update_interval;
    let weak_tracker_service = std::sync::Arc::downgrade(&tracker_service);

    // repeating task, update all seeders and leechers info
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(interval);
        let mut interval = tokio::time::interval(interval);
        interval.tick().await; // first tick is immediate...
        loop {
            interval.tick().await;
            if let Some(tracker) = weak_tracker_service.upgrade() {
                let _ = tracker.update_torrents().await;
            } else {
                break;
            }
        }
    });

    let port = settings.net.port;

    drop(settings);

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("error"));

    println!("Listening on 0.0.0.0:{}", port);

    HttpServer::new(move || {
        let logger = Logger::default().custom_level(|status| {
            if status.is_server_error() {
                Level::Error
            } else if status == StatusCode::NOT_FOUND {
                Level::Warn
            } else {
                Level::Info
            }
        });

        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(app_data.clone()))
            .wrap(logger)
            .configure(handlers::init_routes)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
