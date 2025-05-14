use crate::auth::AuthorizationService;
use crate::config::Configuration;
use crate::database::SqliteDatabase;
use crate::handlers::user::RegistrationService;
use crate::mailer::MailerService;
use crate::tracker::TrackerService;
use std::sync::Arc;

pub type Username = String;

pub type WebAppData = actix_web::web::Data<Arc<AppData>>;

pub struct AppData {
    pub cfg: Arc<Configuration>,
    pub database: Arc<SqliteDatabase>,
    pub auth: Arc<AuthorizationService>,
    pub tracker: Arc<TrackerService>,
    pub mailer: Arc<MailerService>,
    // Services
    pub registration_service: Arc<RegistrationService>,
}

impl AppData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Arc<Configuration>,
        database: Arc<SqliteDatabase>,
        auth: Arc<AuthorizationService>,
        tracker: Arc<TrackerService>,
        mailer: Arc<MailerService>,
        // Services
        registration_service: Arc<RegistrationService>,
    ) -> AppData {
        AppData {
            cfg,
            database,
            auth,
            tracker,
            mailer,
            registration_service,
        }
    }
}
