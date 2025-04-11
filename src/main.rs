use std::io;

use actix_web::{App, HttpServer, web};
use actix_web::{dev::ServiceRequest, middleware};
use actix_web_httpauth::extractors::basic::{BasicAuth, Config as AuthConfig};
use actix_web_httpauth::middleware::HttpAuthentication;
use dav_server::actix::*;
use dav_server::{DavConfig, DavHandler, fakels::FakeLs, localfs::LocalFs};

use actix_web::{Error as ActixError, error::ErrorUnauthorized};

// Basic Auth 验证函数
async fn do_auth(
    req: ServiceRequest,
    creds: BasicAuth,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
    if creds.user_id() == "user" && creds.password() == Some("hunter2") {
        Ok(req)
    } else {
        Err((ErrorUnauthorized("nope"), req))
    }
}

pub async fn dav_handler(req: DavRequest, davhandler: web::Data<DavHandler>) -> DavResponse {
    if let Some(prefix) = req.prefix() {
        let config = DavConfig::new().strip_prefix(prefix);
        davhandler.handle_with(config, req.request).await.into()
    } else {
        davhandler.handle(req.request).await.into()
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let addr = "127.0.0.1:4918";
    let dir = "E:\\dav";
    let auth_config = AuthConfig::default().realm("Restricted Area");
    let dav_server = DavHandler::builder()
        .filesystem(LocalFs::new(dir, false, false, false))
        .locksystem(FakeLs::new())
        .build_handler();

    println!("actix-web example: listening on {} serving {}", addr, dir);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default()) // 启用日志
            .app_data(auth_config.clone())
            .app_data(web::Data::new(dav_server.clone()))
            .wrap(HttpAuthentication::basic(do_auth))
            .service(web::resource("/{tail:.*}").to(dav_handler))
    })
    .bind(addr)?
    .run()
    .await
}
