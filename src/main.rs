use actix_web::{App, HttpServer, web};
use actix_web::{Error as ActixError, error::ErrorUnauthorized};
use actix_web::{dev::ServiceRequest, middleware};
use actix_web_httpauth::extractors::basic::BasicAuth;
use actix_web_httpauth::middleware::HttpAuthentication;
use clap::Parser;
use dav_server::actix::*;
use dav_server::{DavConfig, DavHandler, fakels::FakeLs, localfs::LocalFs};
use env_logger::Env;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct AuthConfig {
    username: String,
    password: Option<String>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    addr: Option<SocketAddrV4>,
    #[arg(short, long)]
    user: Option<String>,
    #[arg(short, long)]
    pass: Option<String>,
    #[arg(short, long)]
    dir: Option<String>,
}

// Basic Auth 验证函数
async fn do_auth(
    req: ServiceRequest,
    creds: BasicAuth,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
    let auth_config = req.app_data::<Option<AuthConfig>>().unwrap();
    if let Some(auth_config) = auth_config {
        println!(
            "Auth config: {:?} {:?} {:?}",
            auth_config,
            creds.user_id(),
            creds.password()
        );
        return if creds.user_id() == auth_config.username
            && creds.password() == auth_config.password.as_ref().map(|v| v.as_str())
        {
            Ok(req)
        } else {
            Err((ErrorUnauthorized("unauthorized"), req))
        };
    }
    Ok(req)
}

pub async fn dav_handler(req: DavRequest, dav_handler: web::Data<DavHandler>) -> DavResponse {
    if let Some(prefix) = req.prefix() {
        let config = DavConfig::new().strip_prefix(prefix);
        dav_handler.handle_with(config, req.request).await.into()
    } else {
        dav_handler.handle(req.request).await.into()
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let addr = args
        .addr
        .unwrap_or(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 4918));
    let dir = if let Some(dir) = args.dir {
        let path = PathBuf::from(dir);
        if !path.is_dir() {
            panic!("dir must be a directory");
        }
        path
    } else {
        std::env::current_dir()?
    };
    let auth_config = if let Some(user) = args.user {
        Some(AuthConfig {
            username: user,
            password: args.pass,
        })
    } else {
        None
    };
    let dav_server = DavHandler::builder()
        .filesystem(LocalFs::new(dir.as_path(), false, false, false))
        .locksystem(FakeLs::new())
        .build_handler();

    log::info!(
        "service on addr {} with the directory {}",
        addr,
        dir.as_path().to_string_lossy()
    );

    if auth_config.is_some() {
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
    } else {
        HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::default()) // 启用日志
                .app_data(web::Data::new(dav_server.clone()))
                .service(web::resource("/{tail:.*}").to(dav_handler))
        })
        .bind(addr)?
        .run()
        .await
    }
}
