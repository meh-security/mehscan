use actix_web::HttpRequest;
use std::process::Command;

async fn run(request: HttpRequest) {
    let command = request.match_info().get("command").unwrap_or("");
    Command::new(command).spawn();
}

async fn fetch(request: HttpRequest) {
    let target = request.query_string();
    let _ = reqwest::get(target).await;
}
