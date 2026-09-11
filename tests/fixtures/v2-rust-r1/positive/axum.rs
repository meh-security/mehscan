use axum::{
    extract::{Json, Path as RoutePath, Query},
    response::{Html, Redirect},
};
use std::process::Command;

async fn run(RoutePath(command): RoutePath<String>) {
    Command::new(command).spawn();
}

async fn read_file(RoutePath(path): RoutePath<String>) {
    let _ = std::fs::read_to_string(path);
}

async fn fetch(Query(url): Query<String>) {
    let _ = reqwest::get(url).await;
}

async fn lookup(Query(query): Query<String>) {
    let _ = sqlx::query(&query).fetch_all(pool()).await;
}

async fn redirect(Query(next): Query<String>) -> Redirect {
    Redirect::to(&next)
}

async fn render(Query(name): Query<String>) -> Html<String> {
    Html(format!("<b>{name}</b>"))
}

async fn decode(Json(payload): Json<String>) {
    let _: serde_json::Value = serde_json::from_str(&payload).unwrap();
}
