use actix_web::{HttpResponse, Responder};
use sqlx::SqlitePool;

async fn static_page() -> impl Responder {
    let html_content = include_str!("template.html");
    HttpResponse::Ok().content_type("text/html").body(html_content)
}

async fn static_page_with_literal_placeholders() -> impl Responder {
    let html_content = include_str!("template.html");
    let response_body = html_content
        .replace("{{message_type}}", "")
        .replace("{{status_message}}", "ready");
    HttpResponse::Ok().content_type("text/html").body(response_body)
}

async fn migration(pool: &SqlitePool) {
    sqlx::query(include_str!("migration.sql"))
        .execute(pool)
        .await
        .unwrap();
}

async fn dynamic_page(user_input: String) -> impl Responder {
    let html_content = include_str!("template.html");
    let response_body = html_content.replace("{{message}}", &user_input);
    HttpResponse::Ok().content_type("text/html").body(response_body)
}
