use axum::response::{Html, Redirect};
use std::process::Command;

fn fixed_operations() {
    Command::new("date").spawn();
    let _ = std::fs::read_to_string("/etc/application.conf");
    let _ = std::fs::write("/tmp/application.out", "safe");
    let _ = reqwest::get("https://example.com/health");
    let _ = sqlx::query("SELECT id FROM users WHERE active = true");
    let _ = serde_json::from_str::<serde_json::Value>("{}");
    let _ = Redirect::to("/home");
    let _ = Html("<p>fixed</p>");
}
