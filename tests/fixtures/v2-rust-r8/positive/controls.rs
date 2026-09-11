use std::path::Path;
use std::process::Command;
use url::Url;

fn separated_process(program: &str, value: &str) {
    Command::new(program).arg(value).spawn().unwrap();
    std::process::Command::new(program)
        .args(["--name", value])
        .spawn()
        .unwrap();
}

fn checked_url(raw: &str, allowed_host: &str) {
    let parsed = Url::parse(raw).unwrap();
    if parsed.scheme() == "https" && parsed.host_str() == Some(allowed_host) {
        let _ = reqwest::blocking::get(parsed);
    }
}

fn contained_path(root: &Path, supplied: &Path) {
    let canonical_root = root.canonicalize().unwrap();
    let canonical_path = std::fs::canonicalize(supplied).unwrap();
    if canonical_path.strip_prefix(&canonical_root).is_ok() {
        let _ = std::fs::read(canonical_path);
    }
}

fn tls_configuration(value: bool) {
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_certs(value)
        .danger_accept_invalid_hostnames(false);
}
