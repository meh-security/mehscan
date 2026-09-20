#[test]
fn detects_explicit_authentication_authorization_and_cors_weakening() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-explicit-security-policy-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let files = [
        (
            "Program.cs",
            r#"using Microsoft.AspNetCore.Authentication.JwtBearer;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication().AddJwtBearer(options => options.RequireHttpsMetadata = false);"#,
        ),
        (
            "app.js",
            r#"const jwt = require('jsonwebtoken');
jwt.verify(token, key, { ignoreExpiration: true, algorithms: ['none'] });"#,
        ),
        (
            "app.py",
            r#"import jwt
from flask_cors import CORS
jwt.decode(token, key, algorithms=['RS256'], options={'verify_exp': False, 'verify_aud': False})
CORS(app, origins='*', supports_credentials=True)"#,
        ),
        (
            "settings.py",
            r#"CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True"#,
        ),
        (
            "Security.java",
            r#"import org.springframework.security.config.annotation.web.builders.HttpSecurity;
class Security { void configure(HttpSecurity http) throws Exception {
  http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
} }"#,
        ),
        (
            "main.go",
            r#"package main
import ("github.com/golang-jwt/jwt/v5"; "github.com/gin-contrib/cors")
func main() { _ = jwt.NewParser(jwt.WithoutClaimsValidation()); _ = cors.Config{AllowAllOrigins: true, AllowCredentials: true} }"#,
        ),
        (
            "main.rs",
            r#"use jsonwebtoken::Validation;
fn main() { let mut validation = Validation::default(); validation.validate_exp = false; validation.validate_aud = false; }"#,
        ),
    ];
    for (path, source) in files {
        std::fs::write(root.join(path), source).unwrap();
    }

    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for rule in [
        "csharp-jwt-https-metadata-disabled",
        "javascript-jwt-expiration-validation-disabled",
        "javascript-jwt-algorithm-validation-weakened",
        "python-jwt-expiration-validation-disabled",
        "python-jwt-identity-claim-validation-disabled",
        "python-flask-credentialed-wildcard-cors",
        "java-spring-security-broad-permit-all",
        "go-jwt-claims-validation-disabled",
        "go-gin-credentialed-all-origins-cors",
        "rust-jwt-expiration-validation-disabled",
        "rust-jwt-audience-validation-disabled",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }
    let django_cors = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "python-django-cors-all-origins-review")
        .expect("missing Django all-origins policy");
    assert!(
        django_cors
            .tags
            .iter()
            .any(|tag| tag == "explicit-permissive-policy")
    );
    std::fs::remove_dir_all(root).unwrap();
}
