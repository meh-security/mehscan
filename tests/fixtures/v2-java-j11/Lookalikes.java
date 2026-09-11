class HttpSecurity { HttpSecurity csrf() { return this; } void disable() {} }
class Cookie { void setSecure(boolean value) {} }
class Logger { void info(String value) {} }
class Lookalikes {
    void run(HttpSecurity http, Cookie cookie, Logger logger, String value) {
        http.csrf().disable();
        cookie.setSecure(false);
        logger.info("value=" + value);
    }
}
