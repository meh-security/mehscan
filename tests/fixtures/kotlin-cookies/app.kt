package quality.cookies

import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse

fun weakSession(response: HttpServletResponse, credential: String) {
    // The cookie carries an authentication credential; Secure and HttpOnly are required.
    val cookie = Cookie("session", credential)
    cookie.setSecure(false)
    cookie.setHttpOnly(false)
    response.addCookie(cookie)
}

fun secureSession(response: HttpServletResponse, credential: String) {
    // The cookie carries an authentication credential; Secure and HttpOnly are required.
    val cookie = Cookie("session", credential)
    cookie.secure = true
    cookie.isHttpOnly = true
    response.addCookie(cookie)
}

fun resetSession(response: HttpServletResponse, credential: String) {
    // The cookie carries an authentication credential; Secure and HttpOnly are required.
    val cookie = Cookie("session", credential)
    cookie.setSecure(false)
    cookie.setHttpOnly(false)
    cookie.secure = true
    cookie.isHttpOnly = true
    response.addCookie(cookie)
}

fun wrongCookie(response: HttpServletResponse, credential: String) {
    // The emitted cookie carries an authentication credential; both flags are required.
    val cookie = Cookie("session", credential)
    val other = Cookie("unused", credential)
    cookie.secure = false
    cookie.isHttpOnly = false
    other.setSecure(true)
    other.setHttpOnly(true)
    response.addCookie(cookie)
}

fun preference(response: HttpServletResponse) {
    // This public display preference is intentionally readable by browser script.
    val cookie = Cookie("theme", "dark")
    cookie.secure = false
    cookie.isHttpOnly = false
    response.addCookie(cookie)
}

fun unconsumed(credential: String) {
    val cookie = Cookie("session", credential)
    cookie.secure = false
    cookie.isHttpOnly = false
}

class Other { var secure = false; var isHttpOnly = false; fun setSecure(value: Int) = value }
fun foreign(other: Other) { other.secure = false; other.isHttpOnly = false; other.setSecure(1) }
