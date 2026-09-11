import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;

class LoggingPolicy {
    void unsafe(HttpServletRequest request, Logger logger, String token) {
        logger.info("user=" + request.getParameter("name"));
        logger.debug("token: {}", token);
    }

    void safe(Logger logger, String user) {
        logger.info("user: {}", user);
    }
}
