import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

class Example {
    void save(HttpServletRequest request, String content) throws Exception {
        Path destination = Paths.get(request.getPart("upload").getSubmittedFileName()).normalize();
        Files.writeString(destination, content);
    }
}
