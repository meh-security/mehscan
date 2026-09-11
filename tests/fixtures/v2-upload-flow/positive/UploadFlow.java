import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

class UploadFlow {
    void direct(HttpServletRequest request, String content) throws Exception {
        Files.writeString(request.getPart("upload").getSubmittedFileName(), content);
    }

    void propagated(HttpServletRequest request, String content) throws Exception {
        String requested = request.getPart("upload").getSubmittedFileName();
        String alias = requested;
        Files.writeString(alias, content);
    }

    void canonicalized(HttpServletRequest request, String content) throws Exception {
        Path destination = Paths.get(request.getPart("upload").getSubmittedFileName()).normalize();
        Files.writeString(destination, content);
    }

    boolean validBasename(String filename) {
        return Paths.get(filename).getFileName().toString().equals(filename);
    }
}
