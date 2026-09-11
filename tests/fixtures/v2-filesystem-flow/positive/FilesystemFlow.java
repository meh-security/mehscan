import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

class FilesystemFlow {
    String direct(HttpServletRequest request) throws Exception {
        return Files.readString(Paths.get(request.getParameter("direct")));
    }

    void propagated(HttpServletRequest request, byte[] content) throws Exception {
        String requested = request.getParameter("propagated");
        String alias = requested;
        Files.write(Paths.get(alias), content);
    }

    String canonicalized(HttpServletRequest request) throws Exception {
        Path canonical = Paths.get(request.getParameter("protected")).normalize();
        return Files.readString(canonical);
    }

    boolean contained(String candidate, String root) {
        return Paths.get(candidate).normalize().startsWith(Paths.get(root).normalize());
    }
}
