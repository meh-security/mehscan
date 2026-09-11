import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

class SafePaths {
    Path lexical(String value) { return Paths.get(value).normalize(); }
    Path real(Path value) throws Exception { return value.toRealPath(); }
    String canonical(File value) throws Exception { return value.getCanonicalPath(); }

    boolean contained(String candidate, String root) {
        return Path.of(candidate).normalize().startsWith(Path.of(root).normalize());
    }

    boolean links(Path candidate) {
        return Files.isSymbolicLink(candidate);
    }

    Object noFollow(Path candidate) throws Exception {
        return Files.newInputStream(candidate, LinkOption.NOFOLLOW_LINKS);
    }

    void overwrite(Path source, Path destination) throws Exception {
        Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
    }
}
