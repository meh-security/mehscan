import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class SafeArchive {
    void extract(ZipInputStream archive, ZipEntry entry, Path root) throws Exception {
        Path destination = root.resolve(entry.getName()).normalize();
        Path canonicalRoot = root.toRealPath();
        if (!destination.startsWith(canonicalRoot)) {
            throw new IllegalArgumentException("entry escapes extraction root");
        }
        Files.copy(archive, destination);
    }
}
