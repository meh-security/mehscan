import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class UnsafeArchive {
    void extract(ZipInputStream archive, ZipEntry entry, Path root) throws Exception {
        Path destination = root.resolve(entry.getName());
        Files.copy(archive, destination, StandardCopyOption.REPLACE_EXISTING);
    }
}
