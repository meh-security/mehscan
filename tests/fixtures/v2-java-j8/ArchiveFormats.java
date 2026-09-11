import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;

class ArchiveFormats {
    void jar(InputStream archive, JarEntry entry, Path root) throws Exception {
        Path destination = root.resolve(entry.getName());
        Files.copy(archive, destination);
    }

    void commonsZip(InputStream archive, ZipArchiveEntry entry, Path root) throws Exception {
        Path destination = root.resolve(entry.getName());
        Files.copy(archive, destination);
    }

    void tar(InputStream archive, TarArchiveEntry entry, Path root) throws Exception {
        Path destination = root.resolve(entry.getName());
        Files.copy(archive, destination);
    }
}
