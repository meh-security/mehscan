import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.core.io.FileSystemResource;
import org.springframework.web.multipart.MultipartFile;

class UnsafeFiles {
    Object nioRead(Path path) throws Exception { return Files.readString(path); }
    void nioWrite(Path path, byte[] content) throws Exception { Files.write(path, content); }
    Object input(String path) throws Exception { return new FileInputStream(path); }
    Object reader(String path) throws Exception { return new FileReader(path); }
    Object random(String path) throws Exception { return new RandomAccessFile(path, "rw"); }
    Object output(String path) throws Exception { return new FileOutputStream(path); }
    Object writer(String path) throws Exception { return new FileWriter(path); }
    Object resource(String path) { return new FileSystemResource(path); }

    void upload(MultipartFile file, Path destination) throws Exception {
        file.transferTo(destination);
    }
}
