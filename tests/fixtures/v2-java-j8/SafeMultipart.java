import java.nio.file.Path;
import org.springframework.web.multipart.MultipartFile;

class SafeMultipart {
    void store(MultipartFile file, Path root) throws Exception {
        Path canonicalRoot = root.toRealPath();
        Path destination = canonicalRoot.resolve(file.getOriginalFilename()).normalize();
        if (!destination.startsWith(canonicalRoot)) {
            throw new IllegalArgumentException("outside upload root");
        }
        file.transferTo(destination);
    }
}
