import java.nio.file.Files;
import static java.nio.file.Files.readString;

class Aliases {
    interface FileWriter {
        void writeString(java.nio.file.Path path, String content);
    }

    void review(java.nio.file.Path path) throws Exception {
        readString(path);
        Files.writeString(path, "content");
    }

    void shadowed(FileWriter Files, java.nio.file.Path path) {
        Files.writeString(path, "content");
    }
}
