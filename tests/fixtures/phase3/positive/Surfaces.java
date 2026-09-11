import java.net.http.HttpRequest;
import java.nio.file.Files;

class Surfaces {
    void review(String query, java.net.URI uri, java.nio.file.Path path, String code, String language)
            throws Exception {
        statement.executeQuery(query);
        HttpRequest.newBuilder(uri);
        Files.readString(path);
        Files.writeString(path, "content");
        new ScriptEngineManager().getEngineByName(language).eval(code);
    }
}
