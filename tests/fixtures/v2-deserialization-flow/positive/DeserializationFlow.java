import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.io.ObjectInputStream;

class DeserializationFlow {
    Object direct(HttpServletRequest request) throws Exception {
        return new ObjectInputStream(request.getInputStream()).readObject();
    }

    Object propagated(HttpServletRequest request) throws Exception {
        InputStream serialized = request.getInputStream();
        InputStream alias = serialized;
        return new ObjectInputStream(alias).readObject();
    }

    UploadDto restricted(HttpServletRequest request, ObjectMapper mapper) throws Exception {
        return mapper.readValue(request.getParameter("restricted"), UploadDto.class);
    }
}
