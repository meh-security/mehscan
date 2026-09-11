import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;
import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputStream;
import org.springframework.web.bind.annotation.RequestBody;
import org.yaml.snakeyaml.Yaml;

class UnsafeDeserialization {
    Object jackson(@RequestBody String input) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);
        return mapper.readValue(input, Object.class);
    }

    Object yaml(@RequestBody String input) {
        Yaml yaml = new Yaml();
        return yaml.load(input);
    }

    Object xstream(@RequestBody String input) {
        XStream xstream = new XStream();
        xstream.addPermission(AnyTypePermission.ANY);
        return xstream.fromXML(input);
    }

    Object nativeObject(@RequestBody InputStream input) throws Exception {
        ObjectInputStream objects = new ObjectInputStream(input);
        return objects.readObject();
    }

    Object xmlDecoder(@RequestBody InputStream input) {
        XMLDecoder decoder = new XMLDecoder(input);
        return decoder.readObject();
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    static class PolymorphicPayload {}
}
import com.fasterxml.jackson.annotation.JsonTypeInfo;
