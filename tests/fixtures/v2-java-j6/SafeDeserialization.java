import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.NoTypePermission;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

class SafeDeserialization {
    Payload jackson(String input) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        PolymorphicTypeValidator validator = BasicPolymorphicTypeValidator.builder()
            .allowIfSubType("example.api.")
            .build();
        mapper.activateDefaultTyping(validator);
        return mapper.readValue(input, Payload.class);
    }

    Object yaml(String input) {
        Yaml yaml = new Yaml(new SafeConstructor());
        return yaml.loadAs(input, Payload.class);
    }

    Object xstream(String input) {
        XStream xstream = new XStream();
        xstream.addPermission(NoTypePermission.NONE);
        xstream.allowTypes(new Class[] { Payload.class });
        return xstream.fromXML(input);
    }

    Object nativeObject(InputStream input) throws Exception {
        ObjectInputStream objects = new ObjectInputStream(input);
        objects.setObjectInputFilter(ObjectInputFilter.Config.createFilter("example.Payload;!*"));
        return objects.readObject();
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
    @JsonSubTypes(@JsonSubTypes.Type(value = Payload.class, name = "payload"))
    static class Payload {}
}
