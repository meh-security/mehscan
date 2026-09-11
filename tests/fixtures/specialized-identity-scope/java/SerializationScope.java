import com.fasterxml.jackson.databind.ObjectMapper;

class SerializationScope {
    private final MapperLookalike mapper = new MapperLookalike();

    void unrelated(ObjectMapper mapper) { }

    Object review(String payload) throws Exception {
        return mapper.readValue(payload, Object.class);
    }

    static class MapperLookalike {
        Object readValue(String payload, Class<?> type) { return payload; }
    }
}

class OtherSerializationScope {
    ObjectMapper mapper;
}
