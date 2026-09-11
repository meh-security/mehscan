class Lookalikes {
    Object test(String input) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        mapper.readValue(input, Object.class);
        Yaml yaml = new Yaml();
        yaml.load(input);
        DocumentBuilder builder = new DocumentBuilder();
        return builder.parse(input);
    }

    static class ObjectMapper {
        void enableDefaultTyping() {}
        Object readValue(String input, Class<?> type) { return input; }
    }
    static class Yaml { Object load(String input) { return input; } }
    static class DocumentBuilder { Object parse(String input) { return input; } }
}
