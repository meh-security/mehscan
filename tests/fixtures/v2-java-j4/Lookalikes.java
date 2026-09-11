package fixtures;

class MultipartFile { byte[] getBytes() { return null; } }
class StringUtils { static String cleanPath(String value) { return value; } }
class Runtime { static Runtime getRuntime() { return new Runtime(); } void exec(String command) {} }

class FakeShell {
    void run(String command) {
        Runtime runtime = Runtime.getRuntime();
        String[] commands = {"bash", "-c", command};
        runtime.exec(command);
    }
}

class Lookalikes {
    String inspect(String name) {
        return StringUtils.cleanPath(name);
    }
}
