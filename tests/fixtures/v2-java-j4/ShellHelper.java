package fixtures;

class ShellHelper {
    String run(String command) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        String[] commands = {"bash", "-c", command};
        return runtime.exec(commands).toString();
    }
}
