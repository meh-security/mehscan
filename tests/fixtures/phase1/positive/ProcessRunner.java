class ProcessRunner {
    void run(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
}

