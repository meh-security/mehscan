class Literals {
    void review() throws Exception {
        final String prefix = "safe/";
        final String command = prefix + "tool";
        Runtime.getRuntime().exec(command);
    }
}
