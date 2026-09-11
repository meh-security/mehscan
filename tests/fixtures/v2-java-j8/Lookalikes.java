class Lookalikes {
    void run(String path) {
        Files.readString(path);
        Files.writeString(path, "content");
        Path normalized = Path.of(path).normalize();
        ZipEntry entry = new ZipEntry();
        entry.getName();
    }

    static class Files {
        static Object readString(String path) { return path; }
        static void writeString(String path, String content) {}
    }
    static class Path {
        static Path of(String value) { return new Path(); }
        Path normalize() { return this; }
    }
    static class ZipEntry { String getName() { return "safe"; } }
}
