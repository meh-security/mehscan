package fixtures;

class Video {
    byte[] video;
    String videoName;
    String conversionParams;
}

class VideoForm {
    long id;
    String conversionParams;
}

interface VideoRepository {
    Video save(Video video);
    Video findById(long id);
}
