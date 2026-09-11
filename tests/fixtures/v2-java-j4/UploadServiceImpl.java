package fixtures;

import java.io.ByteArrayInputStream;
import javax.imageio.ImageIO;
import org.springframework.web.multipart.MultipartFile;

class UploadServiceImpl implements UploadService {
    VideoRepository videoRepository;
    ShellHelper shellHelper;

    public Video upload(MultipartFile file) {
        Video video = new Video();
        video.setVideo(file.getBytes());
        video.setVideoName(file.getOriginalFilename());
        return videoRepository.save(video);
    }

    public Video safeUpload(MultipartFile file) {
        if (!"image/png".equals(file.getContentType()) || file.getSize() > 1024) {
            throw new IllegalArgumentException();
        }
        ImageIO.read(new ByteArrayInputStream(file.getBytes()));
        Video video = new Video();
        video.setVideo(file.getBytes());
        return videoRepository.save(video);
    }

    public Video update(VideoForm form) {
        Video video = videoRepository.findById(form.getId());
        video.setConversionParams(form.getConversionParams());
        return videoRepository.save(video);
    }

    public String convert(long id) {
        Video video = videoRepository.findById(id);
        String command = String.format(
            "convert -i %s %s", video.getVideoName(), video.getConversionParams());
        return shellHelper.run(command);
    }
}
