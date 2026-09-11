package fixtures;

import org.springframework.web.multipart.MultipartFile;

interface UploadService {
    Video upload(MultipartFile file);
    Video safeUpload(MultipartFile file);
    Video update(VideoForm form);
    String convert(long id);
}
