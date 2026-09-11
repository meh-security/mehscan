package fixtures;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

class UploadController {
    UploadService uploadService;

    @PostMapping("/upload")
    Object upload(@RequestPart("file") MultipartFile file) {
        return uploadService.upload(file);
    }

    @PostMapping("/safe-upload")
    Object safeUpload(@RequestPart("file") MultipartFile file) {
        return uploadService.safeUpload(file);
    }

    @PostMapping("/properties")
    Object update(@RequestBody VideoForm form) {
        return uploadService.update(form);
    }
}
