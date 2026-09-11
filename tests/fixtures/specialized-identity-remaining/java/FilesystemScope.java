import org.springframework.web.multipart.MultipartFile;

class FilesystemScope {
    Object upload;
    Object remote;

    void store(Object destination) throws Exception {
        {
            MultipartFile upload = null;
        }
        upload.transferTo(destination);
    }

    void storeRemote(Object destination) throws Exception {
        remote.transferTo(destination);
    }
}

class OtherFilesystemOwner {
    MultipartFile remote;
}
