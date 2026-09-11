package fixtures;

import org.springframework.util.StringUtils;

class FilenameValidation {
    String weak(String supplied) {
        String cleaned = StringUtils.cleanPath(supplied);
        if (cleaned.contains("..")) {
            audit(cleaned);
        }
        return cleaned;
    }

    String reject(String supplied) {
        String cleaned = StringUtils.cleanPath(supplied);
        if (cleaned.contains("..")) {
            throw new IllegalArgumentException();
        }
        return cleaned;
    }
}
