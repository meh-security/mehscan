package fixtures;

import fixtures.support.OTPGenerator;

class OtpFlows {
    String generate() {
        return OTPGenerator.generateRandom(4);
    }

    void validateWeak(Otp otp) {
        otp.setCount(otp.getCount() + 1);
        otp.setStatus(INACTIVE);
    }

    void validateLimited(Otp otp) {
        otp.setCount(otp.getCount() + 1);
        if (otp.getCount() >= 9) {
            invalidateOtp(otp);
        }
        otp.setStatus(INACTIVE);
    }

    boolean validateSubject(Otp otp, String value) {
        return otp.getStatus().equals(ACTIVE) && otp.getOtp().equals(value);
    }
}
