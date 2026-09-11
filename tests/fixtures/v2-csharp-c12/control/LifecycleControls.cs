using System.Security.Cryptography;
using CryptoRandom = System.Security.Cryptography.RandomNumberGenerator;

public static class LifecycleControls
{
    public static string NewPasswordResetToken()
    {
        return RandomNumberGenerator.GetHexString(64);
    }

    public static string NewRecoveryCode()
    {
        return CryptoRandom.GetInt32(100000, 999999).ToString();
    }

    public static byte[] NewInvitationToken()
    {
        var rng = RandomNumberGenerator.Create();
        var invitationToken = new byte[32];
        rng.GetBytes(invitationToken);
        return invitationToken;
    }

    public static void FillVerificationCode(byte[] verificationCode)
    {
        RandomNumberGenerator.Fill(verificationCode);
    }

    public static void FillApprovalCode(byte[] approvalCode)
    {
        RandomNumberGenerator.Create().GetNonZeroBytes(approvalCode);
    }
}
