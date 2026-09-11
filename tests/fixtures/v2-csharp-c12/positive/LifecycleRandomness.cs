using System;
using WeakRandom = System.Random;

public static class LifecycleRandomness
{
    public static string NewPasswordResetToken()
    {
        var resetToken = new Random().NextInt64().ToString();
        return resetToken;
    }

    public static void SetRecoveryCode(Account account)
    {
        var random = new WeakRandom();
        account.RecoveryCode = random.Next(100000, 999999).ToString();
    }

    public static void PersistApprovalCode(Account account)
    {
        var candidate = Random.Shared.Next().ToString();
        account.ApprovalCode = candidate;
    }

    public static void SaveInvitationToken(Account account)
    {
        StoreInvitationToken(account, Guid.NewGuid().ToString());
    }

    public static byte[] GenerateVerificationCode()
    {
        var verificationCode = new byte[8];
        new Random().NextBytes(verificationCode);
        return verificationCode;
    }

    private static void StoreInvitationToken(Account account, string value) { }
}

public sealed class Account
{
    public string RecoveryCode { get; set; } = "";
    public string ApprovalCode { get; set; } = "";
}
