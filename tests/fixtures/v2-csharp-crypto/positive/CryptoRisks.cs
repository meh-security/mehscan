using System;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

public static class CryptoRisks
{
    public static void ConfigureIdentity(IServiceCollection services)
    {
        services.Configure<PasswordHasherOptions>(options =>
        {
            options.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV2;
            options.IterationCount = 10_000;
        });
    }

    public static byte[] WeakPbkdf2(string password)
    {
        return KeyDerivation.Pbkdf2(
            password,
            Encoding.UTF8.GetBytes("shared-static-salt"),
            KeyDerivationPrf.HMACSHA256,
            20_000,
            32);
    }

    public static string WeakBcrypt(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, 8);
    }

    public static Argon2id WeakArgon(byte[] password)
    {
        return new Argon2id(password)
        {
            Iterations = 1,
            MemorySize = 8_192,
            DegreeOfParallelism = 1
        };
    }

    public static string GenerateResetToken()
    {
        var resetToken = new Random().Next().ToString();
        return resetToken;
    }

    public static void EncryptLegacy(byte[] plaintext, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.IV = new byte[16];
        aes.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    public static void EncryptGcm(byte[] plaintext, byte[] key, byte[] output, byte[] tag)
    {
        using AesGcm aes = new AesGcm(key);
        var nonce = new byte[12];
        aes.Encrypt(nonce, plaintext, output, tag);
    }

    public static JwtSecurityToken IssueJwt()
    {
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("literal-signing-key-32-bytes-long")),
            SecurityAlgorithms.HmacSha256);
        return new JwtSecurityToken(signingCredentials: credentials);
    }
}
