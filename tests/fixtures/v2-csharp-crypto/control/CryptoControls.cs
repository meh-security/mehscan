using System;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

public static class CryptoControls
{
    public static void ConfigureIdentity(IServiceCollection services)
    {
        services.Configure<PasswordHasherOptions>(options =>
        {
            options.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3;
            options.IterationCount = 100_000;
        });
    }

    public static byte[] Pbkdf2(string password)
    {
        return KeyDerivation.Pbkdf2(
            password,
            RandomNumberGenerator.GetBytes(16),
            KeyDerivationPrf.HMACSHA256,
            600_000,
            32);
    }

    public static string Bcrypt(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, 12);
    }

    public static Argon2id Argon(byte[] password)
    {
        return new Argon2id(password)
        {
            Iterations = 2,
            MemorySize = 19_456,
            DegreeOfParallelism = 1
        };
    }

    public static string GenerateResetToken()
    {
        var resetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        return resetToken;
    }

    public static void EncryptGcm(byte[] plaintext, byte[] key, byte[] output, byte[] tag)
    {
        using AesGcm aes = new AesGcm(key);
        var nonce = RandomNumberGenerator.GetBytes(12);
        aes.Encrypt(nonce, plaintext, output, tag);
    }

    public static void ConfigureFreshIv(byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = RandomNumberGenerator.GetBytes(16);
    }

    public static JwtSecurityToken IssueJwt(byte[] signingKey)
    {
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(signingKey),
            SecurityAlgorithms.HmacSha256);
        return new JwtSecurityToken(
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: credentials);
    }
}
