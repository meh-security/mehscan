using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;

class SecurityConfig
{
    void Review(object payload)
    {
        handler.ServerCertificateCustomValidationCallback =
            (request, certificate, chain, errors) => false;
        options.Cookie.SecurePolicy = false;
        options.Cookie.HttpOnly = false;
        HashAlgorithm.Create("MD5");
        new BinaryFormatter().Deserialize(payload);
    }
}
