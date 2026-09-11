using System.Net.Http;

class TlsClient
{
    void Configure(HttpClientHandler handler)
    {
        handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) => true;
    }
}
