using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Identity.Client;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace AppRegSNIPOC
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            CallKVWithAppReg();
            Console.ReadKey();
        }

        private static void CallKVWithAppReg()
        {
            string tenantId = "aadtenantid";
            string clientId = "aadappregclientid";
            string subject = "certificatesubjectname";
            Uri keyvaultURI = new Uri("https://keyvaultname.vault.azure.net/");

            X509Certificate2 certificate = GetCertificateBySubjectName(subject);

            var client = new SecretClient(keyvaultURI, SNICredential(tenantId, clientId, certificate));

            var secretValue = client.GetSecret("AppId").Value;
            Console.WriteLine(secretValue.Value);
        }

        private static ClientCertificateCredential SNICredential(string tenantId, string clientId, X509Certificate2 certificate)
        {
            ClientCertificateCredential credential = new ClientCertificateCredential(
                            tenantId,
                            clientId,
                            certificate,
                            new ClientCertificateCredentialOptions
                            {
                                SendCertificateChain = true,
                                AdditionallyAllowedTenants = { "*" }
                            });
            return credential;
        }

        private static X509Certificate2 GetCertificateBySubjectName(string subjectName)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, true);
            if (certs.Count == 0)
                return null;
            return certs[0];
        }
    }
}