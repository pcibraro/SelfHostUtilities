
using SelfHostUtilities.X509Certificates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SelfHostUtilities
{
    public static class X509Util
    {
        public static X509Certificate2 CreateSelfSignedCertificate(string subject)
        {
            var oids = new OidCollection();
            oids.Add(new Oid("1.3.6.1.5.5.7.3.2")); // client auth
            
            var extensions = new X509ExtensionCollection();
            extensions.Add(new X509EnhancedKeyUsageExtension(oids, true));

            var cgr = new CertificateGenerationRequest()
            {
                Subject = subject,
                Extensions = extensions,
                ExpirationLength = TimeSpan.FromDays(365 * 5),
                KeySize = 2048
            };

            var cert = CertificateGenerator.CreateSelfSignedCertificate(cgr);
            
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
            }
            finally
            {
                store.Close();
            }

            return cert;
        }

        public static void DeleteSelfSignedCertificate(string thumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certificates.Count > 0)
                {
                    var certificate = certificates[0];

                    store.Remove(certificate);
                }
            }
            finally
            {
                store.Close();
            }
        }

        public static X509Certificate2 GetSelfSignedCertificate(string thumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadWrite);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certificates.Count > 0)
                {
                    var certificate = certificates[0];

                    return certificate;
                }
                else
                {
                    return null;
                }
            }
            finally
            {
                store.Close();
            }
        }
    }
}
