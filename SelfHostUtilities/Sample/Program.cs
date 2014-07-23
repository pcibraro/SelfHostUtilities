
using SelfHostUtilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            var cert = X509Util.CreateSelfSignedCertificate(Environment.MachineName);

            //Register a namespace reservation for everyone in localhost in port 9010
            HttpServerApi.ModifyNamespaceReservation(new Uri("https://localhost:9010"), 
                "everyone", 
                HttpServerApiConfigurationAction.AddOrUpdate);
            
            //Register the SSL certificate for any address (0.0.0.0) in the port 9010.
            HttpServerApi.ModifySslCertificateToAddressBinding("0.0.0.0", 9010, cert.GetCertHash(), System.Security.Cryptography.X509Certificates.StoreName.My, HttpServerApiConfigurationAction.AddOrUpdate);
        }
    }
}
