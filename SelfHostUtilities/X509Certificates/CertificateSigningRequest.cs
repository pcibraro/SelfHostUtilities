using System;
using System.Security.Cryptography.X509Certificates;

namespace SelfHostUtilities.X509Certificates
{
    internal class CertificateSigningRequest
    {
        /// <summary>
        /// The certificate to sign
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// The period of validity for the certificate
        /// </summary>
        public TimeSpan ExpirationLength { get; set; }

        /// <summary>
        /// The preferred algorithm to sign the certificate
        /// </summary>
        public string SignatureAlgorithm { get; set; }

        /// <summary>
        /// The specification for key usage
        /// </summary>
        public int KeySpecification { get; set; }

        /// <summary>
        /// Any X.509 extensions to attach before signing the certificate
        /// </summary>
        public X509ExtensionCollection Extensions { get; set; }
    }
}
