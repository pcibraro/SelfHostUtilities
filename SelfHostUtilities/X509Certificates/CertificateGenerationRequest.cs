using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SelfHostUtilities.X509Certificates
{
    internal class CertificateGenerationRequest
    {
        private string subject;

        /// <summary>
        /// The subject of the certificate
        /// </summary>
        public string Subject
        {
            get
            {
                if (string.IsNullOrWhiteSpace(subject))
                    return subject;

                if (!subject.StartsWith("CN="))
                    subject = "CN=" + subject;

                return subject;
            }
            set
            {
                subject = value;
            }
        }

        /// <summary>
        /// The size of the key
        /// </summary>
        public int KeySize { get; set; }

        /// <summary>
        /// Custom CSP parameters to specify key generation requirements
        /// </summary>
        public CspParameters Parameters { get; set; }

        /// <summary>
        /// Length of certificate validity
        /// </summary>
        public TimeSpan ExpirationLength { get; set; }

        /// <summary>
        /// The algorithm signature used to sign the certificate
        /// </summary>
        public string SignatureAlgorithm { get; set; }

        /// <summary>
        /// Any X.509 extensions to attach to the certificate before signing
        /// </summary>
        public X509ExtensionCollection Extensions { get; set; }
    }
}
