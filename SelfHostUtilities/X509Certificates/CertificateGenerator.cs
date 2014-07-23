using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SelfHostUtilities.X509Certificates
{
    internal static class CertificateGenerator
    {
        public const int MINIMUM_SELF_SIGNED_CERTIFICATE_KEYSIZE = 2048;
        public const string MS_ENH_RSA_AES_PROV = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        public const int PROV_RSA_AES = 24;

        /// <summary>
        /// Create a self signed certificate
        /// </summary>
        /// <param name="request">A request to generate certificate</param>
        /// <returns>Returns a self signed certificate</returns>
        public static X509Certificate2 CreateSelfSignedCertificate(CertificateGenerationRequest request)
        {
            var ptr = CreateSelfSignedCertificatePtr(request);

            return new X509Certificate2(ptr);
        }

        /// <summary>
        /// Create a certificate
        /// </summary>
        /// <param name="request">A request to generate certificate</param>
        /// <returns>Returns a pointer to the signed certificate</returns>
        internal static unsafe IntPtr CreateSelfSignedCertificatePtr(CertificateGenerationRequest request)
        {
            if (request == null)
                throw new ArgumentNullException("request");

            if (string.IsNullOrWhiteSpace(request.Subject))
                throw new ArgumentException("request.Subject is null");

            NativeMethods.CERT_NAME_BLOB pSubjectIssuerBlob = new NativeMethods.CERT_NAME_BLOB(0, null);

            IntPtr extensionsPtr = IntPtr.Zero;

            var subjectName = request.Subject;
            var extensions = request.Extensions;

            var parameters = request.Parameters;

            if (parameters == null)
                parameters = new CspParameters()
                {
                    ProviderName = MS_ENH_RSA_AES_PROV,
                    ProviderType = PROV_RSA_AES,
                    KeyContainerName = Guid.NewGuid().ToString(),
                    KeyNumber = (int)KeyNumber.Exchange,
                    Flags = CspProviderFlags.UseMachineKeyStore
                };

            var keySize = request.KeySize;

            if (keySize <= 0)
                keySize = MINIMUM_SELF_SIGNED_CERTIFICATE_KEYSIZE;

            var expirationLength = request.ExpirationLength;

            if (expirationLength <= TimeSpan.MinValue)
            {
                expirationLength = TimeSpan.FromDays(365);
            }

            var durationInMinutes = expirationLength.TotalMinutes;

            var signatureAlgo = request.SignatureAlgorithm;

            if (string.IsNullOrWhiteSpace(signatureAlgo))
                signatureAlgo = NativeMethods.OID_RSA_SHA256RSA;

            string container = Guid.NewGuid().ToString();

            try
            {
                uint pcbEncoded = 0;

                if (!NativeMethods.CertStrToName(NativeMethods.X509_ASN_ENCODING, subjectName, NativeMethods.CERT_X500_NAME_STR, IntPtr.Zero, null, ref pcbEncoded, IntPtr.Zero) && pcbEncoded <= 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                byte[] pbEncoded = new byte[pcbEncoded];

                if (!NativeMethods.CertStrToName(NativeMethods.X509_ASN_ENCODING, subjectName, NativeMethods.CERT_X500_NAME_STR, IntPtr.Zero, pbEncoded, ref pcbEncoded, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                using (new RSACryptoServiceProvider(keySize, parameters))
                {
                    pSubjectIssuerBlob.CopyData(pbEncoded);

                    NativeMethods.CRYPT_KEY_PROV_INFO pKeyProvInfo = new NativeMethods.CRYPT_KEY_PROV_INFO
                    {
                        pwszProvName = parameters.ProviderName,
                        pwszContainerName = parameters.KeyContainerName,
                        dwProvType = (uint)parameters.ProviderType,
                        dwFlags = 0x20, //(uint)parameters.Flags, 
                        dwKeySpec = (uint)parameters.KeyNumber
                    };

                    NativeMethods.CRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm = new NativeMethods.CRYPT_ALGORITHM_IDENTIFIER
                    {
                        pszObjId = signatureAlgo
                    };

                    pSignatureAlgorithm.parameters.cbData = 0;
                    pSignatureAlgorithm.parameters.pbData = IntPtr.Zero;

                    NativeMethods.SYSTEM_TIME pStartTime = new NativeMethods.SYSTEM_TIME(DateTime.UtcNow);
                    NativeMethods.SYSTEM_TIME pEndTime = new NativeMethods.SYSTEM_TIME(DateTime.UtcNow.AddMinutes((double)durationInMinutes));

                    extensionsPtr = CertUtil.ConvertExtensions(extensions)[0];

                    IntPtr handle = NativeMethods.CertCreateSelfSignCertificate(IntPtr.Zero, ref pSubjectIssuerBlob, 0, ref pKeyProvInfo, ref pSignatureAlgorithm, ref pStartTime, ref pEndTime, extensionsPtr);

                    if (handle == IntPtr.Zero)
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    return handle;
                }
            }
            finally
            {
                if (IntPtr.Zero != extensionsPtr)
                {
                    Marshal.FreeHGlobal(extensionsPtr);
                    extensionsPtr = IntPtr.Zero;
                }

                pSubjectIssuerBlob.Dispose();
            }
        }
    }
}