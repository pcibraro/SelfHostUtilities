using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SelfHostUtilities.X509Certificates
{
    internal static class CertificateSigner
    {
        public const int AT_KEYEXCHANGE = (int)NativeMethods.AT_KEYEXCHANGE;
        public const int AT_SIGNATURE = (int)NativeMethods.AT_SIGNATURE;

        /// <summary>
        /// Accepts a CSR-like object to sign by another key
        /// </summary>
        /// <param name="request">The request to sign</param>
        /// <param name="CACert">The signing key</param>
        /// <returns>Returns a signed certificate</returns>
        public static X509Certificate2 SignCertificate(CertificateSigningRequest request, X509Certificate2 CACert)
        {
            IntPtr hCAProv = IntPtr.Zero;

            IntPtr hProvAllocPtr = IntPtr.Zero;
            IntPtr subordinateCertInfoAllocPtr = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();

            try
            {
                // Get CA cert into CERT_CONTEXT
                // Get CA cert into CERT_INFO from context.pCertInfo

                NativeMethods.CERT_CONTEXT CAContext = (NativeMethods.CERT_CONTEXT)Marshal.PtrToStructure(CACert.Handle, typeof(NativeMethods.CERT_CONTEXT));
                NativeMethods.CERT_INFO CACertInfo = (NativeMethods.CERT_INFO)Marshal.PtrToStructure(CAContext.pCertInfo, typeof(NativeMethods.CERT_INFO));

                uint pcbData = 0;

                // get the context property handle of the CA Cert

                if (!NativeMethods.CertGetCertificateContextProperty(CACert.Handle, 2, hProvAllocPtr, ref pcbData))
                    throw new CryptographicException(Marshal.GetLastWin32Error());

                hProvAllocPtr = NativeMethods.LocalAlloc(0, new IntPtr((long)pcbData));

                if (!NativeMethods.CertGetCertificateContextProperty(CACert.Handle, 2, hProvAllocPtr, ref pcbData))
                    throw new CryptographicException(Marshal.GetLastWin32Error());

                // get the key handle of the CA Cert

                NativeMethods.CRYPT_KEY_PROV_INFO pKeyInfo = (NativeMethods.CRYPT_KEY_PROV_INFO)Marshal.PtrToStructure(hProvAllocPtr, typeof(NativeMethods.CRYPT_KEY_PROV_INFO));

                // Acquire a context to the provider for crypto

                if (!NativeMethods.CryptAcquireContext(ref hCAProv, pKeyInfo.pwszContainerName, pKeyInfo.pwszProvName, pKeyInfo.dwProvType, pKeyInfo.dwFlags))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // Get subordinate cert into CERT_CONTEXT
                // Get subordinate cert into CERT_INFO from context.pCertInfo

                NativeMethods.CERT_CONTEXT subordinateCertContext = (NativeMethods.CERT_CONTEXT)Marshal.PtrToStructure(request.Certificate.Handle, typeof(NativeMethods.CERT_CONTEXT));
                NativeMethods.CERT_INFO subordinateCertInfo = (NativeMethods.CERT_INFO)Marshal.PtrToStructure(subordinateCertContext.pCertInfo, typeof(NativeMethods.CERT_INFO));

                NativeMethods.CRYPT_ALGORITHM_IDENTIFIER signatureAlgo = new NativeMethods.CRYPT_ALGORITHM_IDENTIFIER()
                {
                    pszObjId = string.IsNullOrWhiteSpace(request.SignatureAlgorithm) ? NativeMethods.OID_RSA_SHA256RSA : request.SignatureAlgorithm
                };

                // apply new issuer

                subordinateCertInfo.NotBefore = CertUtil.FileTimeFromDateTime(DateTime.UtcNow.AddHours(-1));
                subordinateCertInfo.NotAfter = CertUtil.FileTimeFromDateTime(DateTime.UtcNow.Add(request.ExpirationLength));

                var caExtensions = CertUtil.ConvertExtensions(request.Extensions)[0];

                subordinateCertInfo.cExtension = request.Extensions == null ? 0 : (uint)request.Extensions.Count;
                subordinateCertInfo.rgExtension = caExtensions;

                subordinateCertInfo.SignatureAlgorithm = signatureAlgo;
                subordinateCertInfo.Issuer = CACertInfo.Subject;

                subordinateCertInfoAllocPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeMethods.CERT_INFO)));
                Marshal.StructureToPtr(subordinateCertInfo, subordinateCertInfoAllocPtr, false);

                byte[] pbEncodedCert = null;
                uint pbEncodedCertLength = 0;

                if (!NativeMethods.CryptSignAndEncodeCertificate(hCAProv,
                                                                 (uint)request.KeySpecification,
                                                                 NativeMethods.X509_ASN_ENCODING,
                                                                 NativeMethods.X509_CERT_TO_BE_SIGNED,
                                                                 subordinateCertInfoAllocPtr,
                                                                 ref signatureAlgo,
                                                                 IntPtr.Zero,
                                                                 pbEncodedCert,
                                                                 ref pbEncodedCertLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                pbEncodedCert = new byte[pbEncodedCertLength];

                if (!NativeMethods.CryptSignAndEncodeCertificate(hCAProv,
                                                                 (uint)request.KeySpecification,
                                                                 NativeMethods.X509_ASN_ENCODING,
                                                                 NativeMethods.X509_CERT_TO_BE_SIGNED,
                                                                 subordinateCertInfoAllocPtr,
                                                                 ref signatureAlgo,
                                                                 IntPtr.Zero,
                                                                 pbEncodedCert,
                                                                 ref pbEncodedCertLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var cert3 = new X509Certificate2(pbEncodedCert);

                return cert3;
            }
            finally
            {
                if (hProvAllocPtr != IntPtr.Zero)
                    NativeMethods.CryptReleaseContext(hProvAllocPtr, 0);

                if (hCAProv != IntPtr.Zero)
                    NativeMethods.CryptReleaseContext(hCAProv, 0);

                if (hProvAllocPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(hProvAllocPtr);

                if (subordinateCertInfoAllocPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(subordinateCertInfoAllocPtr);
            }
        }
    }
}
