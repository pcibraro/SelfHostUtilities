using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SelfHostUtilities.X509Certificates
{
    internal static class NativeMethods
    {
        public const uint AT_KEYEXCHANGE = 0x00000001;
        public const uint AT_SIGNATURE = 0x00000002;

        public const string OID_RSA_SHA256RSA = "1.2.840.113549.1.1.11";
        public const string szOID_ENHANCED_KEY_USAGE = "2.5.29.37";

        public const uint CERT_X500_NAME_STR = 3;
        public const uint X509_ASN_ENCODING = 0x00000001;
        public const uint PKCS_7_ASN_ENCODING = 0x00010000;
        public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;	 //no private key access flag

        private const string ADVAPI32 = "advapi32.dll";
        private const string CRYPT32 = "crypt32.dll";
        private const string KERNEL32 = "kernel32.dll";

        public const ulong X509_CERT_CRL_TO_BE_SIGNED = 3; // CRL_INFO
        public const ulong X509_CERT_REQUEST_TO_BE_SIGNED = 4; // CERT_REQUEST_INFO
        public const ulong X509_CERT_TO_BE_SIGNED = 2; // CERT_INFO
        public const ulong X509_KEYGEN_REQUEST_TO_BE_SIGNED = 21; // CERT_KEYGEN_REQUEST_INFO

        [DllImport(CRYPT32, SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptSignAndEncodeCertificate(IntPtr hCryptProvOrNCryptKey,
                                                                uint dwKeySpec,
                                                                uint dwCertEncodingType,
                                                                ulong lpszStructType,
                                                                IntPtr pvStructInfo,
                                                                ref CRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
                                                                IntPtr pvHashAuxInfo,
                                                                byte[] pbEncoded,
                                                                ref uint pcbEncoded);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern IntPtr CertCreateSelfSignCertificate(IntPtr hProv,
                                                                  ref CERT_NAME_BLOB pSubjectIssuerBlob,
                                                                  uint dwFlagsm,
                                                                  ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
                                                                  ref CRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
                                                                  ref SYSTEM_TIME pStartTime,
                                                                  ref SYSTEM_TIME pEndTime,
                                                                  IntPtr other);

        [DllImport(CRYPT32, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CertStrToName(uint dwCertEncodingType,
                                                string pszX500,
                                                uint dwStrType,
                                                IntPtr pvReserved,
                                                [In, Out] byte[] pbEncoded,
                                                ref uint pcbEncoded,
                                                IntPtr other);

        [DllImport(ADVAPI32)]
        public static extern bool CryptEnumProviders(int dwIndex,
                                                     IntPtr pdwReserved,
                                                     int dwFlags,
                                                     ref int pdwProvType,
                                                     StringBuilder pszProvName,
                                                     ref int pcbProvName);

        [DllImport(ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptAcquireContext(ref IntPtr hProv, 
                                                      string pszContainer, 
                                                      string pszProvider, 
                                                      uint dwProvType, 
                                                      uint dwFlags);

        [DllImport(ADVAPI32)]
        public static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [DllImport(CRYPT32, SetLastError = true)]
        public static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, 
                                                                    uint dwPropId, 
                                                                    IntPtr pvData, 
                                                                    ref uint pcbData);

        [DllImport(KERNEL32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr LocalAlloc([In] uint uFlags, [In] IntPtr sizetdwBytes);

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_CONTEXT
        {
            public uint dwCertEncodingType;
            public IntPtr pbCertEncoded;
            public int cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_INFO
        {
            public uint dwVersion;
            public CRYPTOAPI_BLOB SerialNumber;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPTOAPI_BLOB Issuer;
            public FILETIME NotBefore;
            public FILETIME NotAfter;
            public CRYPTOAPI_BLOB Subject;
            public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
            public CRYPTOAPI_BLOB IssuerUniqueId;
            public CRYPTOAPI_BLOB SubjectUniqueId;
            public uint cExtension;
            public IntPtr rgExtension;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CERT_EXTENSION
        {
            public IntPtr pszObjId;
            public bool fCritical;
            public NativeMethods.CRYPTOAPI_BLOB Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_EXTENSIONS
        {
            public uint cExtension;
            public IntPtr rgExtension;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_NAME_BLOB : IDisposable
        {
            public int _cbData;
            public SafeGlobalMemoryHandle _pbData;

            public CERT_NAME_BLOB(int cb, SafeGlobalMemoryHandle handle)
            {
                this._cbData = cb;
                this._pbData = handle;
            }

            public void CopyData(byte[] encodedName)
            {
                this._pbData = new SafeGlobalMemoryHandle(encodedName);
                this._cbData = encodedName.Length;
            }

            public void Dispose()
            {
                if (this._pbData != null)
                {
                    this._pbData.Dispose();
                    this._pbData = null;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            public string pszObjId;
            public NativeMethods.CRYPTOAPI_BLOB parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszProvName;
            public uint dwProvType;
            public uint dwFlags;
            public uint cProvParam;
            public IntPtr rgProvParam;
            public uint dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_PUBLIC_KEY_INFO
        {
            public String SubjPKIAlgpszObjId;
            public int SubjPKIAlgParameterscbData;
            public IntPtr SubjPKIAlgParameterspbData;
            public int PublicKeycbData;
            public IntPtr PublicKeypbData;
            public int PublicKeycUnusedBits;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRYPTOAPI_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_TIME
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliseconds;

            public SYSTEM_TIME(DateTime dt)
            {
                this.wYear = (ushort)dt.Year;
                this.wMonth = (ushort)dt.Month;
                this.wDay = (ushort)dt.Day;
                this.wDayOfWeek = (ushort)dt.DayOfWeek;
                this.wHour = (ushort)dt.Hour;
                this.wMinute = (ushort)dt.Minute;
                this.wSecond = (ushort)dt.Second;
                this.wMilliseconds = (ushort)dt.Millisecond;
            }
        }

        internal class SafeGlobalMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeGlobalMemoryHandle()
                : base(true)
            {
            }

            public SafeGlobalMemoryHandle(byte[] data)
                : base(true)
            {
                base.handle = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, base.handle, data.Length);
            }

            private SafeGlobalMemoryHandle(IntPtr handle)
                : base(true)
            {
                base.SetHandle(handle);
            }

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(base.handle);
                return true;
            }
        }
    }
}
