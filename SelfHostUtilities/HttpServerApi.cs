using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SelfHostUtilities
{
    public enum HttpServerApiConfigurationAction
    {
        /// <summary>Add or update configuration data.</summary>
        AddOrUpdate,

        /// <summary>Delete configuration data.</summary>
        Delete
    }

    /// <summary>
    /// <para>
    /// Exposes HTTP Server API functionality.  See here for more info: <a href="http://msdn.microsoft.com/en-us/library/aa364510(v=VS.85).aspx">http://msdn.microsoft.com/en-us/library/aa364510(v=VS.85).aspx</a>
    /// </para>
    /// </summary>
    /// <remarks>
    /// <para>
    /// The HTTP Server API enables applications to communicate over HTTP without using Microsoft Internet Information Server (IIS).
    /// Applications can register to receive HTTP requests for particular URLs, receive HTTP requests, and send HTTP responses. The HTTP Server API
    /// includes SSL support so that applications can exchange data over secure HTTP connections without IIS. It is also designed to work with I/O
    /// completion ports.
    /// </para>
    /// <para>
    /// The HTTP Server API is supported on Windows Server 2003 operating systems and on Windows XP with Service Pack 2 (SP2). Be aware that
    /// Microsoft IIS 5 running on Windows XP with SP2 is not able to share port 80 with other HTTP applications running simultaneously.
    /// </para>
    /// <para>
    /// The HTTP Server API provides developers with a low-level interface to the server side of the HTTP functionality as defined in RFC 2616.
    /// The API enables an application to receive HTTP requests directed to URLs and send HTTP responses. For sending dynamic responses, the ISAPI
    /// or ASP.NET interfaces are recommended.
    /// </para>
    /// <para>
    /// The HTTP Server API enables multiple applications to coexist on a system, sharing the same TCP port (for example, port 80 for HTTP or
    /// port 443 for HTTPS) and serving different parts of the URL namespace.
    /// </para>
    /// </remarks>
    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
    public static class HttpServerApi
    {
        /// <summary>
        /// Adds/updates or deletes an http(s) URL namespace reservation for a specified Windows user or group.
        /// </summary>
        /// <param name="url">The http(s) URL to modify the reservation for.</param>
        /// <param name="windowsAccountName">The Windows account name (user or group) to modify the reservation for.</param>
        /// <param name="configurationAction">The configuration action to perform (e.g. add/update or delete).</param>
        /// <remarks>
        /// This method must be called under a user context with local administrative privledges.  See
        /// <a href="http://msdn.microsoft.com/en-us/magazine/cc163531.aspx">http://msdn.microsoft.com/en-us/magazine/cc163531.aspx</a> about why this is necessary.
        /// </remarks>
        public static void ModifyNamespaceReservation(Uri url, string windowsAccountName, HttpServerApiConfigurationAction configurationAction)
        {
            if ((false == url.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)) &&
              (false == url.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("Invalid scheme.  Only http and https are supported.", "url");
            }

            uint retVal = NativeMethods.HttpInitialize(NativeMethods.HTTPAPI_VERSION_1, (uint)NativeMethods.HTTP_INITIALIZE_FLAG.HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            if ((uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR == retVal)
            {
                string urlPrefix = BuildStrongWildcardUrlPrefixFromUrl(url);
                var keyDesc = new NativeMethods.HTTP_SERVICE_CONFIG_URLACL_KEY(urlPrefix);

                string securityDescriptor = BuildGenericExecuteSecurityDescriptorFromWindowsAccount(windowsAccountName);
                var paramDesc = new NativeMethods.HTTP_SERVICE_CONFIG_URLACL_PARAM(securityDescriptor);

                var inputConfigInfoSet = new NativeMethods.HTTP_SERVICE_CONFIG_URLACL_SET
                {
                    KeyDesc = keyDesc,
                    ParamDesc = paramDesc
                };

                IntPtr unmanagedConfigInformation = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(NativeMethods.HTTP_SERVICE_CONFIG_URLACL_SET)));
                Marshal.StructureToPtr(inputConfigInfoSet, unmanagedConfigInformation, false);

                if (configurationAction == HttpServerApiConfigurationAction.Delete)
                {
                    retVal = NativeMethods.HttpDeleteServiceConfiguration(
                      IntPtr.Zero,
                      NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo,
                      unmanagedConfigInformation,
                      Marshal.SizeOf(inputConfigInfoSet),
                      IntPtr.Zero);

                    if ((uint)NativeMethods.HTTP_API_ErrorCode.ERROR_FILE_NOT_FOUND == retVal)
                    {
                        // OK -- nothing to delete...
                        retVal = (uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR;
                    }
                }
                else
                {
                    retVal = NativeMethods.HttpSetServiceConfiguration(
                      IntPtr.Zero,
                      NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo,
                      unmanagedConfigInformation,
                      Marshal.SizeOf(inputConfigInfoSet),
                      IntPtr.Zero);

                    if ((uint)NativeMethods.HTTP_API_ErrorCode.ERROR_ALREADY_EXISTS == retVal)
                    {
                        retVal = NativeMethods.HttpDeleteServiceConfiguration(
                          IntPtr.Zero,
                          NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo,
                          unmanagedConfigInformation,
                          Marshal.SizeOf(inputConfigInfoSet),
                          IntPtr.Zero);

                        if ((uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR == retVal)
                        {
                            retVal = NativeMethods.HttpSetServiceConfiguration(
                              IntPtr.Zero,
                              NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo,
                              unmanagedConfigInformation,
                              Marshal.SizeOf(inputConfigInfoSet),
                              IntPtr.Zero);
                        }
                    }
                }

                Marshal.FreeCoTaskMem(unmanagedConfigInformation);
                NativeMethods.HttpTerminate((uint)NativeMethods.HTTP_INITIALIZE_FLAG.HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            }

            if ((uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR != retVal)
            {
                throw Marshal.GetExceptionForHR(HResultFromWin32(retVal));
            }
        }

        /// <summary>Add/updates or deletes an SSL certificate binding for a specified IP address/port.</summary>
        /// <remarks>
        /// The provided SSL certificate data in <paramref name="sslHash"/> is added/updated/deleted in the certificate
        /// store specified by <paramref name="targetSslCertStoreName"/>.
        /// </remarks>
        /// <param name="address">The IP address to bind the SSL certificate to.</param>
        /// <param name="port">The port to bind the SSL certificate to.</param>
        /// <param name="sslHash">The hash of the SSL certificate to bind.</param>
        /// <param name="targetSslCertStoreName">The target certificate store for the SSL certificate.</param>
        /// <param name="configurationAction">The configuration action to perform (e.g. add/update or delete).</param>
        public static void ModifySslCertificateToAddressBinding(string address, int port, byte[] sslHash, StoreName targetSslCertStoreName, HttpServerApiConfigurationAction configurationAction)
        {
            uint retVal = NativeMethods.HttpInitialize(NativeMethods.HTTPAPI_VERSION_1, (uint)NativeMethods.HTTP_INITIALIZE_FLAG.HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            if ((uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR == retVal)
            {
                var configSslSet = new NativeMethods.HTTP_SERVICE_CONFIG_SSL_SET();
                var httpServiceConfigSslKey = new NativeMethods.HTTP_SERVICE_CONFIG_SSL_KEY();
                var configSslParam = new NativeMethods.HTTP_SERVICE_CONFIG_SSL_PARAM();

                IPAddress ip = IPAddress.Parse(address);
                var addressEndPoint = new IPEndPoint(ip, port);

                // serialize the endpoint to a SocketAddress and create an array to hold the values.  Pin the array.
                SocketAddress socketAddress = addressEndPoint.Serialize();
                var socketBytes = new byte[socketAddress.Size];
                GCHandle handleSocketAddress = GCHandle.Alloc(socketBytes, GCHandleType.Pinned);

                // Should copy the first 16 bytes (the SocketAddress has a 32 byte buffer, the size will only be 16,
                // which is what the SOCKADDR accepts
                for (int i = 0; i < socketAddress.Size; ++i)
                {
                    socketBytes[i] = socketAddress[i];
                }

                httpServiceConfigSslKey.pIpPort = handleSocketAddress.AddrOfPinnedObject();

                GCHandle handleHash = GCHandle.Alloc(sslHash, GCHandleType.Pinned);
                configSslParam.AppId = Guid.NewGuid();
                configSslParam.DefaultCertCheckMode = 0;
                configSslParam.DefaultFlags = (uint)NativeMethods.HTTP_SERVICE_CONFIG_SSL_FLAG.HTTP_SERVICE_CONFIG_SSL_FLAG_NEGOTIATE_CLIENT_CERT;
                configSslParam.DefaultRevocationFreshnessTime = 0;
                configSslParam.DefaultRevocationUrlRetrievalTimeout = 0;
                configSslParam.pSslCertStoreName = targetSslCertStoreName.ToString();
                configSslParam.pSslHash = handleHash.AddrOfPinnedObject();
                configSslParam.SslHashLength = sslHash.Length;
                configSslSet.ParamDesc = configSslParam;
                configSslSet.KeyDesc = httpServiceConfigSslKey;

                IntPtr unmanagedConfigInformation = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(NativeMethods.HTTP_SERVICE_CONFIG_SSL_SET)));
                Marshal.StructureToPtr(configSslSet, unmanagedConfigInformation, false);

                if (configurationAction == HttpServerApiConfigurationAction.Delete)
                {
                    retVal = NativeMethods.HttpDeleteServiceConfiguration(
                        IntPtr.Zero,
                        NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                        unmanagedConfigInformation,
                        Marshal.SizeOf(configSslSet),
                        IntPtr.Zero);

                    if ((uint)NativeMethods.HTTP_API_ErrorCode.ERROR_FILE_NOT_FOUND == retVal)
                    {
                        // OK -- nothing to delete...
                        retVal = (uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR;
                    }
                }
                else
                {
                    retVal = NativeMethods.HttpSetServiceConfiguration(
                      IntPtr.Zero,
                      NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                      unmanagedConfigInformation,
                      Marshal.SizeOf(configSslSet),
                      IntPtr.Zero);

                    if ((uint)NativeMethods.HTTP_API_ErrorCode.ERROR_ALREADY_EXISTS == retVal)
                    {
                        retVal = NativeMethods.HttpDeleteServiceConfiguration(
                          IntPtr.Zero,
                          NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                          unmanagedConfigInformation,
                          Marshal.SizeOf(configSslSet),
                          IntPtr.Zero);

                        if ((uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR == retVal)
                        {
                            retVal = NativeMethods.HttpSetServiceConfiguration(
                              IntPtr.Zero,
                              NativeMethods.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo,
                              unmanagedConfigInformation,
                              Marshal.SizeOf(configSslSet),
                              IntPtr.Zero);
                        }
                    }
                }

                Marshal.FreeCoTaskMem(unmanagedConfigInformation);
                NativeMethods.HttpTerminate((uint)NativeMethods.HTTP_INITIALIZE_FLAG.HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            }

            if ((uint)NativeMethods.HTTP_API_ErrorCode.NO_ERROR != retVal)
            {
                throw Marshal.GetExceptionForHR(HResultFromWin32(retVal));
            }
        }

        private static string BuildGenericExecuteSecurityDescriptorFromWindowsAccount(string windowsAccountName)
        {
            // get sid for windowsAccountName
            string sid = new NTAccount(windowsAccountName).Translate(typeof(SecurityIdentifier)).ToString();

            // DACL that allows generic execute for the user/group specified by windowsAccountName.
            //
            // D:    - Indicates the beginning of a DACL.
            // (...) - One or more Access Control Entry (ACE) strings, each one enclosed in parentheses. Each ACE string has the following elements,
            //           in the following order, separated by semi-colons:
            //   A;  - This is the ace_type element, and is always set to A, indicating that the ACE type is ACCESS_ALLOWED.
            //   ;   - This is the ace_flags element, and is always empty
            //   GA; - This is the rights element, and can be set by default to GA (GENERIC_ALL). It may also be set to:
            //           GX (GENERIC_EXECUTE), interpreted by the HTTP Server API as HTTP_ALLOW_REGISTER_URL. This allows the designated user to register
            //             to receive requests from this URL, but does not allow the user to delegate sub-tree reservations to others.
            //           GW (GENERIC_WRITE), interpreted by the HTTP Server API as HTTP_ALLOW_DELEGATE_URL. This allows the designated user to reserve
            //             (delegate) a subtree of this URL for another user, but does not allow the user to register to receive requests from the URL.
            //   ;   - This is the object_guid element, left empty.
            //   ;   - This is the inherit_object_guid element, left empty.
            //   sid - This is the account_sid element for the user referred to by this ACE. It is a SID string which can be filled in by calling
            //           LookupAccountName to obtain the user SID, and then converting the SID into string form using the ConvertSidToStringSid function.
            return string.Format(CultureInfo.InvariantCulture, "D:(A;;GX;;;{0})", sid);
        }

        /// <summary>Builds a strong wildcard URL prefix for a given URL.</summary>
        /// <remarks>
        /// <para>
        /// The form of the URL is as follows. The scheme must be http or https, in lowercase. The host is case-insensitive and may use either
        /// the + or * wildcards. The port is an integer value and is required, even if you're talking about the default port for the scheme.
        /// Following this is an optional case-insensitive relative URI (in the previous example, this is /MyServices). And finally, regardless
        /// of whether you supply a relative URI, you need to terminate the string with a trailing slash.
        /// </para>
        /// <para>
        /// The way you specify the host in the URL determines the priority in which your listener will be considered when a request comes in that
        /// matches more than one listener's prefix. For example, one app might register foo.com:8080/ while another app might register
        /// foo.com:8080/MyServices/. Generally the more explicit registration wins. However, there are also wildcards that can be used to control
        /// how this prioritization works. An application might register <a href="http://*:8080/">http://*:8080/</a>. Since this listener uses the * wildcard, it picks up the dregs
        /// of whatever the other listeners don't want. In other words, * is a low priority or weak wildcard. On the other hand, if the application
        /// registered <a href="http://+:8080/">http://+:8080/</a>, it's going to be given top priority and any HTTP request on port 8080 will go to this application without
        /// checking for other, more specific registrations. For more about how these URL prefixes are formed please see
        /// <a href="http://msdn.microsoft.com/en-us/library/Aa364698">http://msdn.microsoft.com/en-us/library/Aa364698</a>.
        /// </para>
        /// </remarks>
        /// <param name="url">The URL to build the strong wildcard URL prefix for.</param>
        /// <returns>The strong wildcard URL prefix for the specified URL.</returns>
        private static string BuildStrongWildcardUrlPrefixFromUrl(Uri url)
        {
            var sb = new StringBuilder();

            sb.Append(url.Scheme);
            sb.Append("://+:"); // specify a strong wildcard for the host
            sb.Append(url.Port); // port must always be specified
            if (url.PathAndQuery.Length > 0)
            {
                sb.AppendFormat("{0}", url.PathAndQuery);
            }

            // ensure we have a trailing forward slash
            if (sb[sb.Length - 1] != '/')
            {
                sb.Append("/");
            }

            return sb.ToString();
        }

        private static int HResultFromWin32(uint errorCode)
        {
            if (errorCode <= 0)
            {
                return (int)errorCode;
            }

            return (int)((0x0000FFFFU & errorCode) | (7U << 16) | 0x80000000U);
        }

        #region Nested type: NativeMethods
        internal static class NativeMethods
        {
            #region Constants
            internal static readonly HTTPAPI_VERSION HTTPAPI_VERSION_1 = new HTTPAPI_VERSION(1, 0);
            internal static readonly HTTPAPI_VERSION HTTPAPI_VERSION_2 = new HTTPAPI_VERSION(2, 0);
            #endregion

            [DllImport("httpapi.dll", SetLastError = true)]
            internal static extern uint HttpSetServiceConfiguration(
                IntPtr ServiceHandle,
                HTTP_SERVICE_CONFIG_ID ConfigId,
                IntPtr pConfigInformation,
                int ConfigInformationLength,
                IntPtr pOverlapped);

            [DllImport("httpapi.dll", SetLastError = true)]
            internal static extern uint HttpDeleteServiceConfiguration(
                IntPtr ServiceIntPtr,
                HTTP_SERVICE_CONFIG_ID ConfigId,
                IntPtr pConfigInformation,
                int ConfigInformationLength,
                IntPtr pOverlapped);

            [DllImport("httpapi.dll", SetLastError = true)]
            internal static extern uint HttpInitialize(
                HTTPAPI_VERSION Version,
                uint Flags,
                IntPtr pReserved);

            [DllImport("httpapi.dll", SetLastError = true)]
            internal static extern uint HttpTerminate(
                uint Flags,
                IntPtr pReserved);

            #region Nested type: HTTP_API_ErrorCode
            internal enum HTTP_API_ErrorCode : uint
            {
                NO_ERROR = 0,
                ERROR_FILE_NOT_FOUND = 2,
                ERROR_INVALID_PARAMETER = 87,
                ERROR_ALREADY_EXISTS = 183,
            }
            #endregion

            #region Nested type: HTTP_INITIALIZE_FLAG
            [Flags]
            internal enum HTTP_INITIALIZE_FLAG : uint
            {
                HTTP_INITIALIZE_SERVER = 0x00000001,
                HTTP_INITIALIZE_CONFIG = 0x00000002
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_SSL_FLAG
            [Flags]
            internal enum HTTP_SERVICE_CONFIG_SSL_FLAG : uint
            {
                HTTP_SERVICE_CONFIG_SSL_FLAG_USE_DS_MAPPER = 0x00000001,
                HTTP_SERVICE_CONFIG_SSL_FLAG_NEGOTIATE_CLIENT_CERT = 0x00000002,
                HTTP_SERVICE_CONFIG_SSL_FLAG_NO_RAW_FILTER = 0x00000004
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_ID
            internal enum HTTP_SERVICE_CONFIG_ID
            {
                HttpServiceConfigIPListenList = 0,
                HttpServiceConfigSSLCertInfo,
                HttpServiceConfigUrlAclInfo,
                HttpServiceConfigMax
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_IP_LISTEN_PARAM
            [StructLayout(LayoutKind.Sequential)]
            internal struct HTTP_SERVICE_CONFIG_IP_LISTEN_PARAM
            {
                public ushort AddrLength;
                public IntPtr pAddress;
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_SSL_KEY
            [StructLayout(LayoutKind.Sequential)]
            internal struct HTTP_SERVICE_CONFIG_SSL_KEY
            {
                public IntPtr pIpPort;
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_SSL_PARAM
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct HTTP_SERVICE_CONFIG_SSL_PARAM
            {
                public int SslHashLength;
                public IntPtr pSslHash;
                public Guid AppId;

                [MarshalAs(UnmanagedType.LPWStr)]
                public string pSslCertStoreName;

                public uint DefaultCertCheckMode;
                public int DefaultRevocationFreshnessTime;
                public int DefaultRevocationUrlRetrievalTimeout;

                [MarshalAs(UnmanagedType.LPWStr)]
                public string pDefaultSslCtlIdentifier;

                [MarshalAs(UnmanagedType.LPWStr)]
                public string pDefaultSslCtlStoreName;

                public uint DefaultFlags;
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_SSL_SET
            [StructLayout(LayoutKind.Sequential)]
            internal struct HTTP_SERVICE_CONFIG_SSL_SET
            {
                public HTTP_SERVICE_CONFIG_SSL_KEY KeyDesc;
                public HTTP_SERVICE_CONFIG_SSL_PARAM ParamDesc;
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_URLACL_KEY
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct HTTP_SERVICE_CONFIG_URLACL_KEY
            {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string pUrlPrefix;

                public HTTP_SERVICE_CONFIG_URLACL_KEY(string urlPrefix)
                {
                    pUrlPrefix = urlPrefix;
                }
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_URLACL_PARAM
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct HTTP_SERVICE_CONFIG_URLACL_PARAM
            {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string pStringSecurityDescriptor;

                public HTTP_SERVICE_CONFIG_URLACL_PARAM(string securityDescriptor)
                {
                    pStringSecurityDescriptor = securityDescriptor;
                }
            }
            #endregion

            #region Nested type: HTTP_SERVICE_CONFIG_URLACL_SET
            [StructLayout(LayoutKind.Sequential)]
            internal struct HTTP_SERVICE_CONFIG_URLACL_SET
            {
                public HTTP_SERVICE_CONFIG_URLACL_KEY KeyDesc;
                public HTTP_SERVICE_CONFIG_URLACL_PARAM ParamDesc;
            }
            #endregion

            #region Nested type: HTTPAPI_VERSION
            [StructLayout(LayoutKind.Sequential, Pack = 2)]
            internal struct HTTPAPI_VERSION
            {
                public ushort HttpApiMajorVersion;
                public ushort HttpApiMinorVersion;

                public HTTPAPI_VERSION(ushort majorVersion, ushort minorVersion)
                {
                    HttpApiMajorVersion = majorVersion;
                    HttpApiMinorVersion = minorVersion;
                }
            }
            #endregion
        }
        #endregion
    }
}
