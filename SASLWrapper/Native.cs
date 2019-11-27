using System;
using System.Runtime.InteropServices;

namespace SASLWrapper
{
    internal class Native
    {
        const string SASL2 = "sasl2";
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct WSAData64
        {
            internal ushort wVersion;
            internal ushort wHighVersion;
            internal ushort iMaxSockets;
            internal ushort iMaxUdpDg;
            internal IntPtr lpVendorInfo;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
            internal string szDescription;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
            internal string szSystemStatus;
        }

        [DllImport("ws2", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData64 wsaData);

        internal const int SASL_OK = 0;
        internal const int SASL_CONTINUE = 1;
        internal const int SASL_BADPARAM = -7;

        [DllImport(SASL2)]
        internal static extern int sasl_client_init(IntPtr callbacks);

        [DllImport(SASL2)]
        internal static extern int sasl_client_new(string service,
            string serverFQDN,
            string iplocalport,
            string ipremoteport,
            IntPtr prompt_supp,
            uint flags,
            ref IntPtr pconn);

        [DllImport(SASL2)]
        internal static extern int sasl_dispose(ref IntPtr conn);

        [DllImport(SASL2)]
        internal static extern int sasl_listmech(IntPtr conn,
            IntPtr user,
            string prefix,
            string sep,
            string suffix,
            ref IntPtr result,
            IntPtr plen,
            IntPtr pcount);

        [DllImport(SASL2)]
        internal static extern int sasl_client_start(IntPtr conn,
            string mechlist,
            IntPtr prompt_need,
            ref IntPtr clientout,
            ref uint clientoutlen,
            ref IntPtr mech);

        [DllImport(SASL2)]
        internal static extern int sasl_client_step(IntPtr conn,
               IntPtr serverin,
               uint serverinlen,
               IntPtr prompt_need,
               ref IntPtr clientout,
               ref uint clientoutlen);

        internal const int SASL_CB_LIST_END = 0;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int sasl_log_t(IntPtr context, int level, IntPtr message);

        internal const int SASL_CB_LOG = 2;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int sasl_getpath_t(IntPtr context, ref IntPtr result);

        internal const int SASL_CB_GETPATH = 3;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int sasl_getsimple_t(IntPtr context, int id, ref IntPtr result, ref uint len);

        internal const int SASL_CB_USER = 0x4001;
        internal const int SASL_CB_AUTHNAME = 0x4002;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate int sasl_getsecret_t(IntPtr conn, IntPtr context, int id, ref IntPtr result);

        internal const int SASL_CB_PASS = 0x4004;
    }
}
