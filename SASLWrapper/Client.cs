using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SASLWrapper
{
    public class ClientParams
    {
        public string Service { get; set; }
        public string ServerFQDN { get; set; }
        public string IpLocalPort { get; set; }
        public string IpRemotePort { get; set; }
        public uint Flags { get; set; }
        public Func<string> Authname { get; set; }
        public Func<string> User { get; set; }
        public Func<string> Pass { get; set; }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(GetType().Name).Append("{")
                .Append(" Service: ").Append(Service)
                .Append(" ServerFQDN: ").Append(ServerFQDN)
                .Append(" IpLocalPort: ").Append(IpLocalPort)
                .Append(" IpRemotePort: ").Append(IpRemotePort)
                .Append(" Flags: ").Append(Flags)
                .Append(" }");
            return sb.ToString();
        }
    }

    public class Client : IDisposable
    {
        private IntPtr handle;
#pragma warning disable IDE0052 // Remove unread private members
        private ICollection<Delegate> delegates;
#pragma warning restore IDE0052 // Remove unread private members

        internal Client(IntPtr handle, ICollection<Delegate> delegates)
        {
            this.handle = handle;
            this.delegates = delegates;
        }

        public string[] Listmech()
        {
            IntPtr nativeResult = IntPtr.Zero;

            int r = Native.sasl_listmech(
                handle,
                IntPtr.Zero,
                "",
                ",",
                "",
                ref nativeResult,
                IntPtr.Zero,
                IntPtr.Zero);
            CheckSaslReturnCode(r, "sasl_listmech");

            return Marshal.PtrToStringAnsi(nativeResult).Split(',');
        }

        public bool Start(string mechlist, out byte[] clientout, out string mech)
        {
            uint clientoutlen = 0;
            IntPtr nativeClientout = IntPtr.Zero;
            IntPtr nativeMech = IntPtr.Zero;

            int r = Native.sasl_client_start(
                handle,
                mechlist,
                IntPtr.Zero,
                ref nativeClientout,
                ref clientoutlen,
                ref nativeMech);
            CheckSaslReturnCode(r, "sasl_client_start");

            if (clientoutlen > 0)
            {
                clientout = new byte[clientoutlen];
                Marshal.Copy(nativeClientout, clientout, 0, (int)clientoutlen);
            }
            else
            {
                clientout = null;
            }

            mech = Marshal.PtrToStringAnsi(nativeMech);

            return r == Native.SASL_CONTINUE;
        }

        public bool Step(byte[] serverin, out byte[] clientout)
        {
            IntPtr nativeServerin = Marshal.AllocHGlobal(serverin.Length);
            Marshal.Copy(serverin, 0, nativeServerin, serverin.Length);

            uint clientoutlen = 0;
            IntPtr nativeClientout = IntPtr.Zero;

            int r = Native.sasl_client_step(
                handle,
                nativeServerin,
                (uint)serverin.Length,
                IntPtr.Zero,
                ref nativeClientout,
                ref clientoutlen);
            CheckSaslReturnCode(r, "sasl_client_step");

            if (clientoutlen > 0)
            {
                clientout = new byte[clientoutlen];
                Marshal.Copy(nativeClientout, clientout, 0, (int)clientoutlen);
            }
            else
            {
                clientout = null;
            }

            return r == Native.SASL_CONTINUE;
        }

        private static void CheckSaslReturnCode(int r, string function)
        {
            if (r < 0)
            {
                throw new Exception(string.Format("{0} error: {1}", function, r));
            }
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // No managed state to dispose.
                }

                // Unmanaged state.
                if (handle != IntPtr.Zero)
                {
                    Native.sasl_dispose(ref handle);
                    handle = IntPtr.Zero; // Redundant.
                }

                delegates = null;

                disposedValue = true;
            }
        }

        ~Client()
        {
           Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
