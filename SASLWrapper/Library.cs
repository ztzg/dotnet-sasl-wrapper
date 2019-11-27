using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace SASLWrapper
{
    public sealed class Library
    {
        public enum ExceptionLocation
        {
            LogCallback,
            GetsimpleCallback,
            GetsecretCallback
        }

        private static readonly Lazy<Library> lazy = new Lazy<Library>(() => new Library());

        private static readonly ICollection<Delegate> delegates = new List<Delegate>();

        private static readonly bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static Action<Exception, ExceptionLocation, object> NoteException { get; set; }

        public static bool NeedWSAStartup { get; set; } = false;

        public static Action<int, string> Log { get; set; }

        public static Library Instance { get { return lazy.Value; } }

        public Client CreateClient(ClientParams clientParams)
        {
            IList<CallbackDef> callbacks = new List<CallbackDef>();
            // GetFunctionPointerForDelegate doc says that delegates must be kept alive.
            ICollection<Delegate> delegates = new List<Delegate>();

            if (clientParams.Authname != null)
            {
                Native.sasl_getsimple_t d = GetsimpleAdapter(clientParams.Authname);

                delegates.Add(d);
                callbacks.Add(new CallbackDef
                {
                    id = Native.SASL_CB_AUTHNAME,
                    proc = Marshal.GetFunctionPointerForDelegate(d)
                });
            }

            if (clientParams.User != null)
            {
                Native.sasl_getsimple_t d = GetsimpleAdapter(clientParams.User);

                delegates.Add(d);
                callbacks.Add(new CallbackDef
                {
                    id = Native.SASL_CB_USER,
                    proc = Marshal.GetFunctionPointerForDelegate(d)
                });
            }

            if (clientParams.Pass != null)
            {
                Native.sasl_getsecret_t d = GetsecretAdapter(clientParams.Pass);

                delegates.Add(d);
                callbacks.Add(new CallbackDef
                {
                    id = Native.SASL_CB_PASS,
                    proc = Marshal.GetFunctionPointerForDelegate(d)
                });
            }

            IntPtr cbs = MarshallCallbacks(callbacks);

            IntPtr handle = IntPtr.Zero;
            int r = Native.sasl_client_new(
                clientParams.Service,
                clientParams.ServerFQDN,
                clientParams.IpLocalPort,
                clientParams.IpRemotePort,
                cbs,
                clientParams.Flags,
                ref handle);

            if (r != Native.SASL_OK)
            {
                Marshal.FreeHGlobal(cbs);
                throw new Exception(string.Format("sasl_client_new: {0}", r));
            }

            return new Client(handle, delegates);
        }

        private Library()
        {
            if (NeedWSAStartup)
            {
                DoWSAStartup();
                NeedWSAStartup = false;
            }

            DoSaslClientInit();
        }

        private static void DoSaslClientInit()
        {
            IList<CallbackDef> callbacks = new List<CallbackDef>();

            if (isWindows)
            {
                Native.sasl_getpath_t d = new Native.sasl_getpath_t(GetpathCb);

                delegates.Add(d);
                callbacks.Add(new CallbackDef
                {
                    id = Native.SASL_CB_GETPATH,
                    proc = Marshal.GetFunctionPointerForDelegate(d)
                });
            }

            if (Log != null)
            {
                Native.sasl_log_t d = new Native.sasl_log_t(LogCb);

                delegates.Add(d);
                callbacks.Add(new CallbackDef
                {
                    id = Native.SASL_CB_LOG,
                    proc = Marshal.GetFunctionPointerForDelegate(d)
                });
            }

            IntPtr cbs = MarshallCallbacks(callbacks);
            int r = Native.sasl_client_init(cbs);

            if (r != Native.SASL_OK)
            {
                Marshal.FreeHGlobal(cbs);
                throw new Exception(string.Format("sasl_client_init error: {0}", r));
            }
        }

        private static void DoWSAStartup()
        {
            Native.WSAData64 wsaData;
            int r = Native.WSAStartup(2, out wsaData);

            if (r != 0)
            {
                throw new Exception(string.Format("WSAStartup error: {0}", r));
            }
        }

        private static void MaybeNoteException(Exception e, ExceptionLocation l, object o)
        {
            if (NoteException != null)
            {
                try
                {
                    NoteException(e, l, o);
                }
                catch { }
            }
        }

        private static int GetpathCb(IntPtr context, ref IntPtr result)
        {
            string loc = Assembly.GetExecutingAssembly().Location;
            string dir = System.IO.Path.GetDirectoryName(loc);
            result = Marshal.StringToHGlobalAnsi(dir);
            return Native.SASL_OK;
        }

        private static int LogCb(IntPtr context, int level, IntPtr message)
        {
            if (Log != null)
            {
                string messageString = Marshal.PtrToStringAnsi(message);
                try
                {
                    Log(level, messageString);
                }
                catch (Exception e)
                {
                    MaybeNoteException(e, ExceptionLocation.LogCallback, messageString);
                }
            }
            return Native.SASL_OK;
        }

        private struct CallbackDef
        {
            internal uint id;
            internal IntPtr proc;
            internal IntPtr context;
        }

        private static IntPtr MarshallCallbacks(IList<CallbackDef> callbacks)
        {
            const int elemSize = 8 + 8 + 8;
            IntPtr ptrs = Marshal.AllocHGlobal(elemSize * (callbacks.Count + 1));
            for (int i = 0; i < callbacks.Count; i++)
            {
                int elemOffset = i * elemSize;

                WriteCallbackStruct(ptrs, elemOffset, callbacks[i].id, callbacks[i].proc, callbacks[i].context);
            }
            WriteCallbackStruct(ptrs, callbacks.Count * elemSize, Native.SASL_CB_LIST_END, IntPtr.Zero, IntPtr.Zero);
            return ptrs;
        }

        private static void WriteCallbackStruct(IntPtr ptrs, int elemOffset, uint id, IntPtr proc, IntPtr context)
        {
            if (isWindows)
            {
                Marshal.WriteInt32(ptrs, elemOffset + 0, (int)id);
            }
            else
            {
                Marshal.WriteInt64(ptrs, elemOffset + 0, (int)id);
            }
            Marshal.WriteIntPtr(ptrs, elemOffset + 8, proc);
            Marshal.WriteIntPtr(ptrs, elemOffset + 8 + 8, context);
        }

        private static Native.sasl_getsimple_t GetsimpleAdapter(Func<string> f)
        {
            return new Native.sasl_getsimple_t((IntPtr context, int id, ref IntPtr result, ref uint len) => {
                string s = null;

                try
                {
                    s = f();
                }
                catch (Exception e)
                {
                    MaybeNoteException(e, ExceptionLocation.GetsimpleCallback, f);
                }

                result = Marshal.StringToHGlobalAnsi(s);
                return Native.SASL_OK;
            });
        }

        private static int Strlen(IntPtr ptr)
        {
            int len = 0;
            while (Marshal.ReadByte(ptr, len) != 0)
            {
                len++;
            }
            return len;
        }

        private static Native.sasl_getsecret_t GetsecretAdapter(Func<string> f)
        {
            // [result is] set to password structure which must persist until
            // next call to getsecret in same connection, but middleware will
            // erase password data when it's done with it.
            IntPtr lastResult = IntPtr.Zero;

            return new Native.sasl_getsecret_t((IntPtr conn, IntPtr context, int id, ref IntPtr result) => {
                if (lastResult != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(lastResult);
                    lastResult = IntPtr.Zero;
                }

                if (id != Native.SASL_CB_PASS)
                {
                    return Native.SASL_BADPARAM;
                }

                string pass = null;

                try
                {
                    pass = f();
                }
                catch (Exception e)
                {
                    MaybeNoteException(e, ExceptionLocation.GetsecretCallback, f);
                }

                if (pass == null)
                {
                    result = lastResult = IntPtr.Zero;
                }
                else
                {
                    IntPtr nativePass = Marshal.StringToHGlobalAnsi(pass);
                    int nativeLength = Strlen(nativePass);

                    IntPtr secretStruct = Marshal.AllocHGlobal(nativeLength + 4);
                    Marshal.WriteInt32(secretStruct, 0, nativeLength);
                    for (int i = 0; i < nativeLength; i++)
                    {
                        byte b = Marshal.ReadByte(nativePass, i);
                        Marshal.WriteByte(secretStruct, 4 + i, b);
                        Marshal.WriteByte(nativePass, i, 0);
                    }
                    Marshal.FreeHGlobal(nativePass);

                    result = lastResult = secretStruct;
                }

                return Native.SASL_OK;
            });
        }
    }
}
