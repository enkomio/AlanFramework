using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace DotNetAgentRunnerTest
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0 && File.Exists(args[0]))
            {
                var s = Convert.ToBase64String(File.ReadAllBytes(args[0]));
                DotNetAgentRunner.AgentRunner.Run(s);
            }                
            else
            {
                DotNetAgentRunner.AgentRunner.Run(AgentFiles.Agent);
            }
                
        }
    }
}
