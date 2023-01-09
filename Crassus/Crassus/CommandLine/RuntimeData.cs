using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crassus.Crassus.CommandLine
{
    class RuntimeData
    {
        public static string ProcMonConfigFile = "";

        public static string ProcMonLogFile = "";

        public static string CsvOutputFile = "results.csv";

        public static string ProcMonExecutable = "";

        public static string ExportsOutputDirectory = "stubs";

        public static string ProxyDllTemplate = "";

        public static string ProxyDllTemplateHeader = "";

        public static string ProxyDllTemplateResource = "";

        public static bool ProcessExistingLog = true;

        public static List<string> TrackExecutables = new List<string>();

        public static bool Verbose = false;

        public static bool Debug = false;

        public static bool InjectBackingFileIntoConfig = false;

        public static bool IncludeAllDLLs = false;

        public static bool DetectProxyingDLLs = false;

        public static bool FoundBad = false;

        public static bool HasAcronis = false;
    }
}
