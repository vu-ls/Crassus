using Crassus.ProcMon;
using Crassus.Crassus;
using Crassus.Crassus.CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;

namespace Crassus
{
    class Program
    {
        static private bool IsCurrentUserAnAdmin()
        {
            var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        static private bool IsCurrentUserInAdminGroup()
        {
            // https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
            // S-1-5-32-544
            // A built-in group. After the initial installation of the operating system,
            // the only member of the group is the Administrator account.
            // When a computer joins a domain, the Domain Admins group is added to
            // the Administrators group. When a server becomes a domain controller,
            // the Enterprise Admins group also is added to the Administrators group.
            var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            var claims = principal.Claims;
            return (claims.FirstOrDefault(c => c.Value == "S-1-5-32-544") != null);
        }
        static void Main(string[] args)
        {
            string appVersion = String.Format("{0}.{1}.{2}", Assembly.GetExecutingAssembly().GetName().Version.Major.ToString(), Assembly.GetExecutingAssembly().GetName().Version.Minor.ToString(), Assembly.GetExecutingAssembly().GetName().Version.Build.ToString());
            if (args.Length == 0)
            {
                string help = 
$@"Crassus v{appVersion} [ Will Dormann ]
- For more information visit https://github.com/vullabs/crassus

Usage: Crassus.exe [PMLFile] [options]

[PMLFile]               Location (file) of the ProcMon event log file.
--verbose               Enable verbose output.
--debug                 Enable debug output.

Examples:


Parse an existing PML event log output

Crassus.exe C:\tmp\Bootlog.PML

";
                Logger.Info(help, true, false);

#if DEBUG
                Console.ReadLine();
#endif
                return;
            }

            
            Logger.Info($"Crassus v{appVersion}");

            try
            {
                // This will parse everything into RuntimeData.*
                CommandLineParser cmdParser = new CommandLineParser(args);
            } catch (Exception e) {
                Logger.Error(e.Message);
#if DEBUG
                Console.ReadLine();
#endif
                return;
            }


            if (RuntimeData.DetectProxyingDLLs)
            {
                Logger.Info("Starting DLL Proxying detection");
                Logger.Info("", true, false);
                Logger.Info("This feature is not to be relied upon - I just thought it'd be cool to have.", true, false);
                Logger.Info("The way it works is by checking if a process has 2 or more DLLs loaded that share the same name but different location.", true, false);
                Logger.Info("For instance 'version.dll' within the application's directory and C:\\Windows\\System32.", true, false);
                Logger.Info("", true, false);
                Logger.Info("There is no progress indicator - when a DLL is found it will be displayed here - hit CTRL-C to exit.");

                Detect detector = new Detect();
                detector.Run();
            }
            else
            {
                Manager manager = new Manager();

                if (!RuntimeData.ProcessExistingLog)
                {

                    Logger.Verbose("Making sure there are no ProcessMonitor instances...");
                    manager.TerminateProcessMonitor();

                    if (RuntimeData.ProcMonLogFile != "" && File.Exists(RuntimeData.ProcMonLogFile))
                    {
                        Logger.Verbose("Deleting previous log file: " + RuntimeData.ProcMonLogFile);
                        File.Delete(RuntimeData.ProcMonLogFile);
                    }

                    Logger.Info("Getting PMC file...");
                    string pmcFile = manager.GetPMCFile();

                    Logger.Info("Executing ProcessMonitor...");
                    manager.StartProcessMonitor();

                    Logger.Info("Process Monitor has started...");

                    Logger.Warning("Press ENTER when you want to terminate Process Monitor and parse its output...", false, true);
                    Console.ReadLine();

                    Logger.Info("Terminating Process Monitor...");
                    manager.TerminateProcessMonitor();
                }
                if (IsCurrentUserInAdminGroup())
                {
                    Logger.Warning("You are logged in as an admin! Some results may simply be UAC bypasses.");
                }

                if (IsCurrentUserAnAdmin())
                {
                    Logger.Error("This utility will not function with admin privileges");
                    return;
                }

                Logger.Info("Reading events file...");
                ProcMonPML log = new ProcMonPML(RuntimeData.ProcMonLogFile);

                Logger.Info("Found " + String.Format("{0:N0}", log.TotalEvents()) + " events...");

                EventProcessor processor = new EventProcessor(log);
                processor.Run();

                if (RuntimeData.FoundBad)
                {
                    Logger.Info("CSV Output stored in: " + RuntimeData.CsvOutputFile);
                    if (RuntimeData.ExportsOutputDirectory != "")
                    {
                        Logger.Info("Proxy DLL sources stored in: " + RuntimeData.ExportsOutputDirectory);
                    }
                }

            }

            Logger.Success("All done");

#if DEBUG
            Console.ReadLine();
#endif
        }
    }
}
