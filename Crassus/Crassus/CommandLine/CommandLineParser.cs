﻿using Crassus.ProcMon;
using Crassus.Properties;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Crassus.Crassus.CommandLine
{
    internal class CommandLineParser
    {
        private readonly string[] RawArguments;

        private readonly Dictionary<string, string> GlobalArguments = new Dictionary<string, string>
        {
            { "pml", "" },
            { "pmc", "" },
            { "csv", "" },
            { "exe", "" },
            { "exports", "" },
            { "procmon", "" },
            { "proxy-dll-template", "" },
            { "existing-log", "switch" },
            { "verbose", "switch" },
            { "debug", "switch" },
            { "all", "switch" },
            { "detect", "switch" }
        };

        private Dictionary<string, string> Arguments = new Dictionary<string, string>();

        public CommandLineParser(string[] args)
        {
            RawArguments = args;

            Load();
        }

        private void Load()
        {
            Arguments = LoadCommandLine(GlobalArguments);
            Parse(Arguments);
        }

        private Dictionary<string, string> LoadCommandLine(Dictionary<string, string> arguments)
        {
            foreach (string parameter in arguments.Keys.ToList())
            {
                arguments[parameter] = GetArgument($"--{parameter}", arguments[parameter] == "switch");
            }

            // Remove null values.
            return arguments
                .Where(v =>
                {
                    return v.Value != null;
                })
                .ToDictionary(v =>
                {
                    return v.Key;
                }, v =>
                {
                    return v.Value;
                });
        }

        private string GetArgument(string name, bool isSwitch = false)
        {
            string value = null;

            for (int i = 0; i < RawArguments.Length; i++)
            {
                if (string.Equals(RawArguments[i], name, StringComparison.OrdinalIgnoreCase))
                {
                    if (isSwitch)
                    {
                        // This is a boolean switch, like --verbose, so we just return a non empty value.
                        value = "true";
                    }
                    else
                    {
                        if (i + 1 <= RawArguments.Length)
                        {
                            value = RawArguments[i + 1];
                        }
                    }
                    break;
                }
            }

            return value;
        }

        private void Parse(Dictionary<string, string> arguments)
        {
            foreach (KeyValuePair<string, string> argument in arguments)
            {
                switch (argument.Key.ToLower())
                {
                    case "debug":
                        if (!string.Equals(argument.Value, "false", StringComparison.OrdinalIgnoreCase))
                        {
                            RuntimeData.Debug = (argument.Value.Length > 0);
                            Logger.IsDebug = RuntimeData.Debug;
                        }
                        break;
                    case "verbose":
                        if (!string.Equals(argument.Value, "false", StringComparison.OrdinalIgnoreCase))
                        {
                            RuntimeData.Verbose = (argument.Value.Length > 0);
                            Logger.IsVerbose = RuntimeData.Verbose;
                        }
                        break;
                    case "pmc":
                        RuntimeData.ProcMonConfigFile = argument.Value;
                        break;
                    case "pml":
                        RuntimeData.ProcMonLogFile = argument.Value;
                        break;
                    case "csv":
                        RuntimeData.CsvOutputFile = argument.Value;
                        break;
                    case "exe":
                        RuntimeData.TrackExecutables = argument.Value
                            .Split(',')
                            .ToList()
                            .Select(s =>
                            {
                                return s.Trim();
                            }) // Trim
                            .Where(s =>
                            {
                                return !string.IsNullOrWhiteSpace(s);
                            }) // Remove empty
                            .Distinct() // Remove duplicates
                            .ToList();
                        break;
                    case "procmon":
                        RuntimeData.ProcMonExecutable = argument.Value;
                        break;
                    case "exports":
                        RuntimeData.ExportsOutputDirectory = argument.Value;
                        break;
                    case "existing-log":
                        if (!string.Equals(argument.Value, "false", StringComparison.OrdinalIgnoreCase))
                        {
                            RuntimeData.ProcessExistingLog = (argument.Value.Length > 0);
                        }
                        break;
                    case "proxy-dll-template":
                        RuntimeData.ProxyDllTemplate = argument.Value;
                        break;
                    case "all":
                        if (!string.Equals(argument.Value, "false", StringComparison.OrdinalIgnoreCase))
                        {
                            RuntimeData.IncludeAllDLLs = (argument.Value.Length > 0);
                        }
                        break;
                    case "detect":
                        if (!string.Equals(argument.Value, "false", StringComparison.OrdinalIgnoreCase))
                        {
                            RuntimeData.DetectProxyingDLLs = (argument.Value.Length > 0);
                        }
                        break;
                    default:
                        throw new Exception("Unknown argument: " + argument.Key);
                }
            }

            // For debug.
            foreach (KeyValuePair<string, string> argument in arguments)
            {
                Logger.Debug($"Command Line (raw): {argument.Key} = {argument.Value}");
            }

            SanitiseRuntimeData();
        }

        private void SanitiseExistingLogProcessing()
        {
            if (Environment.GetCommandLineArgs().Length < 2)
            {
                // We'll never get here.  But whatevs.
                throw new Exception("Please specify a PML file to parse (Environment.GetCommandLineArgs.count()).");
            }
            else if (RuntimeData.ProcMonLogFile?.Length == 0)
            {
                RuntimeData.ProcMonLogFile = Environment.GetCommandLineArgs()[1];
            }

            string ContinuePMLFile = RuntimeData.ProcMonLogFile.ToLower().Replace(".pml", "") + "-1.pml";
            if (!File.Exists(RuntimeData.ProcMonLogFile))
            {
                throw new Exception("PML file does not exist");
            }
            else if (File.Exists(ContinuePMLFile))
            {
                Logger.Warning(RuntimeData.ProcMonLogFile + " appears to be a multi-file PML. Please re-save this log to get complete output!");
            }
        }

        private void SanitiseHijackingDetection()
        {
            // Log and Config files.
            if (RuntimeData.ProcMonConfigFile?.Length == 0)
            {
                // If --pmc is not passed we'll need to create it. In this case we must have a --pml parameter.
                if (RuntimeData.ProcMonLogFile?.Length == 0)
                {
                    throw new Exception("--pml is missing");
                }
                else if (File.Exists(RuntimeData.ProcMonLogFile))
                {
                    // Just a debug statement.
                    Logger.Debug("--pml exists and will be overwritten");
                }
            }
            else if (!File.Exists(RuntimeData.ProcMonConfigFile))
            {
                // If --pmc was passed but does not exist, it's invalid.
                throw new Exception("--pmc does not exist: " + RuntimeData.ProcMonConfigFile);
            }
            else
            {
                // At this point --pmc exists, so we'll have to use that one.
                ProcMonPMC pmc = new ProcMonPMC(RuntimeData.ProcMonConfigFile);

                // If the PMC file has no logfile/backing file, check to see if --pml has been set.
                if (pmc.GetConfiguration().Logfile?.Length == 0)
                {
                    if (RuntimeData.ProcMonLogFile?.Length == 0)
                    {
                        throw new Exception("The --pmc file that was passed has no log/backing file configured and no --pml file has been passed either. Either setup the backing file in the existing PML file or pass a --pml parameter");
                    }
                    // We'll use the --pml argument that was passed.
                    RuntimeData.InjectBackingFileIntoConfig = true;
                }
                else
                {
                    // The PM file has a backing file, so we don't need the --pml argument.
                    RuntimeData.ProcMonLogFile = pmc.GetConfiguration().Logfile;
                }
            }
        }

        private void SanitiseSharedArguments()
        {
            if (RuntimeData.TrackExecutables.Any())
            {
                Logger.Debug("--exe passed, will track the following executables: " + string.Join(", ", RuntimeData.TrackExecutables.ToArray()));
            }

            // Exports directory.
            if (RuntimeData.ExportsOutputDirectory?.Length == 0)
            {
                Logger.Debug("No --exports passed, will skip proxy DLL generation");
            }
            //else if (Directory.Exists(RuntimeData.ExportsOutputDirectory))
            //{
            //    Logger.Debug("--exports directory already exists");
            //}
            //else
            //{
            //    // Directory does not exist.
            //    Logger.Debug("--exports directory does not exist, creating it now");
            //    // Will throw exception if there's an error.
            //    Directory.CreateDirectory(RuntimeData.ExportsOutputDirectory);
            //}

            // Proxy DLL Template.
            if (RuntimeData.ProxyDllTemplate != "")
            {
                // Check if the file exists.
                if (!File.Exists(RuntimeData.ProxyDllTemplate))
                {
                    throw new Exception("--proxy-dll-template file does not exist");
                }

                // Load the template into the file.
                RuntimeData.ProxyDllTemplate = File.ReadAllText(RuntimeData.ProxyDllTemplate);
            }
            else
            {
                // Otherwise, load it from the resource.
                RuntimeData.ProxyDllTemplate = Resources.ResourceManager.GetString("proxy.dll.cpp");
            }

            RuntimeData.ProxyDllTemplateResource = Resources.ResourceManager.GetString("proxy.dll.def");

            // Argument combination validation.
            if (RuntimeData.ProcMonConfigFile != "" && RuntimeData.TrackExecutables.Any())
            {
                throw new Exception("You cannot use --pmc with --exe");
            }
        }

        private void SanitiseRuntimeData()
        {
            // If Debug is enabled, force-enable Verbose.
            if (RuntimeData.Debug)
            {
                RuntimeData.Verbose = Logger.IsVerbose = Logger.IsDebug = true;
            }

            if (RuntimeData.DetectProxyingDLLs)
            {
                // Not much here yet.
            }
            else
            {
                // Now we need to validate everything.
                if (RuntimeData.ProcessExistingLog)
                {
                    SanitiseExistingLogProcessing();
                }
                else
                {
                    SanitiseHijackingDetection();
                }

                SanitiseSharedArguments();
            }
        }
    }
}
