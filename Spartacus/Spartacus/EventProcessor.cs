using Spartacus.ProcMon;
using Spartacus.Properties;
using Spartacus.Spartacus.CommandLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using static Spartacus.ProcMon.ProcMonConstants;
using static Spartacus.Spartacus.PEFileExports;

namespace Spartacus.Spartacus
{
    class EventProcessor
    {
        private readonly ProcMonPML PMLog;

        private Dictionary<string, PMLEvent> EventsOfInterest = new Dictionary<string, PMLEvent>();

        public EventProcessor(ProcMonPML log)
        {
            PMLog = log;
        }

        public void Run()
        {
            // Find all events that indicate that a DLL is vulnerable.
            Stopwatch watch = Stopwatch.StartNew();

            FindEvents();
            
            watch.Stop();
            if (RuntimeData.Debug)
            {
                Logger.Debug(String.Format("FindEvents() took {0:N0}ms", watch.ElapsedMilliseconds));
            }

            // Extract all DLL paths into a list.
            Logger.Verbose("Extract paths from events of interest...");
            List<string> Paths = new List<string>();
            List<string> WritablePaths = new List<string>();
            foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
            {
                try
                {
                    string name = Path.GetFileName(item.Key).ToLower();
                    //Logger.Info(name);
                    string path = item.Key.ToLower();
                    //Logger.Info(path);
                    if (!Paths.Contains(path))
                    {
                        Paths.Add(path);
                    }

                }
                catch (Exception e)
                {
                    //Logger.Error(e.Message);
                }
            }
            Logger.Verbose("Found " + String.Format("{0:N0}", Paths.Count()) + " unique DLLs...");

            // Now try to find the actual DLL that was loaded. For example if 'version.dll' was missing, identify
            // the location it was eventually loaded from.
            //watch.Restart();

            //IdentifySuccessfulEvents(Paths);

            //watch.Stop();
            //if (RuntimeData.Debug)
            //{
            //    Logger.Debug(String.Format("IdentifySuccessfulEvents() took {0:N0}ms", watch.ElapsedMilliseconds));
            //}


            //if (RuntimeData.ExportsOutputDirectory != "" && Directory.Exists(RuntimeData.ExportsOutputDirectory))
            //{
            //    ExtractExportFunctions();
            //}

            foreach (string PathName in Paths)
            {
                if (File.Exists(PathName))
                {
                    // This is a library or EXE that was actually loaded.
                    // Let's check the privileges of the file and directory to make sure that they're sane.
                    bool Writable = CheckPathACLs(PathName);
                    if (Writable && !WritablePaths.Contains(PathName))
                    {
                        WritablePaths.Add(PathName);
                        Logger.Success("We can write to: " + PathName);
                    }
                    else
                    {
                        if (HasWritePermissionOnDir(PathName))
                        {
                            Logger.Warning("ACLs should allow writing to " + PathName + ", but we cannot. In use maybe?");
                        }
                    }


                    string Dir = FindMutableDirPart(PathName);
                    if (Dir != "")
                    {
                        // There is a parent directory of the target file that can be renamed by the current user
                        if (!WritablePaths.Contains(Dir))
                        {
                            string PlantFileName = Path.GetFileName(PathName);
                            WritablePaths.Add(Dir);
                            Logger.Success("We can rename: " + Dir + " to allow loading of our own " + PlantFileName);
                        }
                        //else
                        //{
                        //    if (HasWritePermissionOnDir(Dir))
                        //    {
                        //        Logger.Warning("ACLs should allow renaming " + Dir + ", but we cannot. In use maybe?");
                        //    }
                        //}
                    }


                }
                else
                {
                    // Must be a missing file.  Let's check the directory ACLs.
                    string MissingFileDir = Path.GetDirectoryName(PathName);
                    string MissingFile = Path.GetFileName(PathName);
                    if (HasWritePermissionOnDir(MissingFileDir))
                    {
                        Logger.Success("ACLs should allow placment of missing " + MissingFile + " in " + MissingFileDir);
                    }

                }
            }



            try
            {
                SaveEventsOfInterest();
            } catch (Exception e)
            {
                Logger.Error(e.Message);
                Logger.Warning("There was an error saving the output. In order to avoid losing the processed data");
                Logger.Warning("we're going to give it another go. When you resolve the error described above");
                Logger.Warning("hit ENTER and another attempt at saving the output will be made.", false, true);
                Console.ReadLine();
                Logger.Warning("Trying to save file again...");
                SaveEventsOfInterest();
            }
        }

        public static bool HasWritePermissionOnDir(string path)
        {
            var mySID = WindowsIdentity.GetCurrent().User;
            var mySIDs = WindowsIdentity.GetCurrent().Groups;
            var writeAllow = false;
            var writeDeny = false;
            //Logger.Info(path);

            System.Security.AccessControl.DirectorySecurity accessControlList;
            try
            {
                accessControlList = Directory.GetAccessControl(path);
            }
            catch (Exception e)
            {
                //Logger.Error(e.ToString());
                return false;
            }
            if (accessControlList == null)
                return false;
            
            System.Security.AccessControl.AuthorizationRuleCollection accessRules = null;
            try
            {
                accessRules = accessControlList.GetAccessRules(true, true,
                                          typeof(System.Security.Principal.SecurityIdentifier));
            }
            catch (Exception e)
            {
                //Logger.Error(e.ToString());
                return false;
            }
            
            if (accessRules == null)
                return false;

            mySIDs.Add(mySID);

            foreach (FileSystemAccessRule rule in accessRules)
            {
                if ((FileSystemRights.Write & rule.FileSystemRights) != FileSystemRights.Write)
                    continue;

                if (rule.AccessControlType == AccessControlType.Allow)
                    foreach (var SID in mySIDs)
                    {
                        if (mySIDs.Contains(rule.IdentityReference))
                        {
                            //Logger.Info("SID " + SID + " can write to this file!");
                            writeAllow = true;
                        }
                    }
                else if (rule.AccessControlType == AccessControlType.Deny)
                    foreach (var SID in mySIDs)
                    {
                        if (mySIDs.Contains(rule.IdentityReference))
                        {
                            writeDeny = true;
                        }
                    }
            }

            return writeAllow && !writeDeny;
        }

        private bool CheckPathACLs(string pathname)
        {
            bool Writable = false;
//            foreach (string pathname in Paths)
//            {
                //string dir = Path.GetDirectoryName(pathname);
                try
                {
                    FileAttributes attr = File.GetAttributes(pathname);
                    if (attr.HasFlag(FileAttributes.Directory))
                    {
                        //Logger.Info(pathname + " is a directory!");
                    }
                }
                catch (Exception e)
                {
                    //Nothing
                }
                if (File.Exists(pathname))
                {
                    try
                    {
                        //Logger.Info(pathname + " is a file that exists!");
                        FileSecurity fSecurity = File.GetAccessControl(pathname);
                        //Logger.Info("Got security details!");
                        FileStream writableFile = File.OpenWrite(pathname);
                        //Logger.Info(pathname + " is writable!!!!");
                        writableFile.Close();
                        Writable = true;
;                    }
                    catch (Exception e)
                    {
                        // Nothing
                    }
                }
                //Logger.Info(FindMutableDirPart(pathname));


                
//            }
            return Writable;
        }

        private string FindMutableDirPart(string filePath)
        {
            //Logger.Info("Getting directory for: " + filePath);
            string dirPart = Path.GetDirectoryName(filePath);
            //Logger.Info(dirPart);
            try
            {
                Directory.Move(dirPart, dirPart + "-test");
                Directory.Move(dirPart + "-test", dirPart);
            }
            catch (Exception e)
            {
                if (dirPart.Length > 4)
                {
                    dirPart = FindMutableDirPart(dirPart);
                }
                else
                {
                    //Logger.Info("Setting dirPart to empty string!");
                    dirPart = "";
                }
            }
            
            
            return dirPart;
        }

            private string LookForFileIfNeeded(string filePath)
        {
            // When we get a path it may be either x32 or a x64. As Spartacus is x64 we can search in the x32 locations if needed.
            if (File.Exists(filePath))
            {
                return filePath;
            }

            // There should really be a case-insensitive replace.
            if (filePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.System), StringComparison.OrdinalIgnoreCase))
            {   
                return Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) + filePath.Remove(0, Environment.GetFolderPath(Environment.SpecialFolder.System).Length);
            }
            else if (filePath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase))
            {
                return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + filePath.Remove(0, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).Length);
            }

            // Otherwise return the original value.
            return filePath;
        }

        private void ExtractExportFunctions()
        {
            Logger.Info("Extracting DLL export functions...");

            PEFileExports ExportLoader = new PEFileExports();

            List<string> alreadyProcessed = new List<string>();

            foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
            {
                if (alreadyProcessed.Contains(Path.GetFileName(item.Value.Path).ToLower()))
                {
                    continue;
                }
                alreadyProcessed.Add(Path.GetFileName(item.Value.Path).ToLower());
                Logger.Info("Processing " + Path.GetFileName(item.Value.Path), false, true);
                string saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, Path.GetFileName(item.Value.Path) + ".cpp");

                if (item.Value.FoundPath == "")
                {
                    File.Create(saveAs + "-file-not-found").Dispose();
                    Logger.Warning(" - No DLL Found", true, false);
                    continue;
                }

                string actualLocation = LookForFileIfNeeded(item.Value.FoundPath);
                if (!File.Exists(actualLocation))
                {
                    File.Create(saveAs + "-file-not-found").Dispose();
                    Logger.Warning(" - No DLL Found", true, false);
                    continue;
                }

                string actualPathNoExtension = Path.Combine(Path.GetDirectoryName(actualLocation), Path.GetFileNameWithoutExtension(actualLocation));

                List<FileExport> exports = new List<FileExport>();
                try
                {
                    exports = ExportLoader.Extract(actualLocation);
                } catch (Exception e)
                {
                    // Nothing.
                }
                
                if (exports.Count == 0)
                {
                    File.Create(saveAs + "-no-exports-found").Dispose();
                    Logger.Warning(" - No export functions found", true, false);
                    continue;
                }

                List<string> pragma = new List<string>();
                string pragmaTemplate = "#pragma comment(linker,\"/export:{0}={1}.{2},@{3}\")";
                int steps = exports.Count() / 10;
                if (steps == 0)
                {
                    steps = 1;
                }
                int counter = 0;
                foreach (FileExport f in exports)
                {
                    if (++counter % steps == 0)
                    {
                        Logger.Info(".", false, false);
                    }
                    pragma.Add(String.Format(pragmaTemplate, f.Name, actualPathNoExtension.Replace("\\", "\\\\"), f.Name, f.Ordinal));
                }

                string fileContents = RuntimeData.ProxyDllTemplate.Replace("%_PRAGMA_COMMENTS_%", String.Join("\r\n", pragma.ToArray()));
                File.WriteAllText(saveAs, fileContents);

                Logger.Success("OK", true, false);
            }
        }

        private void SaveEventsOfInterest()
        {
            //Logger.Info("Saving output...");

            //using (StreamWriter stream = File.CreateText(RuntimeData.CsvOutputFile))
            //{
            //    stream.WriteLine(string.Format("Process, Image Path, Missing DLL, Found DLL, Integrity, Command Line"));
            //    foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
            //    {
            //        stream.WriteLine(
            //            string.Format(
            //                "\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\"",
            //                item.Value.Process.ProcessName,
            //                item.Value.Process.ImagePath,
            //                item.Value.Path,
            //                item.Value.FoundPath,
            //                item.Value.Process.Integrity,
            //                item.Value.Process.CommandLine.Replace("\"", "\"\""))
            //            );
            //    }
            //}
        }

        private void IdentifySuccessfulEvents(List<string> Paths)
        {
            if (Paths.Count() == 0)
            {
                Logger.Verbose("No DLLs identified - skipping successful event tracking");
                return;
            }

            UInt32 counter = 0;
            UInt32 steps = PMLog.TotalEvents() / 10;
            if (steps == 0)
            {
                steps = 1;
            }

            Logger.Info("Trying to identify which DLLs were actually loaded...", false, true);
            PMLog.Rewind();
            do
            {
                if (++counter % steps == 0)
                {
                    Logger.Info(".", false, false);
                }

                PMLEvent e = PMLog.GetNextEvent().GetValueOrDefault();
                if (!e.Loaded)
                {
                    break;
                }

                // Now we are looking for "CreateFile" SUCCESS events.
                string p = e.Path.ToLower();
                if (!p.EndsWith(".dll".ToLower()))
                {
                    continue;
                }
                else if (e.Result != EventResult.SUCCESS)
                {
                    continue;
                }
                else if (e.Operation != EventFileSystemOperation.CreateFile)
                {
                    continue;
                }

                // If we are here it means we have found a DLL that was actually loaded. Extract its name.
                string name = Path.GetFileName(p);
                if (name == "")
                {
                    continue;
                }
                else if (!Paths.Contains(name))
                {
                    // We found a SUCCESS DLL but it's not one that is vulnerable.
                    continue;
                }

                // Find all events of interest (NAME/PATH NOT FOUND) that use the same DLL.
                try
                {
                    List<string> keys = EventsOfInterest
                        .Where(ve => Path.GetFileName(ve.Key).ToLower() == name && ve.Value.FoundPath == "")
                        .Select(ve => ve.Key)
                        .ToList();

                    foreach (string key in keys)
                    {
                        PMLEvent Event = EventsOfInterest[key];
                        Event.FoundPath = e.Path;
                        EventsOfInterest[key] = Event;
                    }
                }
                catch (Exception e2)
                {
                    //Logger.Error(e2.Message);
                }


                Paths.Remove(name);
                if (Paths.Count == 0)
                {
                    // Abort if we have no other DLLs to look for.
                    break;
                }
            } while (true);
            Logger.Info("", true, false);
        }

        private void FindEvents()
        {
            UInt32 counter = 0;
            UInt32 steps = PMLog.TotalEvents() / 10;
            if (steps == 0)
            {
                steps = 1;
            }

            Logger.Info("Searching events...", false, true);
            PMLog.Rewind();
            do
            {
                // We care about each of these things:
                // 1) Privileged Create Process on a file that is itself or in a directory that is mutable by a non-privileged user
                // 2) Privileged Load Library on a file that is itself or in a directory that is mutable by a non-privileged user
                // 3) Privileged CreateFile on a file that does not exist
                //
                // For now, we're just looking at EXE and DLL files.


                bool ProcessEvent = false;
                if (++counter % steps == 0)
                {
                    Logger.Info(".", false, false);
                }

                // Get the next event from the stream.
                PMLEvent e = PMLog.GetNextEvent().GetValueOrDefault();
                if (!e.Loaded)
                {
                    break;
                }

                //if (e.EventClass == EventClassType.Process && e.ProcessOperation == EventProcessOperation.Process_Create)
                if (e.EventClass == EventClassType.Process)
                {
                    ProcessEvent = true;
                    if ( e.Operation == EventFileSystemOperation.VolumeMount)
                    {
                        // 1) Privileged Create Process on a file that is itself or in a directory that is mutable by a non-privileged user
                        if (e.Path.ToLower().Contains("\microsoftedgeupdate.exe")
                        {
                            continue;
                        }
                    }
                    else if (e.Operation == EventFileSystemOperation.ReadFile2)
                    {
                        // 2) Privileged Load Library on a file that is itself or in a directory that is mutable by a non-privileged user
                    }
                    else
                    {
                        continue;
                    }
                }


                // We want a "CreateFile" that is either a "NAME NOT FOUND" or a "PATH NOT FOUND".
                //if (e.Operation != EventFileSystemOperation.CreateFile && e.ProcessOperation != EventProcessOperation.Load_Image)
                if (!ProcessEvent)
                {
                    if (e.Operation != EventFileSystemOperation.CreateFile)
                    {
                        continue;
                    }
                    else if (e.Result != EventResult.NAME_NOT_FOUND && e.Result != EventResult.PATH_NOT_FOUND)
                    {
                        continue;
                    }
                    //else if (e.EventClass != EventClassType.File_System && e.EventClass != EventClassType.Process)
                    else if (e.EventClass != EventClassType.File_System)
                    {
                        // If we get here, we have an event that is not a Process or CreateFile event, so we don't care.
                        continue;
                    }
                }



                // Only look at processes with higher than normal integrity
                if (e.Process.Integrity == "Low" || e.Process.Integrity == "Medium")
                {
                    continue;
                }

                

                // Exclude any DLLs that are in directories that are known to be writable only by privileged users.
                string p = e.Path.ToLower();
                
                if (!p.EndsWith(".dll".ToLower()) && !p.EndsWith(".exe".ToLower()))
                {
                    continue;
                }
                //TODO: There are a couple of user-writable directories within SystemRoot.
                else if (!RuntimeData.IncludeAllDLLs && (p.StartsWith(Environment.ExpandEnvironmentVariables("%ProgramW6432%").ToLower()) || p.StartsWith(Environment.GetEnvironmentVariable("SystemRoot").ToLower())))
                {
                    continue;
                }

                // Don't add duplicates.
                if (EventsOfInterest.ContainsKey(p))
                {
                    continue;
                }

                EventsOfInterest.Add(p, e);
            } while (true);
            Logger.Info("Found " + String.Format("{0:N0}", EventsOfInterest.Count()) + " events of interest...");
        }
    }
}
