using Crassus.ProcMon;
using Crassus.Properties;
using Crassus.Crassus.CommandLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using static Crassus.ProcMon.ProcMonConstants;
using static Crassus.Crassus.PEFileExports;

namespace Crassus.Crassus
{
    class EventProcessor
    {
        private readonly ProcMonPML PMLog;

        private Dictionary<string, PMLEvent> EventsOfInterest = new Dictionary<string, PMLEvent>();
        private Dictionary<string, PMLEvent> ConfirmedEventsOfInterest = new Dictionary<string, PMLEvent>();

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
            List<string> MissingDlls = new List<string>();
            List<string> WritablePaths = new List<string>();

            /////////////////////////////////////////////////////////////////////////////
            //  Why separate the path-creation list from the dictionary of items that has both the path and the event?
            foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
            {
                try
                {
                    string name = Path.GetFileName(item.Key).ToLower();
                    //Logger.Info(name);
                    string path = item.Key.ToLower();
                    //Logger.Info(path);
                    if (item.Value.Result == EventResult.NAME_NOT_FOUND || item.Value.Result == EventResult.PATH_NOT_FOUND)
                    {
                        if (!MissingDlls.Contains(name))
                        {
                            MissingDlls.Add(name);
                        }
                    }

                }
                catch (Exception e)
                {
                    //Logger.Error(e.Message);
                }
            }
            Logger.Verbose("Found " + String.Format("{0:N0}", MissingDlls.Count()) + " unique DLLs...");
            //////////////////////////////////////////////////////////////////////////////////


            //Now try to find the actual DLL that was loaded. For example if 'version.dll' was missing, identify
            // the location it was eventually loaded from.
            watch.Restart();

            IdentifySuccessfulEvents(MissingDlls);

            watch.Stop();
            if (RuntimeData.Debug)
            {
                Logger.Debug(String.Format("IdentifySuccessfulEvents() took {0:N0}ms", watch.ElapsedMilliseconds));
            }


            Logger.Info("Checking ACLs of events of interest...");
            bool FoundBad = false;
            //foreach (string PathName in Paths)
            foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
            {
                bool is64bit;
                bool isBadItem = false;
                if (item.Value.Process.Is64 == 1)
                {
                    is64bit = true;
                }
                else
                {
                    is64bit = false;
                }
                string PathName = item.Key.ToLower();
                if (File.Exists(PathName))
                {
                    // Logger.Info(PathName);
                    if (item.Value.EventClass != EventClassType.Process)
                    {
                        // This is an access to an existing file, so let's not be bothered by non process (load library, start process) events
                        continue;
                    }
                    // This is a library or EXE that was actually loaded.
                    // Let's check the privileges of the file and directory to make sure that they're sane.
                    bool Writable = CheckPathACLs(PathName);
                    if (Writable && !WritablePaths.Contains(PathName))
                    {
                        WritablePaths.Add(PathName);
                        Logger.Success("We can write to: " + PathName);
                        FoundBad = true;
                    }
                    else
                    {
                        if (HasWritePermissionOnDir(PathName))
                        {
                            Logger.Warning("ACLs should allow writing to " + PathName + ", but we cannot. In use maybe?");
                            isBadItem = true;
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

                            string LoadedInfo = "";
                            if (PathName.EndsWith(".dll"))
                            {
                                // If it's a DLL, then we should share if it's a 64-bit or a 32-bit process attempting to load the file.
                                if (is64bit)
                                {
                                    LoadedInfo = " (64-bit, " + item.Value.Process.Integrity + " Integrity)";
                                }
                                else
                                {
                                    LoadedInfo = " (32-bit, " + item.Value.Process.Integrity + " Integrity)";
                                }
                            }
                            else
                            {
                                if (is64bit)
                                {
                                    LoadedInfo = " (" + item.Value.Process.Integrity + " Integrity)";
                                }
                                else
                                {
                                    LoadedInfo = " (" + item.Value.Process.Integrity + " Integrity)";
                                }
                            }
                            Logger.Success("We can rename: " + Dir + " to allow loading of our own " + PlantFileName + LoadedInfo);
                            isBadItem = true;
                        }
                    }


                }
                else
                {
                    // Must be a missing file. We don't know for sure what the program would do with the file, but we can guess.
                    // If it's a DLL, it's *probably* to load it, but that's just a guess.
                    // Let's check the directory ACLs.
                    string LoadedInfo = "";
                    if (PathName.EndsWith(".dll"))
                    {
                        // If it's a DLL, then we should share if it's a 64-bit or a 32-bit process attempting to load the file.
                        if (is64bit)
                        {
                            LoadedInfo = " (64-bit, " + item.Value.Process.Integrity + " Integrity)";
                        }
                        else
                        {
                            LoadedInfo = " (32-bit, " + item.Value.Process.Integrity + " Integrity)";
                        }
                    }
                    else if (PathName.EndsWith(".exe") || PathName.EndsWith("openssl.cnf"))
                    {
                        if (is64bit)
                        {
                            LoadedInfo = " (" + item.Value.Process.Integrity + " Integrity)";
                        }
                        else
                        {
                            LoadedInfo = " (" + item.Value.Process.Integrity + " Integrity)";
                        }
                    }
                    if (PathName.EndsWith("openssl.cnf"))
                    {
                        //Logger.Success(PathName);
                    }

                    string MissingFileDir = Path.GetDirectoryName(PathName);
                    string MissingFile = Path.GetFileName(PathName);
                    //Logger.Info("Checking if we can write to: " + MissingFileDir);
                    if (HasWritePermissionOnDir(MissingFileDir))
                    {
                        Logger.Success("ACLs should allow placement of missing " + MissingFile + " in " + MissingFileDir + LoadedInfo);
                        isBadItem = true;
                    }
                    else if (TryWritingToDir(MissingFileDir))
                    {
                        Logger.Success("We should be able to place the missing " + MissingFile + " in " + MissingFileDir + LoadedInfo);
                        isBadItem = true;
                    }
                    else if (!MissingFileDir.StartsWith("c:\\"))
                    {
                        Logger.Warning("Ability to place the missing " + PathName + " should be investigated." + LoadedInfo);
                        isBadItem = true;
                    }

                }
                if (isBadItem)
                {
                    FoundBad = true;
                    //EventsOfInterest.Remove(item.Key);
                    Logger.Verbose("Potentially exploitable path access: " + item.Key);
                    ConfirmedEventsOfInterest.Add(item.Key, item.Value);
                }
                
            }

            if (!FoundBad)
            {
                Logger.Info("No events seem to be exploitable!");
            }
            else
            {
                if (RuntimeData.ExportsOutputDirectory != "")
                {
                    if (!Directory.Exists(RuntimeData.ExportsOutputDirectory))
                    {
                        Directory.CreateDirectory(RuntimeData.ExportsOutputDirectory);
                    }
                    ExtractExportFunctions();
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
//                Logger.Error(e.ToString());
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
                    //Logger.Info("Skipping non-write rule");
                    continue;

                if (rule.AccessControlType == AccessControlType.Allow)
                    foreach (var SID in mySIDs)
                    {
                        if (mySIDs.Contains(rule.IdentityReference))
                        {
//                            Logger.Info("SID " + SID + " can write to this file!");
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

        public static bool TryWritingToDir(string DirName)
        {
            bool canWrite = false;
            if (Directory.Exists(DirName))
            {
                var myUniqueFileName = $@"{Guid.NewGuid()}.txt";
                string FullPath = Path.Combine(DirName, myUniqueFileName);
                //Logger.Info("Trying to create: " + FullPath);
                try
                {
                    StreamWriter stream = File.CreateText(FullPath);
                    stream.Close();
                    try
                    {
                        File.Delete(myUniqueFileName);
                    }
                    catch (Exception e)
                    {
                        // We're going to leave a file behind here.  Live with it.
                    }
                    //Logger.Info("Success!");
                    canWrite = true;
                }
                catch (Exception e)
                {
                    //Logger.Error("Failed");
                }
            }
            else
            {
                try
                {
                    Directory.CreateDirectory(DirName);
                    canWrite = true;
                }
                catch
                {
                    // Nothing
                }
            }
            return canWrite;

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
            // When we get a path it may be either x32 or a x64. As Crassus is x64 we can search in the x32 locations if needed.
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


        public static class SafeWalk
        {
            public static IEnumerable<string> EnumerateFiles(string path, string searchPattern, SearchOption searchOpt)
            {
                try
                {
                    var dirFiles = Enumerable.Empty<string>();
                    if (searchOpt == SearchOption.AllDirectories)
                    {
                        dirFiles = Directory.EnumerateDirectories(path)
                                            .SelectMany(x => EnumerateFiles(x, searchPattern, searchOpt));
                    }
                    return dirFiles.Concat(Directory.EnumerateFiles(path, searchPattern));
                }
                catch (UnauthorizedAccessException ex)
                {
                    return Enumerable.Empty<string>();
                }
            }
        }

        private void ExtractExportFunctions()
        {
            Logger.Info("Extracting DLL export functions...");

            PEFileExports ExportLoader = new PEFileExports();

            List<string> alreadyProcessed = new List<string>();

            foreach (KeyValuePair<string, PMLEvent> item in ConfirmedEventsOfInterest)
            {
                //Logger.Info(item.Value.Path);
                if (item.Value.Path.ToLower().EndsWith(".dll"))
                    {
                    if (alreadyProcessed.Contains(Path.GetFileName(item.Value.Path).ToLower()))
                    {
                        continue;
                    }
                    alreadyProcessed.Add(Path.GetFileName(item.Value.Path).ToLower());
                    Logger.Info("Finding " + Path.GetFileName(item.Value.Path), false, true);
                    string saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, Path.GetFileName(item.Value.Path) + ".cpp");

                    string actualLocation = "";
                    if (item.Value.FoundPath == "")
                    {
                        //File.Create(saveAs + "-file-not-found").Dispose();
                        //Logger.Warning(" - No DLL Found", true, false);
                        string fileName = Path.GetFileName(item.Value.Path);
                        //string[] files = Directory.GetFiles("\\", fileName, SearchOption.AllDirectories);
                        //IEnumerable<string> files = Directory.EnumerateFiles("\\", fileName, SearchOption.AllDirectories);
                        //foreach(string file in files)
                        //{
                        //    //
                        //}
                        //string fileMatch = SafeWalk.EnumerateFiles("C:\\", fileName, SearchOption.AllDirectories).Take(1).SingleOrDefault();
                        string fileMatch = null;
                        if (fileMatch != null)
                        {
                                actualLocation = fileMatch;
                        }
                        else
                        {
                            //Logger.Warning(" - No DLL Found", true, false);
//                            continue;
                        }
                    }
                    else
                    {
                        actualLocation = LookForFileIfNeeded(item.Value.FoundPath);
                    }


                    if (!File.Exists(actualLocation))
                    {
                        //File.Create(saveAs + "-file-not-found").Dispose();
                       // Logger.Warning(" - No DLL Found", true, false);
//                        continue;
                    }

                    string actualPathNoExtension = "";
                    if (actualLocation != "")
                    {
                        actualPathNoExtension = Path.Combine(Path.GetDirectoryName(actualLocation), Path.GetFileNameWithoutExtension(actualLocation));
                    }
                    else
                    {
                       
                    }
                    

                    List<FileExport> exports = new List<FileExport>();
                    try
                    {
                        exports = ExportLoader.Extract(actualLocation);
                    } catch (Exception e)
                    {
                        // Nothing.
                    }

                    //if (exports.Count == 0)
                    //{
                    //    File.Create(saveAs + "-no-exports-found").Dispose();
                    //    Logger.Warning(" - No export functions found", true, false);
                    //    continue;
                    //}

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

                    Logger.Success(" OK", true, false);
                }
            }
        }

        private void SaveEventsOfInterest()
        {
            Logger.Info("Saving output...");

            using (StreamWriter stream = File.CreateText(RuntimeData.CsvOutputFile))
            {
                stream.WriteLine(string.Format("Process, Image Path, Missing DLL, Found DLL, Integrity, Command Line"));
                foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
                {
                    stream.WriteLine(
                        string.Format(
                            "\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\"",
                            item.Value.Process.ProcessName,
                            item.Value.Process.ImagePath,
                            item.Value.Path,
                            item.Value.FoundPath,
                            item.Value.Process.Integrity,
                            item.Value.Process.CommandLine.Replace("\"", "\"\""))
                        );
                }
            }
        }

        private void IdentifySuccessfulEvents(List<string> MissingDLLs)
        {
            if (MissingDLLs.Count() == 0)
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
                else if (!MissingDLLs.Contains(name))
                {
                    // We found a SUCCESS DLL but it's not one that is vulnerable.
                    //continue;
                }

                // Find all events of interest (NAME/PATH NOT FOUND) that use the same DLL.
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

                MissingDLLs.Remove(name);
                if (MissingDLLs.Count == 0)
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

                if (e.Process.ProcessName.ToLower() == "msmpeng.exe" || e.Process.ProcessName.ToLower() == "mbamservice.exe" || e.Process.ProcessName.ToLower() == "coreserviceshell.exe")
                {
                    // Windows Defender and any antivirus can do things that look interesting, but are not exploitable
                    // e.g. looking for a non-existing EXE or DLL, but for scanning it, rather than running it.
                    // So we'll just ignore this whole process.
                    continue;
                }

                if (e.EventClass == EventClassType.Process)
                {
                    ProcessEvent = true;
                    // Yes, Process_Create and Load_image aren't really FileSystem operations.  But Crassus wasn't originally designed
                    // with the concept of looking anything other than FileSystem oeprations, so...
                    if ( e.Operation == EventFileSystemOperation.Process_Create)
                    {
                        // 1) Privileged Create Process on a file that is itself or in a directory that is mutable by a non-privileged user
                        if (e.Path.ToLower().Contains("\\microsoftedgeupdate.exe"))
                        {
                            continue;
                        }
                    }
                    else if (e.Operation == EventFileSystemOperation.Load_Image)
                    {
                        // 2) Privileged Load Library on a file that is itself or in a directory that is mutable by a non-privileged user
                    }
                    else
                    {
                        continue;
                    }
                }


                // We want a "CreateFile" that is either a "NAME NOT FOUND" or a "PATH NOT FOUND".
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

                


                string p = e.Path.ToLower();

                // By now, we are dealing with the legacy Crassus behavior: Looking for "interesting" things that are missing.
                // But there are probably more interesting files than DLLs...
                if (!p.EndsWith(".dll".ToLower()) && !p.EndsWith(".exe".ToLower()) && !p.EndsWith("openssl.cnf".ToLower()))
                {
                    continue;
                }

                if (p.Contains("local\\microsoft\\onedrive\\"))
                {
                    // Windows does things with OneDrive that look to be exploitable, but don't seem to be. Ignore these.
                    continue;
                }

                if (p.Contains("appdata\\local\\microsoft\\windowsapps\\backup"))
                {
                    // This shouldn't be exploitable
                    continue;
                }
                //TODO: There are a couple of user-writable directories within SystemRoot.
                // Exclude any DLLs that are in directories that are known to be writable only by privileged users.
                //else if (!RuntimeData.IncludeAllDLLs && (p.StartsWith(Environment.ExpandEnvironmentVariables("%ProgramW6432%").ToLower()) || p.StartsWith(Environment.GetEnvironmentVariable("SystemRoot").ToLower())))
                //{
                //    continue;
                //}

                    // Don't add duplicates.
                    if (EventsOfInterest.ContainsKey(p))
                {
                    continue;
                }

                EventsOfInterest.Add(p, e);
                Logger.Debug(p);
            } while (true);
            Console.WriteLine("");           
            Logger.Info("Found " + String.Format("{0:N0}", EventsOfInterest.Count()) + " privileged events of interest...");
        }
    }
}
