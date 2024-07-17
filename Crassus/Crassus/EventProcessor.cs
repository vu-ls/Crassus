using Crassus.ProcMon;
using Crassus.Properties;
using Crassus.Crassus.CommandLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
        private List<string> libraryExtensionList = new List<string>
        // For missing files that are attempted to be opened, anything in this list will be marked as notable.
        // If we reported all missing files, the false-positive rate would go through the roof.
        // TODO: Maybe there's a comprehensive list of likely to be LoadLibrary'd file extensions
            {
            ".dll",
            ".sys",
            ".xll",
            ".wll",
            ".drv",
            ".cpl",
            ".so",
            ".acm",
            ".ppi",
            };
        private List<string> immutableDirParts = new List<string>();
        private static List<string> pathsWithNoWriteACLs = new List<string>();

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

            // TODO: Only do this if there's reason to
            IdentifySuccessfulEvents(MissingDlls);

            watch.Stop();

            Logger.Info("Checking ACLs of events of interest...");
            //foreach (string PathName in Paths)
            foreach (KeyValuePair<string, PMLEvent> item in EventsOfInterest)
            {
                bool is64bit;
                bool isBadItem = false;
                bool fileLocked = false;
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
                    Logger.Debug("Found path: " + PathName);
                    if (item.Value.EventClass != EventClassType.Process && !item.Value.Path.EndsWith("openssl.cnf") && item.Value.Result != EventResult.NAME_NOT_FOUND)
                    {
                        // This is an access to an existing file that was also existing on boot, so let's not be bothered by non process (load library, start process) events
                        continue;
                    }

                    string LoadedInfo = "";
                    string fileExtension = "";
                    try
                    {
                        fileExtension = Path.GetExtension(PathName.ToLower());
                    }
                    catch
                    {
                        continue;
                    }
                    if (libraryExtensionList.Contains(fileExtension))
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

                    // This is a library or EXE that was actually loaded.
                    // Let's check the privileges of the file and directory to make sure that they're sane.
                    bool Writable = TestIfWritable(PathName);
                    if (Writable && !WritablePaths.Contains(PathName))
                    {
                        WritablePaths.Add(PathName);
                        Logger.Success("We can write to: " + PathName + LoadedInfo);
                        isBadItem = true;
                    }
                    else
                    {
                        if (HasWritePermissionOnPath(PathName))
                        {
                            Logger.Warning("ACLs should allow writing to " + PathName + ", but we cannot. In use maybe?");
                            isBadItem = true;
                            fileLocked = true;
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
                            Logger.Debug("Adding '" + Dir + "' to the list of writable paths.");

                            if ((isBadItem && fileLocked) || (!isBadItem && !fileLocked))
                            {
                                Logger.Success("We can rename: " + Dir + " to allow loading of our own " + PathName + LoadedInfo);
                            }
                            else
                            {
                                // We've already reported a success, so we use "also"
                                Logger.Success("We can also rename: " + Dir + " to allow loading of our own " + PathName + LoadedInfo);
                            }

                            isBadItem = true;
                        }
                    }


                }
                else
                {
                    Logger.Debug("Missing path: " + PathName);
                    // Must be a missing file. We don't know for sure what the program would do with the file, but we can guess.
                    // If it's a DLL, it's *probably* to load it, but that's just a guess.
                    // Let's check the directory ACLs.
                    string LoadedInfo = "";
                    //                    if (PathName.EndsWith(".dll"))
                    //                    string fileExtension = Path.GetExtension(PathName).ToLower();
                    string fileExtension = "";
                    try
                    {
                        fileExtension = Path.GetExtension(PathName.ToLower());
                        //Logger.Info(fileExtension);
                    }
                    catch
                    {
                        //Logger.Warning(PathName);
                        continue;
                    }
                    if (libraryExtensionList.Contains(fileExtension) || fileExtension == ".cnf")
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
                    else if (PathName.EndsWith(".exe"))
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

                    string MissingFileDir = "";
                    string MissingFile = "";
                    try
                    {
                        MissingFileDir = Path.GetDirectoryName(PathName).ToLower();
                        MissingFile = Path.GetFileName(PathName).ToLower(); ;
                    }
                    catch
                    {
                        Logger.Debug("Error parsing " + PathName);
                        continue;
                    }

                    Logger.Debug("Checking if we can write to: " + MissingFileDir);
                    if (!Directory.Exists(MissingFileDir))
                    {
                        Logger.Debug(MissingFileDir + " doesn't even exist!");
                        if (MissingFileDir.StartsWith("c:\\"))
                        {
                            try
                            {
                                Directory.CreateDirectory(MissingFileDir);
                                Logger.Success("We can create the missing " + MissingFileDir + " directory to place " + MissingFile + LoadedInfo);
                                isBadItem = true;
                            }
                            catch
                            {
                                // Carry on...
                            }

                        }
                        else
                        {
                            Logger.Warning("Ability to place the missing " + PathName + " should be investigated." + LoadedInfo);
                            isBadItem = true;
                        }

                    }
                    // It seems that the checking for the write permission check isn't sufficient. So we'll blindly attempt to write to the dir for now.
                    else if (HasWritePermissionOnPath(MissingFileDir) || true)
                    {
                        if (TryWritingToDir(MissingFileDir))
                        // We shouldn't have to do this, but some AV software can do weird things where real-world behavior
                        // doesn't necessarily match up with what the ACLs imply should be possible.
                        {
                            Logger.Success("We can place the missing " + MissingFile + " in " + MissingFileDir + LoadedInfo);
                            isBadItem = true;
                        }

                    }
                }

                if (isBadItem)
                {
                    RuntimeData.FoundBad = true;
                    //EventsOfInterest.Remove(item.Key);
                    Logger.Verbose("Potentially exploitable path access: " + item.Key);
                    ConfirmedEventsOfInterest.Add(item.Key, item.Value);
                }

            }

            if (!RuntimeData.FoundBad)
            {
                Logger.Info("No events seem to be exploitable!");
            }
            else
            {
                if (RuntimeData.Debug)
                {
                    Logger.Debug(String.Format("IdentifySuccessfulEvents() took {0:N0}ms", watch.ElapsedMilliseconds));
                }

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
                }
                catch (Exception e)
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

        public static bool HasWritePermissionOnPath(string path)
        // Loop through the SIDs to see if the current user might be able to write to the specified path
        {
            var writeAllow = false;
            var writeDeny = false;
            if (!pathsWithNoWriteACLs.Contains(path))
            {
                var mySID = WindowsIdentity.GetCurrent().User;
                var mySIDs = WindowsIdentity.GetCurrent().Groups;


                Logger.Debug("Checking if ACLs would allow writing to: " + path);

                System.Security.AccessControl.DirectorySecurity accessControlList;
                try
                {
                    accessControlList = Directory.GetAccessControl(path);
                }
                catch
                {
                    Logger.Debug("Failed to get access control list for " + path);
                    return false;
                }
                if (accessControlList == null)
                {
                    Logger.Debug("Empty access control list for " + path);
                    return false;
                }


                System.Security.AccessControl.AuthorizationRuleCollection accessRules = null;
                try
                {
                    accessRules = accessControlList.GetAccessRules(true, true,
                                              typeof(System.Security.Principal.SecurityIdentifier));
                }
                catch
                {
                    Logger.Debug("Failed to get access rules for " + path);
                    return false;
                }

                if (accessRules == null)
                {
                    Logger.Debug("Empty access access rules for " + path);
                    return false;
                }


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
                                Logger.Debug("SID " + SID + " can write to " + path);
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
                if (!writeAllow || writeDeny)
                {
                    pathsWithNoWriteACLs.Add(path);
                }
            }


            return writeAllow && !writeDeny;
        }

        public static bool TryWritingToDir(string DirName)
        // Attempt to create a file in a specified directory
        {
            Logger.Debug("Attempting to create a file in: " + DirName);
            bool canWrite = false;
            if (Directory.Exists(DirName))
            {
                Logger.Debug(DirName + " already exists...");
                var myUniqueFileName = $@"{Guid.NewGuid()}.txt";
                string FullPath = Path.Combine(DirName, myUniqueFileName);
                //Logger.Info("Trying to create: " + FullPath);
                try
                {
                    StreamWriter stream = File.CreateText(FullPath);
                    stream.Close();
                    try
                    {
                        File.Delete(FullPath);
                    }
                    catch (Exception e)
                    {
                        // We're going to leave a file behind here.  Live with it.
                        Logger.Debug("Failed to delete " + FullPath);
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
                Logger.Debug("Creating directory: " + DirName);
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


        private bool TestIfWritable(string pathname)
        // Try to see if a file path is writable by first simply attempting to open it with write permissions
        // This generally works, except Acronis anti-ransomware software will show that some files are writable
        // by the current user, when they're actually not.  So we fall back to actually writing metadata to a file
        {
            Logger.Debug("Checking to see if " + pathname + " is writable by the current user");
            bool Writable = false;
            try
            {
                // Check if a path is a directory, by checking its attributes
                FileAttributes attr = File.GetAttributes(pathname);
                if (attr.HasFlag(FileAttributes.Directory))
                {
                    //Logger.Info(pathname + " is a directory!");
                }
            }
            catch
            {
                // If we can't get a path's attributes, then there's not much we can do.
            }
            if (File.Exists(pathname))
            {
                try
                {
                    FileSecurity fSecurity = File.GetAccessControl(pathname);
                    FileStream writableFile = File.OpenWrite(pathname);
                    writableFile.Close();

                    // The above should be good enough, but some AV software plays games where file ACLs allow
                    // a file to be opened for writing, but at some level will not allow the modification.
                    // This should be good enough to test actually writing to file metadata, with the same value.
                    DateTime lastAccess = File.GetLastAccessTime(pathname);
                    File.SetLastAccessTime(pathname, lastAccess);
                    Writable = true;
                    ;
                }
                catch
                {
                    // Attempting to open a file with write permissions will throw an error if you won't be able to write to it.
                }
            }

            return Writable;
        }

        private string FindMutableDirPart(string filePath)
        // For any given path, see if it can be renamed, recursing up to the root
        {
            string dirPart = Path.GetDirectoryName(filePath);
            if (dirPart.Length > 3)
            {
                if (!immutableDirParts.Contains(dirPart))
                {


                    Logger.Debug("Checking if " + dirPart + " can be renamed...");
                    try
                    {
                        Directory.Move(dirPart, dirPart + "-test");
                        Directory.Move(dirPart + "-test", dirPart);
                    }
                    catch
                    {
                        immutableDirParts.Add(dirPart);
                        if (dirPart.Length > 3)
                        {
                            dirPart = FindMutableDirPart(dirPart);
                        }
                        else
                        {
                            //Logger.Info("Setting dirPart to empty string!");
                            dirPart = "";
                        }
                    }
                }
                else
                {
                    dirPart = FindMutableDirPart(dirPart);
                }
            }
            else
            {
                dirPart = "";
            }

            if (dirPart.Length > 3)
            {
                Logger.Debug("We can rename " + dirPart);
            }
            return dirPart;
        }

        private string LookForFileIfNeeded(string filePath)
        {
            Logger.Debug("Looking for: " + filePath);
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
                //                if (item.Value.Path.ToLower().EndsWith(".dll"))
                //                string fileExtension = Path.GetExtension(item.Value.Path);
                string fileExtension = "";
                try
                {
                    fileExtension = Path.GetExtension(item.Value.Path.ToLower());
                }
                catch
                {
                    continue;
                }
                if (libraryExtensionList.Contains(fileExtension))
                {
                    if (alreadyProcessed.Contains(Path.GetFileName(item.Value.Path).ToLower()))
                    {
                        continue;
                    }
                    alreadyProcessed.Add(Path.GetFileName(item.Value.Path).ToLower());
                    Logger.Info("Finding " + Path.GetFileName(item.Value.Path), false, true);
                    string saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, Path.GetFileNameWithoutExtension(item.Value.Path) + ".cpp");

                    string actualLocation = "";
                    bool notFound = false;
                    if (item.Value.FoundPath == "")
                    {
                        string fileName = Path.GetFileName(item.Value.Path);
                        string fileMatch = null;
                        if (fileMatch != null)
                        {
                            actualLocation = fileMatch;
                        }
                        else
                        {
                            Logger.Warning(" - No DLL Found", true, false);
                            notFound = true;
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
                    }
                    catch (Exception e)
                    {
                        // Nothing.
                    }

                    //if (exports.Count == 0)
                    //{
                    //    File.Create(saveAs + "-no-exports-found").Dispose();
                    //    Logger.Warning(" - No export functions found", true, false);
                    //    continue;
                    //}

                    //List<string> pragma = new List<string>();
                    //string pragmaTemplate = "#pragma comment(linker,\"/export:{0}=\\\"{1}.{2},@{3}\\\"\")";
                    List<string> functions = new List<string>();
                    string functionsTemplate = "  void {0}() {{}}";
                    //List<string> headerFunctions = new List<string>();
                    //string headerFunctionsTemplate = "ADDAPI int ADDCALL {0}();";
                    List<string> resourceFunctions = new List<string>();
                    string resourceFunctionsTemplate = "{0} @{1}";
                    int steps = exports.Count() / 10;
                    if (steps == 0)
                    {
                        steps = 1;
                    }
                    int counter = 0;
                    foreach (FileExport f in exports)
                    {
                        string ExportName = "";
                        ExportName = f.Name;

                        if (++counter % steps == 0)
                        {
                            Logger.Info(".", false, false);
                        }
                        // Visual Studio:
                        //                       pragma.Add(String.Format(pragmaTemplate, ExportName, actualPathNoExtension.Replace("\\", "\\\\"), ExportName, f.Ordinal));
                        // MinGW
                        if (!ExportName.Contains("?") && !ExportName.Contains("@"))
                        {
                            // TODO: Maybe figured out how to handle mangled exports properly
                            functions.Add(String.Format(functionsTemplate, ExportName));
                            //headerFunctions.Add(String.Format(headerFunctionsTemplate, ExportName));
                            resourceFunctions.Add(String.Format(resourceFunctionsTemplate, ExportName, f.Ordinal));
                        }

                    }

                    //                    string fileContents = RuntimeData.ProxyDllTemplate.Replace("%_PRAGMA_COMMENTS_%", String.Join("\r\n", pragma.ToArray()));
                    string fileContents = RuntimeData.ProxyDllTemplate;
                    if (item.Value.Process.Is64 == 1)
                    {
                        fileContents = fileContents.Replace("//%_BUILD_AS%", "//BUILD_AS_64");
                    }
                    else
                    {
                        fileContents = fileContents.Replace("//%_BUILD_AS%", "//BUILD_AS_32");
                    }
                    fileContents = fileContents.Replace("%_EXPORTS_%", String.Join("\r\n", functions.ToArray()));
                    string baseName = Path.GetFileNameWithoutExtension(saveAs);
                    fileContents = fileContents.Replace("%_BASENAME_%", baseName);
                    baseName = Path.Combine(RuntimeData.ExportsOutputDirectory, baseName);
                    File.WriteAllText(saveAs, fileContents);
                    //saveAs = baseName + ".h";
                    //fileContents = RuntimeData.ProxyDllTemplateHeader.Replace("%_EXPORTS_%", String.Join("\r\n", headerFunctions.ToArray()));
                    //File.WriteAllText(saveAs, fileContents);
                    saveAs = baseName + ".def";
                    fileContents = RuntimeData.ProxyDllTemplateResource.Replace("%_EXPORTS_%", String.Join("\r\n", resourceFunctions.ToArray()));
                    File.WriteAllText(saveAs, fileContents);

                    if (!notFound)
                    {
                        Logger.Success(" OK", true, false);
                    }
                }
                else if (fileExtension == ".cnf")
                {
                    string saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, "openssl.cnf");
                    string fileContents = Resources.ResourceManager.GetString("openssl.cnf");
                    File.WriteAllText(saveAs, fileContents);
                    saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, "calc.cpp");
                    fileContents = RuntimeData.ProxyDllTemplate;
                    //                    fileContents = RuntimeData.ProxyDllTemplate.Replace("%_PRAGMA_COMMENTS_%", "\r\n");
                    fileContents = fileContents.Replace("%_EXPORTS_%", "");
                    fileContents = fileContents.Replace("#include \"%_BASENAME_%.h\"", "");
                    if (item.Value.Process.Is64 == 1)
                    {
                        fileContents = fileContents.Replace("//%_BUILD_AS%", "//BUILD_AS_64");
                    }
                    else
                    {
                        fileContents = fileContents.Replace("//%_BUILD_AS%", "//BUILD_AS_32");
                    }
                    File.WriteAllText(saveAs, fileContents);
                    saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, "calc.def");
                    fileContents = RuntimeData.ProxyDllTemplateResource.Replace("%_EXPORTS_%", "");
                    File.WriteAllText(saveAs, fileContents);
                }
            }
            if (ConfirmedEventsOfInterest.Count > 0)
            {
                // Write out helper scripts for compiling proxy DLLs with MinGW and Visual Studio
                string fileContents = Resources.ResourceManager.GetString("build.sh");
                // make shell script Linux-friendly
                fileContents = fileContents.Replace("\r\n", "\n");
                string saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, "build.sh");
                File.WriteAllText(saveAs, fileContents);
                fileContents = Resources.ResourceManager.GetString("build.bat");
                saveAs = Path.Combine(RuntimeData.ExportsOutputDirectory, "build.bat");
                File.WriteAllText(saveAs, fileContents);
            }
        }

        private void SaveEventsOfInterest()
        {
            Logger.Info("Saving output...");

            using (StreamWriter stream = File.CreateText(RuntimeData.CsvOutputFile))
            {
                stream.WriteLine(string.Format("Process, Parent Image Path, User-controllable Path, Found DLL, Integrity, Command Line"));
                foreach (KeyValuePair<string, PMLEvent> item in ConfirmedEventsOfInterest)
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
            long steps = PMLog.TotalEvents() / 10;
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
                string fileExtension = "";
                try
                {
                    fileExtension = Path.GetExtension(e.Path.ToLower());
                }
                catch
                {
                    continue;
                }
                if (!libraryExtensionList.Contains(fileExtension))
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
                //else if (!MissingDLLs.Contains(name))
                //{
                //    // We found a SUCCESS DLL but it's not one that is vulnerable.
                //    //continue;
                //}

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
            long steps = PMLog.TotalEvents() / 10;
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
                // The logic here is that anything that makes it past any of the "continue" conditions is added to EventsOfInterest
                // For now, we're just looking at EXE and DLL files.


                bool ProcessEvent = false;
                string p = "";
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

                // Check if ProcessName or Path is empty
                if (string.IsNullOrEmpty(e.Process.ProcessName) || string.IsNullOrEmpty(e.Path))
                {
                    continue;
                }

                if (e.Process.ProcessName.ToLower() == "msmpeng.exe" || e.Process.ProcessName.ToLower() == "mbamservice.exe"
                || e.Process.ProcessName.ToLower() == "coreserviceshell.exe" || e.Process.ProcessName.ToLower() == "compattelrunner.exe" && !e.Path.EndsWith("openssl.cnf"))
                {
                    // Windows Defender and any antivirus can do things that look interesting, but are not exploitable
                    // e.g. looking for a non-existing EXE or DLL, but for scanning it, rather than running it.
                    // So we'll just ignore this whole process.
                    continue;
                }

                if (e.Path.ToLower().Contains("\\appdata\\local\\microsoft\\windowsapps\\"))
                {
                    // Self-updating Microsoft Windows store apps are just noise.
                    continue;
                }

                if (e.EventClass == EventClassType.Process)
                {
                    ProcessEvent = true;
                    // Yes, Process_Create and Load_image aren't really FileSystem operations.  But Spartacus wasn't originally designed
                    // with the concept of looking anything other than FileSystem oeprations, so...
                    if (e.Operation == EventFileSystemOperation.Process_Create)
                    {
                        // 1) Privileged Create Process on a file that is itself or in a directory that is mutable by a non-privileged user
                        if (e.Path.ToLower().EndsWith("\\microsoftedgeupdate.exe"))
                        {
                            // This seems to just be noise
                            continue;
                        }
                    }
                    else if (e.Operation == EventFileSystemOperation.Load_Image)
                    {
                        // 2) Privileged Load Library on a file that is itself or in a directory that is mutable by a non-privileged user
                    }
                    else
                    {
                        // A "Process" event, yet neither Load_image or Process_Create.  Let's move on, as we don't care.
                        continue;
                    }
                }


                // We want a "CreateFile" that is either a "NAME NOT FOUND" or a "PATH NOT FOUND".
                else if (e.EventClass == EventClassType.File_System)
                {
                    p = e.Path.ToLower();
                    string fileExtension = "";
                    //Logger.Info("We have a filesystem event: " + p);
                    // We have a FileSystem event
                    if (e.Operation != EventFileSystemOperation.CreateFile)
                    {
                        // Throw out anything other than CreateFile
                        continue;
                    }
                    else if (p.EndsWith("openssl.cnf".ToLower()))
                    {
                        //Logger.Warning(p);
                        // Fine if it exists.  We'll still check it...
                    }
                    else if (e.Result != EventResult.NAME_NOT_FOUND && e.Result != EventResult.PATH_NOT_FOUND)
                    {
                        // We've already got Load_image and Process_Create events. We don't care about existing files
                        continue;
                    }
                    else if (e.Path.ToLower().Contains("}-microsoftedge_") || e.Process.ProcessName.ToLower() == "mpwigstub.exe"
                    || e.Path.ToLower().EndsWith("\\msteamsupdate.exe") || e.Path.ToLower().EndsWith("\\msteams.exe"))
                    {
                        // More noise, apparently.
                        continue;
                    }
                    // By now, we are dealing with the legacy Crassus behavior: Looking for "interesting" things that are missing.
                    // But there are probably more interesting files than DLLs...

                    try
                    {
                        fileExtension = Path.GetExtension(p.ToLower());
                    }
                    catch
                    {
                        continue;
                    }
                    if (!libraryExtensionList.Contains(fileExtension) && !p.EndsWith(".exe".ToLower()) && !p.EndsWith("openssl.cnf".ToLower()))
                    {
                        continue;
                    }
                }
                else // Not a File_System event
                {
                    // Must be something other than FileSystem or Process events.  We don't care.
                    continue;
                }


                // At this point, we have loaded libraries, spawned processes, or missing files
                // Only look at processes with higher than normal integrity
                if (e.Process.Integrity == "Low" || e.Process.Integrity == "Medium")
                {
                    continue;
                }

                p = e.Path.ToLower();

                if (e.Process.ProcessName == "svchost.exe" && p.StartsWith("c:\\systemroot\\") && p.EndsWith(".sys"))
                {
                    // This is an odd one for sure, but doesn't look to be exploitable
                    continue;
                }

                if (e.Process.ProcessName == "csrss.exe")
                {
                    // csrss.exe stuff isn't interesting.
                    continue;
                }

                if (e.Process.ProcessName.ToLower() == "mpsigstub.exe")
                {
                    // Defender update stuff. Ignore.
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
