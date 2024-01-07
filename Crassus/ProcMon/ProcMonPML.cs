﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Crassus.Crassus.Exceptions;
using static Crassus.ProcMon.ProcMonConstants;

namespace Crassus.ProcMon
{
    internal class ProcMonPML : IDisposable
    {
        private readonly string PMLFile = "";

        private FileStream stream = null;

        private BinaryReader reader = null;

        private PMLHeaderStruct LogHeader = new PMLHeaderStruct();

        private string[] LogStrings = new string[0];
        private readonly Dictionary<int, PMLProcessStruct> LogProcesses = new Dictionary<int, PMLProcessStruct>();

        private uint[] LogEventOffsets = new uint[0];

        private uint currentEventIndex = 0;
        private bool disposedValue;

        public ProcMonPML(string pMLFile)
        {
            PMLFile = pMLFile;
            Load();
        }

        public void Rewind()
        {
            currentEventIndex = 0;
        }

        public PMLEvent? GetNextEvent()
        {
            return GetEvent(currentEventIndex++);
        }

        public PMLEvent? GetEvent(uint eventIndex)
        {
            if (eventIndex >= TotalEvents())
            {
                return null;
            }

            int pVoidSize;
            if (LogHeader.Architecture == 1)
            {
                pVoidSize = 8;
            }
            else
            {
                pVoidSize = 4;
            }
            _ = stream.Seek(LogEventOffsets[eventIndex], SeekOrigin.Begin);

            PMLEventStruct logEvent = new PMLEventStruct
            {
                indexProcessEvent = reader.ReadInt32(),
                ThreadId = reader.ReadInt32(),
                EventClass = reader.ReadInt32(),
                OperationType = reader.ReadInt16()
            };

            /*
             * In order to speed up the I/O I'm reading in bulk data that I'm not using further down.
             * By doing so, reading 8 million events drops from 65 to 46 seconds.
             */
            //reader.ReadBytes(6);    // Unknown.
            //logEvent.DurationOfOperation = reader.ReadInt64();
            //reader.ReadInt64(); // FILETIME.
            _ = reader.ReadBytes(6 + 8 + 8);    // Comment this and uncomment the 3 lines above if needed.

            logEvent.Result = reader.ReadUInt32();
            logEvent.CapturedStackTraceDepth = reader.ReadInt16();
            _ = reader.ReadInt16(); // Unknown.
            logEvent.ExtraDetailSize = reader.ReadUInt32();
            logEvent.ExtraDetailOffset = reader.ReadUInt32();

            int sizeOfStackTrace = logEvent.CapturedStackTraceDepth * pVoidSize;

            /* Check the comment about speeding this up from above. */
            //stream.Seek(sizeOfStackTrace, SeekOrigin.Current);
            //stream.Seek(pVoidSize * 5 + 0x14, SeekOrigin.Current);
            //reader.ReadInt32(); // Should be 0

            // This is all silly.  But it's an artifact of how Crassus was originally coded.
            string eventPath = "";
            // In the case of Load Image, we want to seek 72
            if (logEvent.EventClass == 1 && logEvent.OperationType == 5)
            {
                // Load Image (DLL) Procmon event
                _ = stream.Seek(sizeOfStackTrace + pVoidSize + 4, SeekOrigin.Current);
                byte stringSize = reader.ReadByte();
                //                byte stringSize = 40;
                _ = reader.ReadBytes(3); // Not relevant for now.
                eventPath = Encoding.ASCII.GetString(reader.ReadBytes(stringSize));
            }
            else if (logEvent.EventClass == 1 && logEvent.OperationType == 1)
            {
                // Create Process Procmon Event
                _ = stream.Seek(sizeOfStackTrace + 0xc + 0x3d, SeekOrigin.Current);
                byte stringSize = reader.ReadByte();
                // Whoever wrote this code should feel really bad about themselves.
                // The path of a created process is in the string table, rather than as a specified-length ASCII string
                // Doing this hack to avoid figuring out how to work with the string table sure is something.
                stringSize = 255;
                _ = reader.ReadBytes(2); // Not relevant for now.
                // Create Process uses a string table to specify what process is created
                // This is an embarrassing hack, but it was easier than reverse enginerring the PML file format
                // to figure out how to get string table entries precisely.
                eventPath = Encoding.Unicode.GetString(reader.ReadBytes(stringSize));
                Regex regex = new Regex(@".:\\.+?\.exe");
                eventPath = regex.Match(eventPath.ToLower()).Value;
            }
            else if (logEvent.EventClass == 3 && logEvent.OperationType == 20)
            {
                // FileOpen Procmon Event
                _ = stream.Seek(sizeOfStackTrace + ((pVoidSize * 5) + 0x14) + 4, SeekOrigin.Current);
                byte stringSize = reader.ReadByte();  // TODO: For Load Image, this string size returns 0!
                //stringSize = 40;
                _ = reader.ReadBytes(3); // Not relevant for now.
                eventPath = Encoding.ASCII.GetString(reader.ReadBytes(stringSize));
            }

            if (!LogProcesses.TryGetValue(logEvent.indexProcessEvent, out PMLProcessStruct thisProcess))
            {
                Logger.Debug("Cannot determine process for event: " + logEvent.indexProcessEvent);
            }
            else
            {
                thisProcess = new PMLProcessStruct();
            }

            // TODO fix up to be more universal
            return new PMLEvent()
            {
                EventClass = (EventClassType)logEvent.EventClass,
                Operation = (EventFileSystemOperation)logEvent.OperationType,
                Result = (EventResult)logEvent.Result,
                Path = eventPath,
                Process = thisProcess,
                OriginalEvent = logEvent,
                Loaded = true,
                FoundPath = ""
            };
        }

        public uint TotalEvents()
        {
            return LogHeader.TotalEventCount;
        }

        private void Load()
        {
            try
            {
                stream = File.Open(PMLFile, FileMode.Open, FileAccess.Read);
            }
            catch
            {
                Logger.Error("Cannot open " + PMLFile);
                return;
            }
            reader = new BinaryReader(stream, Encoding.Unicode);

            Logger.Debug("Reading event log header...");
            try
            {
                ReadHeader();
            }
            catch
            {
                Logger.Error("Cannot parse PML file!");
                return;
            }
            Logger.Debug("Reading event log strings...");
            ReadStrings();

            Logger.Debug("Reading event log processes...");
            ReadProcesses();

            Logger.Debug("Reading event offsets...");
            ReadEventOffsets();
        }

        private void ReadHeader()
        {
            LogHeader.Signature = Encoding.ASCII.GetString(reader.ReadBytes(4));
            LogHeader.Version = reader.ReadInt32();
            if (LogHeader.Signature != "PML_")
            {
                throw new FileFormatException("Invalid file signature - it should be PML_ but it is: " + LogHeader.Signature);
            }
            else if (LogHeader.Version != 9)
            {
                throw new FileFormatException("Invalid file version: " + LogHeader.Version);
            }

            LogHeader.Architecture = reader.ReadInt32();
            LogHeader.ComputerName = new string(reader.ReadChars(0x10));
            LogHeader.SystemRootPath = new string(reader.ReadChars(0x104));
            LogHeader.TotalEventCount = reader.ReadUInt32();
            _ = reader.ReadInt64(); // Unknown.
            LogHeader.OffsetEventArray = reader.ReadInt64();
            LogHeader.OffsetEventOffsetArray = reader.ReadInt64();
            LogHeader.OffsetProcessArray = reader.ReadInt64();
            LogHeader.OffsetStringArray = reader.ReadInt64();
            LogHeader.OffsetIconArray = reader.ReadInt64();
            _ = reader.ReadBytes(0xC);  // Unknown.
            LogHeader.WindowsVersionMajor = reader.ReadInt32();
            LogHeader.WindowsVersionMinor = reader.ReadInt32();
            LogHeader.WindowsVersionBuild = reader.ReadInt32();
            LogHeader.WindowsVersionRevision = reader.ReadInt32();
            LogHeader.WindowsServicePack = Encoding.Unicode.GetString(reader.ReadBytes(0x32));

            _ = reader.ReadBytes(0xD6); // Unknown.
            LogHeader.LogicalProcessors = reader.ReadInt32();
            LogHeader.RAMSize = reader.ReadInt64();
            LogHeader.OffsetEventArray2 = reader.ReadInt64();
            LogHeader.OffsetHostsPortArray = reader.ReadInt64();
        }

        private void ReadStrings()
        {
            _ = stream.Seek(LogHeader.OffsetStringArray, SeekOrigin.Begin);
            int stringCount = reader.ReadInt32();
            Logger.Verbose("Found " + stringCount + " strings...");

            Logger.Verbose("Reading string offesets...");
            int[] stringOffsets = new int[stringCount];
            for (int i = 0; i < stringOffsets.Length; i++)
            {
                stringOffsets[i] = reader.ReadInt32();
            }

            Logger.Verbose("Reading strings...");
            Array.Resize(ref LogStrings, stringCount);
            for (int i = 0; i < stringOffsets.Length; i++)
            {
                _ = stream.Seek(LogHeader.OffsetStringArray + stringOffsets[i], SeekOrigin.Begin);
                int stringSize = reader.ReadInt32();
                LogStrings[i] = Encoding.Unicode.GetString(reader.ReadBytes(stringSize)).Trim('\0');
            }
        }

        private void ReadProcesses()
        {
            _ = stream.Seek(LogHeader.OffsetProcessArray, SeekOrigin.Begin);
            int processCount = reader.ReadInt32();
            Logger.Verbose("Found " + processCount + " processes...");

            Logger.Verbose("Reading process offsets...");
            // The array of process indexes is not essential becuase they appear in the process structure itself.
            _ = stream.Seek(processCount * 4, SeekOrigin.Current);
            int[] processOffsets = new int[processCount];
            for (int i = 0; i < processOffsets.Length; i++)
            {
                processOffsets[i] = reader.ReadInt32();
            }

            Logger.Verbose("Reading processes...");
            for (int i = 0; i < processOffsets.Length; i++)
            {
                _ = stream.Seek(LogHeader.OffsetProcessArray + processOffsets[i], SeekOrigin.Begin);
                PMLProcessStruct process = new PMLProcessStruct
                {
                    ProcessIndex = reader.ReadInt32(),
                    ProcessId = reader.ReadInt32(),
                    ParentProcessId = reader.ReadInt32()
                };
                _ = reader.ReadInt32();     // Unknown.
                process.AuthenticationId = reader.ReadInt64();
                process.SessionNumber = reader.ReadInt32();
                _ = reader.ReadInt32();     // Unknown.
                _ = reader.ReadInt64();     // Start Process FILETIME.
                _ = reader.ReadInt64();     // End Process FILETIME.
                process.IsVirtualised = reader.ReadInt32();
                process.Is64 = reader.ReadInt32();
                process.indexStringIntegrity = reader.ReadInt32();
                process.indexStringUser = reader.ReadInt32();
                process.indexStringProcessName = reader.ReadInt32();
                process.indexStringImagePath = reader.ReadInt32();
                process.indexStringCommandLine = reader.ReadInt32();
                process.indexStringExecutableCompany = reader.ReadInt32();
                process.indexStringExecutableVersion = reader.ReadInt32();
                process.indexStringExecutableDescription = reader.ReadInt32();

                process.Integrity = LogStrings[process.indexStringIntegrity];
                process.User = LogStrings[process.indexStringUser];
                process.ProcessName = LogStrings[process.indexStringProcessName];
                process.ImagePath = LogStrings[process.indexStringImagePath];
                process.CommandLine = LogStrings[process.indexStringCommandLine];
                process.ExecutableCompany = LogStrings[process.indexStringExecutableCompany];
                process.ExecutableVersion = LogStrings[process.indexStringExecutableVersion];
                process.ExecutableDescription = LogStrings[process.indexStringExecutableDescription];

                LogProcesses.Add(process.ProcessIndex, process);
            }
        }

        private void ReadEventOffsets()
        {
            // Load Events.
            Logger.Verbose("Reading event log offsets...");
            _ = stream.Seek(LogHeader.OffsetEventOffsetArray, SeekOrigin.Begin);
            Array.Resize(ref LogEventOffsets, (int)LogHeader.TotalEventCount);
            for (int i = 0; i < LogEventOffsets.Length; i++)
            {
                LogEventOffsets[i] = reader.ReadUInt32();
                _ = reader.ReadByte();      // Unknown.
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    stream?.Dispose();
                    reader?.Dispose();
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
