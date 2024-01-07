using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Crassus.Crassus
{
    internal class PEFileExports
    {
        /*
         * Don't try and make sense of this file
         * The PE Header read functionality was butchered to only obtain the relevant information.
         */
        private const int SIZEOF_IMAGE_DOS_HEADER = 64;
        private const int SIZEOF_IMAGE_FILE_HEADER = 20;
        private const int SIZEOF_IMAGE_NT_HEADERS32 = 248;
        private const int SIZEOF_IMAGE_NT_HEADERS64 = 264;
        private const int SIZEOF_IMAGE_EXPORT_DIRECTORY = 40;
        private const int SIZEOF_IMAGE_SECTION_HEADER = 40;

        private FileStream stream;
        private BinaryReader reader;

        private struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions; // RVA from base of image
            public uint AddressOfNames; // RVA from base of image
            public uint AddressOfNameOrdinals; // RVA from base of image
        }

        public struct FileExport
        {
            public string Name;
            public short Ordinal;
        }

        public List<FileExport> Extract(string dllPath)
        {
            List<FileExport> exports = new List<FileExport>();

            stream = File.Open(dllPath, FileMode.Open, FileAccess.Read);
            reader = new BinaryReader(stream, Encoding.ASCII, false);

            int newExecutableHeader = GetNewExecutableHeader();
            bool x32 = Is32bit(newExecutableHeader);
            int NumberOfSections = GetNumberOfSections(newExecutableHeader);
            uint VirtualAddress = GetVirtualAddress(newExecutableHeader, x32);
            int SectionOffset = GetSectionOffset(newExecutableHeader, x32, NumberOfSections, VirtualAddress);
            int ExportOffset = (int)(VirtualAddress - SectionOffset);
            IMAGE_EXPORT_DIRECTORY ExportTable = GetImageExportDirectory(ExportOffset);
            string[] Functions = GetFunctionNames(ExportTable, SectionOffset);
            short[] Ordinals = GetOrdinals(ExportTable, SectionOffset);

            for (int i = 0; i < Functions.Length; i++)
            {
                exports.Add(new FileExport { Name = Functions[i], Ordinal = Ordinals[i] });
            }

            reader.Close();
            stream.Close();

            return exports;
        }

        private int GetNewExecutableHeader()
        {
            // Get the file address of the new executable header - https://www.pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
            _ = stream.Seek(SIZEOF_IMAGE_DOS_HEADER - 4, SeekOrigin.Begin);
            return reader.ReadInt32();
        }

        private bool Is32bit(int newExecutableHeader)
        {
            // Get the architecture - https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
            _ = stream.Seek(newExecutableHeader + 4, SeekOrigin.Begin);
            return reader.ReadUInt16() == 0x014c;   // IMAGE_FILE_MACHINE_I386
        }

        private ushort GetNumberOfSections(int newExecutableHeader)
        {
            _ = stream.Seek(newExecutableHeader, SeekOrigin.Begin);
            _ = reader.ReadUInt32();    // Signature.
            _ = reader.ReadUInt16();    // Machine.
            return reader.ReadUInt16();
        }

        private uint GetVirtualAddress(int newExecutableHeader, bool is32bit)
        {
            // Get the virtual address - IMAGE_NT_HEADERS32.IMAGE_OPTIONAL_HEADER32.IMAGE_DATA_DIRECTORY.VirtualAddress
            _ = stream.Seek(newExecutableHeader + 4 + SIZEOF_IMAGE_FILE_HEADER, SeekOrigin.Begin);
            // 9 UInt16, 2 Bytes, 19 UInt32             - IMAGE_OPTIONAL_HEADER32
            // 9 UInt16, 2 Bytes, 13 UInt32, 5 UInt64   - IMAGE_OPTIONAL_HEADER64
            int skipBytesDependingOnMachine = is32bit ? ((2 * 9) + (2 * 1) + (19 * 4)) : ((2 * 9) + (2 * 1) + (13 * 4) + (5 * 8));
            _ = stream.Seek(skipBytesDependingOnMachine, SeekOrigin.Current);
            return reader.ReadUInt32();
        }

        private int GetSectionOffset(int newExecutableHeader, bool is32bit, int NumberOfSections, uint VirtualAddress)
        {
            int sectionOffset = 0;
            int sectionHeaderOffset = newExecutableHeader + (is32bit ? SIZEOF_IMAGE_NT_HEADERS32 : SIZEOF_IMAGE_NT_HEADERS64);
            for (int i = 0; i < NumberOfSections; i++)
            {
                _ = stream.Seek(sectionHeaderOffset, SeekOrigin.Begin);
                _ = reader.ReadBytes(8);    // char[] * 8
                uint sectionImageVirtualSize = reader.ReadUInt32();
                uint sectionImageVirtualAddress = reader.ReadUInt32();
                _ = reader.ReadUInt32();    // SizeOfRawData
                uint sectionImagePointerToRawData = reader.ReadUInt32();

                if (VirtualAddress > sectionImageVirtualAddress && VirtualAddress < (sectionImageVirtualAddress + sectionImageVirtualSize))
                {
                    sectionOffset = (int)(sectionImageVirtualAddress - sectionImagePointerToRawData);
                    break;
                }

                sectionHeaderOffset += SIZEOF_IMAGE_SECTION_HEADER;
            }
            return sectionOffset;
        }

        private IMAGE_EXPORT_DIRECTORY GetImageExportDirectory(int ExportOffset)
        {
            _ = stream.Seek(ExportOffset, SeekOrigin.Begin);
            IMAGE_EXPORT_DIRECTORY exportTable = new IMAGE_EXPORT_DIRECTORY
            {
                Characteristics = reader.ReadUInt32(),
                TimeDateStamp = reader.ReadUInt32(),
                MajorVersion = reader.ReadUInt16(),
                MinorVersion = reader.ReadUInt16(),
                Name = reader.ReadUInt32(),
                Base = reader.ReadUInt32(),
                NumberOfFunctions = reader.ReadUInt32(),
                NumberOfNames = reader.ReadUInt32(),
                AddressOfFunctions = reader.ReadUInt32(),
                AddressOfNames = reader.ReadUInt32(),
                AddressOfNameOrdinals = reader.ReadUInt32()
            };
            return exportTable;
        }

        private string[] GetFunctionNames(IMAGE_EXPORT_DIRECTORY ExportTable, int SectionOffset)
        {
            int addressOfNamesOffset = (int)(ExportTable.AddressOfNames - SectionOffset);
            string[] Functions = new string[ExportTable.NumberOfNames];

            for (int i = 0; i < ExportTable.NumberOfNames; i++)
            {
                _ = stream.Seek(addressOfNamesOffset, SeekOrigin.Begin);
                int nameOffset = reader.ReadInt32() - SectionOffset;

                _ = stream.Seek(nameOffset, SeekOrigin.Begin);
                Functions[i] = "";
                byte c;
                do
                {
                    c = reader.ReadByte();
                    Functions[i] += Encoding.ASCII.GetString(new byte[] { c });
                } while (c != 0x00);
                Functions[i] = Functions[i].Trim('\0');
                addressOfNamesOffset += 4;
            }

            return Functions;
        }

        private short[] GetOrdinals(IMAGE_EXPORT_DIRECTORY ExportTable, int SectionOffset)
        {
            int ordinalOffset = (int)(ExportTable.AddressOfNameOrdinals - SectionOffset);
            short[] ordinals = new short[ExportTable.NumberOfNames];
            _ = stream.Seek(ordinalOffset, SeekOrigin.Begin);
            for (int i = 0; i < ExportTable.NumberOfNames; i++)
            {
                ordinals[i] = (short)(reader.ReadInt16() + ExportTable.Base);
            }

            return ordinals;
        }
    }
}
