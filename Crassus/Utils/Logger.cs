using System;
using System.IO;
using System.Reflection;

namespace Crassus
{
    internal static class Logger
    {
        public static bool IsVerbose { get; set; }

        public static bool IsDebug { get; set; }

        public static string ConsoleLogFile { get; set; } = string.Empty;

        public static void Verbose(string message, bool newLine = true, bool showTime = true)
        {
            if (!IsVerbose)
            {
                return;
            }

            Write(message, newLine, showTime);
        }

        public static void Debug(string message, bool newLine = true, bool showTime = true)
        {
            if (!IsDebug)
            {
                return;
            }

            Console.ForegroundColor = ConsoleColor.Blue;
            Write("[DEBUG] " + message, newLine, showTime);
            Console.ResetColor();
        }

        public static void Error(string message, bool newLine = true, bool showTime = true)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Write(message, newLine, showTime);
            Console.ResetColor();
        }

        public static void Info(string message, bool newLine = true, bool showTime = true)
        {
            Write(message, newLine, showTime);
        }

        public static void Warning(string message, bool newLine = true, bool showTime = true)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Write(message, newLine, showTime);
            Console.ResetColor();
        }

        public static void Success(string message, bool newLine = true, bool showTime = true)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Write(message, newLine, showTime);
            Console.ResetColor();
        }

        internal static string FormatString(string message)
        {
            return $"[{DateTime.Now:HH:mm:ss}] {message}";
        }

        internal static void Write(string message, bool newLine = true, bool showTime = true)
        {
            message = showTime ? FormatString(message) : message;
            message += newLine ? Environment.NewLine : "";
            Console.Write(message);
            WriteToLogFile(message);
        }

        internal static void WriteToLogFile(string message)
        {
            // Write to file too.
            if (ConsoleLogFile?.Length == 0)
            {
                ConsoleLogFile = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\Crassus.log";
                if (!File.Exists(ConsoleLogFile))
                {
                    File.Create(ConsoleLogFile).Dispose();
                }
            }

            using (StreamWriter w = File.AppendText(ConsoleLogFile))
            {
                w.Write(message);
            }
        }
    }
}
