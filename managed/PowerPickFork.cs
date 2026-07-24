using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PowerPickFork
{
    internal static class Program
    {
        private const int OperatorTimeoutMilliseconds = 180 * 1000;
        private const int OperatorOutputCharacters = 256 * 1024;
        private const int OperatorMaximumBytes = 2 * 1024 * 1024;
        private const uint MapMagic = 0x4B464650; /* 'PFFK' */
        private const int SlotMax = 160;
        private const int MaxImports = 32;
        private const int MailslotChunkBytes = 4096;

        private const uint GenericWrite = 0x40000000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        // FileStream refuses \\.\ device paths (mailslots). Open via CreateFile.
        private static FileStream OpenMailslotWrite(string slotPath)
        {
            SafeFileHandle handle = CreateFile(
                slotPath,
                GenericWrite,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero);
            if (handle == null || handle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                throw new IOException(
                    String.Format(
                        "CreateFile mailslot failed (err={0}): {1}",
                        error,
                        slotPath));
            }

            return new FileStream(handle, FileAccess.Write);
        }

        [ThreadStatic]
        private static Stream OutputStream;

        private sealed class SlotTextWriter : TextWriter
        {
            public override Encoding Encoding
            {
                get { return Encoding.UTF8; }
            }

            public override void Write(char value)
            {
                SlotWrite(value.ToString());
            }

            public override void Write(string value)
            {
                if (value != null)
                {
                    SlotWrite(value);
                }
            }

            public override void Write(char[] buffer, int index, int count)
            {
                if (buffer != null && count > 0)
                {
                    SlotWrite(new string(buffer, index, count));
                }
            }
        }

        private static void SlotWrite(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return;
            }

            Stream stream = OutputStream;
            if (stream == null)
            {
                Console.Write(value);
                return;
            }

            byte[] data = Encoding.UTF8.GetBytes(value);
            int offset = 0;
            while (offset < data.Length)
            {
                int n = Math.Min(MailslotChunkBytes, data.Length - offset);
                stream.Write(data, offset, n);
                stream.Flush();
                offset += n;
            }
        }

        private static void SlotWriteLine(string value)
        {
            if (value == null)
            {
                value = String.Empty;
            }
            SlotWrite(value);
            if (value.Length == 0 ||
                (value[value.Length - 1] != '\n' && value[value.Length - 1] != '\r'))
            {
                SlotWrite("\n");
            }
        }

        private static void WriteBounded(
            string value,
            ref int remainingCharacters,
            ref bool truncationReported,
            int outputLimit)
        {
            if (String.IsNullOrEmpty(value))
            {
                return;
            }

            if (remainingCharacters <= 0)
            {
                if (!truncationReported)
                {
                    SlotWriteLine(
                        String.Format(
                            "[output truncated at {0} characters]",
                            outputLimit));
                    truncationReported = true;
                }
                return;
            }

            bool truncated = value.Length > remainingCharacters;
            string bounded = truncated
                ? value.Substring(0, remainingCharacters)
                : value;

            SlotWriteLine(bounded);

            remainingCharacters -= bounded.Length;
            if (truncated && !truncationReported)
            {
                SlotWriteLine(
                    String.Format(
                        "[output truncated at {0} characters]",
                        outputLimit));
                truncationReported = true;
            }
        }

        private static int InvokeBounded(
            PowerShell powerShell,
            int timeoutMilliseconds,
            int outputCharacters)
        {
            IAsyncResult pending = powerShell.BeginInvoke();
            if (!pending.AsyncWaitHandle.WaitOne(timeoutMilliseconds))
            {
                powerShell.Stop();
                SlotWriteLine(
                    String.Format(
                        "PowerShell execution exceeded the {0}-second limit.",
                        timeoutMilliseconds / 1000));
                return 124;
            }

            PSDataCollection<PSObject> results = powerShell.EndInvoke(pending);
            int remainingCharacters = outputCharacters;
            bool truncationReported = false;
            int written = 0;

            foreach (PSObject result in results)
            {
                if (result != null)
                {
                    string text = result.ToString();
                    if (!String.IsNullOrEmpty(text))
                    {
                        WriteBounded(
                            text,
                            ref remainingCharacters,
                            ref truncationReported,
                            outputCharacters);
                        written++;
                    }
                }
            }

            foreach (ErrorRecord error in powerShell.Streams.Error)
            {
                WriteBounded(
                    error.ToString(),
                    ref remainingCharacters,
                    ref truncationReported,
                    outputCharacters);
                written++;
            }

            foreach (WarningRecord warning in powerShell.Streams.Warning)
            {
                WriteBounded(
                    warning.ToString(),
                    ref remainingCharacters,
                    ref truncationReported,
                    outputCharacters);
                written++;
            }

            foreach (VerboseRecord verbose in powerShell.Streams.Verbose)
            {
                WriteBounded(
                    verbose.ToString(),
                    ref remainingCharacters,
                    ref truncationReported,
                    outputCharacters);
                written++;
            }

            return powerShell.Streams.Error.Count > 0 ? 1 : 0;
        }

        private static bool TryDecodeScript(
            string encodedScript,
            int maximumBytes,
            out string scriptText,
            out string error)
        {
            scriptText = null;
            error = null;

            byte[] scriptBytes;
            try
            {
                scriptBytes = Convert.FromBase64String(encodedScript);
            }
            catch (FormatException)
            {
                error = "The script transport is not valid Base64.";
                return false;
            }

            if (scriptBytes.Length == 0 || scriptBytes.Length > maximumBytes)
            {
                error = String.Format(
                    "The script must be between 1 byte and {0} bytes.",
                    maximumBytes);
                return false;
            }

            scriptText = Encoding.UTF8.GetString(scriptBytes);
            if (scriptText.IndexOf('\0') >= 0)
            {
                error = "The script contains an invalid NUL character.";
                return false;
            }

            return true;
        }

        private static bool ReadExact(Stream stream, byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(buffer, offset, count - offset);
                if (read <= 0)
                {
                    return false;
                }
                offset += read;
            }
            return true;
        }

        private static int ImportScriptText(
            Runspace runspace,
            string scriptText,
            int timeoutMilliseconds,
            int outputCharacters)
        {
            using (PowerShell powerShell = PowerShell.Create())
            {
                powerShell.Runspace = runspace;
                powerShell.AddScript(scriptText, false);
                return InvokeBounded(
                    powerShell,
                    timeoutMilliseconds,
                    outputCharacters);
            }
        }

        private static int RunOperatorScriptTexts(
            string commandText,
            List<string> importTexts)
        {
            if (importTexts == null)
            {
                importTexts = new List<string>();
            }

            int totalBytes = Encoding.UTF8.GetByteCount(commandText);
            for (int index = 0; index < importTexts.Count; index++)
            {
                totalBytes += Encoding.UTF8.GetByteCount(importTexts[index]);
                if (totalBytes > OperatorMaximumBytes)
                {
                    SlotWriteLine(
                        String.Format(
                            "Session imports plus command exceed the {0}-byte limit.",
                            OperatorMaximumBytes));
                    return 2;
                }
            }

            using (Runspace runspace = RunspaceFactory.CreateRunspace())
            {
                runspace.Open();

                for (int index = 0; index < importTexts.Count; index++)
                {
                    int importResult = ImportScriptText(
                        runspace,
                        importTexts[index],
                        OperatorTimeoutMilliseconds,
                        OperatorOutputCharacters);
                    if (importResult != 0)
                    {
                        SlotWriteLine(
                            String.Format(
                                "Session import {0} failed.",
                                index + 1));
                        return importResult;
                    }
                }

                using (PowerShell powerShell = PowerShell.Create())
                {
                    powerShell.Runspace = runspace;
                    // Prefer capturing native-exe stdout as text in-process.
                    powerShell.AddScript(
                        commandText + " | Out-String -Width 4096",
                        false);
                    return InvokeBounded(
                        powerShell,
                        OperatorTimeoutMilliseconds,
                        OperatorOutputCharacters);
                }
            }
        }

        private static int RunOperatorScript(string encodedCommand)
        {
            string commandText;
            string commandError;
            if (!TryDecodeScript(
                    encodedCommand,
                    OperatorMaximumBytes,
                    out commandText,
                    out commandError))
            {
                SlotWriteLine(commandError);
                return 2;
            }

            return RunOperatorScriptTexts(commandText, null);
        }

        private static string SlotPathFromBytes(byte[] slot)
        {
            int length = 0;
            while (length < slot.Length && slot[length] != 0)
            {
                length++;
            }
            return Encoding.ASCII.GetString(slot, 0, length);
        }

        /*
         * Map layout (same as native BOF/host):
         *   magic(4) slot(160) asmLen(4) asm[asmLen]
         *   argsLen(4) args[argsLen]  // "exec <b64>"
         *   importCount(4)
         *   repeat: len(4) utf8[len]
         */
        private static int RunFromMap(string mapName)
        {
            if (String.IsNullOrEmpty(mapName))
            {
                Console.Error.WriteLine("Import map name is empty.");
                return 2;
            }

            mapName = mapName.Trim();

            try
            {
                using (MemoryMappedFile map = MemoryMappedFile.OpenExisting(mapName))
                using (MemoryMappedViewStream stream = map.CreateViewStream())
                {
                    byte[] magicBytes = new byte[4];
                    if (!ReadExact(stream, magicBytes, 4))
                    {
                        Console.Error.WriteLine("Map ended before magic.");
                        return 2;
                    }

                    uint magic = BitConverter.ToUInt32(magicBytes, 0);
                    if (magic != MapMagic)
                    {
                        Console.Error.WriteLine("Map magic mismatch.");
                        return 2;
                    }

                    byte[] slot = new byte[SlotMax];
                    if (!ReadExact(stream, slot, SlotMax))
                    {
                        Console.Error.WriteLine("Map ended before slot path.");
                        return 2;
                    }

                    string slotPath = SlotPathFromBytes(slot);
                    if (String.IsNullOrEmpty(slotPath))
                    {
                        Console.Error.WriteLine("Map slot path is empty.");
                        return 2;
                    }

                    byte[] asmLenBytes = new byte[4];
                    if (!ReadExact(stream, asmLenBytes, 4))
                    {
                        Console.Error.WriteLine("Map ended before asm length.");
                        return 2;
                    }

                    int asmLen = BitConverter.ToInt32(asmLenBytes, 0);
                    if (asmLen < 0 || asmLen > 64 * 1024 * 1024)
                    {
                        Console.Error.WriteLine("Map asm length invalid.");
                        return 2;
                    }

                    if (asmLen > 0)
                    {
                        byte[] skip = new byte[Math.Min(asmLen, 65536)];
                        int remaining = asmLen;
                        while (remaining > 0)
                        {
                            int chunk = Math.Min(remaining, skip.Length);
                            if (!ReadExact(stream, skip, chunk))
                            {
                                Console.Error.WriteLine("Map ended in asm blob.");
                                return 2;
                            }
                            remaining -= chunk;
                        }
                    }

                    byte[] argsLenBytes = new byte[4];
                    if (!ReadExact(stream, argsLenBytes, 4))
                    {
                        Console.Error.WriteLine("Map ended before args length.");
                        return 2;
                    }

                    int argsLen = BitConverter.ToInt32(argsLenBytes, 0);
                    if (argsLen <= 0 || argsLen > OperatorMaximumBytes)
                    {
                        Console.Error.WriteLine("Map args length invalid.");
                        return 2;
                    }

                    byte[] argsBytes = new byte[argsLen];
                    if (!ReadExact(stream, argsBytes, argsLen))
                    {
                        Console.Error.WriteLine("Map ended in args blob.");
                        return 2;
                    }

                    string args = Encoding.UTF8.GetString(argsBytes);
                    if (!args.StartsWith("exec ", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.Error.WriteLine("Map args must start with 'exec '.");
                        return 2;
                    }

                    string afterExec = args.Substring(5).TrimStart();
                    int space = afterExec.IndexOf(' ');
                    string encodedCommand = space < 0
                        ? afterExec
                        : afterExec.Substring(0, space);

                    byte[] countBytes = new byte[4];
                    if (!ReadExact(stream, countBytes, 4))
                    {
                        Console.Error.WriteLine("Map ended before import count.");
                        return 2;
                    }

                    int importCount = BitConverter.ToInt32(countBytes, 0);
                    if (importCount < 0 || importCount > MaxImports)
                    {
                        Console.Error.WriteLine("Map import count invalid.");
                        return 2;
                    }

                    List<string> imports = new List<string>();
                    for (int index = 0; index < importCount; index++)
                    {
                        byte[] lenBytes = new byte[4];
                        if (!ReadExact(stream, lenBytes, 4))
                        {
                            Console.Error.WriteLine("Map ended before import length.");
                            return 2;
                        }

                        int length = BitConverter.ToInt32(lenBytes, 0);
                        if (length <= 0 || length > OperatorMaximumBytes)
                        {
                            Console.Error.WriteLine(
                                "Import {0} has an invalid length.",
                                index + 1);
                            return 2;
                        }

                        byte[] data = new byte[length];
                        if (!ReadExact(stream, data, length))
                        {
                            Console.Error.WriteLine(
                                "Map ended in import {0}.",
                                index + 1);
                            return 2;
                        }

                        string text = Encoding.UTF8.GetString(data);
                        if (text.IndexOf('\0') >= 0)
                        {
                            Console.Error.WriteLine(
                                "Import {0} contains an invalid NUL.",
                                index + 1);
                            return 2;
                        }

                        imports.Add(text);
                    }

                    string commandText;
                    string commandError;
                    if (!TryDecodeScript(
                            encodedCommand,
                            OperatorMaximumBytes,
                            out commandText,
                            out commandError))
                    {
                        // Best-effort: still try to open the slot for the error.
                        try
                        {
                            using (FileStream slotStream = OpenMailslotWrite(slotPath))
                            {
                                OutputStream = slotStream;
                                SlotWriteLine(commandError);
                            }
                        }
                        catch
                        {
                            Console.Error.WriteLine(commandError);
                        }
                        finally
                        {
                            OutputStream = null;
                        }
                        return 2;
                    }

                    using (FileStream slotStream = OpenMailslotWrite(slotPath))
                    {
                        OutputStream = slotStream;
                        TextWriter previousOut = Console.Out;
                        TextWriter previousErr = Console.Error;
                        try
                        {
                            TextWriter slotWriter = new SlotTextWriter();
                            Console.SetOut(slotWriter);
                            Console.SetError(slotWriter);

                            return RunOperatorScriptTexts(commandText, imports);
                        }
                        finally
                        {
                            Console.SetOut(previousOut);
                            Console.SetError(previousErr);
                            OutputStream = null;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    "Failed to run from map '{0}': {1}",
                    mapName,
                    exception.Message);
                return 2;
            }
        }

        public static int Main(string[] args)
        {
            try
            {
                if (args == null ||
                    args.Length < 2 ||
                    !String.Equals(args[0], "exec", StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine(
                        "Usage: PowerPickFork.exe exec <base64-script>");
                    return 2;
                }

                return RunOperatorScript(args[1]);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(
                    "PowerShell host failed: {0}: {1}",
                    exception.GetType().FullName,
                    exception.Message);
                return 1;
            }
        }

        // Called via ICLRRuntimeHost.ExecuteInDefaultAppDomain.
        // Argument is the payload map name (Local\...).
        public static int ForkExec(string mapName)
        {
            try
            {
                return RunFromMap(mapName);
            }
            catch (Exception exception)
            {
                try
                {
                    SlotWriteLine(
                        String.Format(
                            "PowerShell host failed: {0}: {1}",
                            exception.GetType().FullName,
                            exception.Message));
                }
                catch
                {
                    Console.Error.WriteLine(
                        "PowerShell host failed: {0}: {1}",
                        exception.GetType().FullName,
                        exception.Message);
                }
                return 1;
            }
        }
    }
}
