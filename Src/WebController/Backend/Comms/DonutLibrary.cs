using System;
using System.Runtime.InteropServices;

// https://github.com/TheWover/donut/blob/master/lib/donut.h

namespace FSecure.C3.WebController.Comms
{
    public class DonutLibrary
    {
        public enum ErrorCode
        {
            SUCCESS = 0,
            FILE_NOT_FOUND = 1,
            FILE_EMPTY = 2,
            FILE_ACCESS = 3,
            FILE_INVALID = 4,
            NET_PARAMS = 5,
            NO_MEMORY = 6,
            INVALID_ARCH = 7,
            INVALID_URL = 8,
            URL_LENGTH = 9,
            INVALID_PARAMETER = 10,
            RANDOM = 11,
            DLL_FUNCTION = 12,
            ARCH_MISMATCH = 13,
            DLL_PARAM = 14,
            BYPASS_INVALID = 15,
            NORELOC = 16,
            INVALID_ENCODING = 17,
            INVALID_ENGINE = 18,
            COMPRESSION = 19,
            INVALID_ENTROPY = 20,
            MIXED_ASSEMBLY = 21,
        }

        // target architecture
        public enum Architecture
        {
            ANY = -1,  // just for vbs,js and xsl files
            X86 = 1,  // x86
            X64 = 2,  // AMD64
            X84 = 3,  // AMD64 + x86
        }

        // module type
        public enum ModuleType
        {
            NET_DLL = 1,  // .NET DLL. Requires class and method
            NET_EXE = 2,  // .NET EXE. Executes Main if no class and method provided
            DLL = 3,  // Unmanaged DLL, function is optional
            EXE = 4,  // Unmanaged EXE
            VBS = 5,  // VBScript
            JS = 6,  // JavaScript or JScript
        }

        // format type
        public enum OutputFormat
        {
            BINARY = 1,
            BASE64 = 2,
            RUBY = 3,
            C = 4,
            PYTHON = 5,
            POWERSHELL = 6,
            CSHARP = 7,
            HEX = 8,
        }

        // compression engine
        public enum ComperssionEngine
        {
            NONE = 1,
            APLIB = 2,
            LZNT1 = 3,  // COMPRESSION_FORMAT_LZNT1
            XPRESS = 4,  // COMPRESSION_FORMAT_XPRESS
            XPRESS_HUFF = 5,  // COMPRESSION_FORMAT_XPRESS_HUFF
        }

        // entropy level
        public enum EntropyLevel
        {
            NONE = 1,  // don't use any entropy
            RANDOM = 2,  // use random names
            DEFAULT = 3,  // use random names + symmetric encryption
        }

        // misc options
        public enum ExitOpt
        {
            EXIT_THREAD = 1,  // return to the caller which calls RtlExitUserThread
            EXIT_PROCESS = 2,  // call RtlExitUserProcess to terminate host process
        }
        // instance type
        public enum InstanceType
        {
            PIC = 1,  // Self-contained
            URL = 2,  // Download from remote server
        }

        // AMSI/WLDP options
        public enum AmsiWldpBypass
        {
            NONE = 1,  // Disables bypassing AMSI/WDLP
            ABORT = 2,  // If bypassing AMSI/WLDP fails, the loader stops running
            CONTINUE = 3,  // If bypassing AMSI/WLDP fails, the loader continues running
        }

        public static class Constants
        {
            public const int DONUT_MAX_NAME = 256;  // maximum length of string for domain, class, method and parameter names
            public const int DONUT_MAX_DLL = 8;  // maximum number of DLL supported by instance
            public const int DONUT_MAX_URL = 256;
            public const int DONUT_MAX_MODNAME = 8;
            public const int DONUT_SIG_LEN = 8;  // 64-bit string to verify decryption ok
            public const int DONUT_VER_LEN = 32;
            public const int DONUT_DOMAIN_LEN = 8;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct DonutConfig
        {
            public uint len, zlen;                // original length of input file and compressed length

            // general / misc options for loader
            public int arch;
            public int bypass;
            public int compress;                 // engine to use when compressing file via RtlCompressBuffer
            public int entropy;                  // entropy/encryption level
            public int format;                   // output format for loader
            public int exit_opt;                 // return to caller or invoke RtlExitUserProcess to terminate the host process
            public int thread;                   // run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API
            public ulong oep;                     // original entrypoint of target host file

            // files in/out
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string input;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string output;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]

            // .NET stuff
            public string runtime;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string domain;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string cls;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string method;

            // command line for DLL/EXE
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string param;                 // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
            public int unicode;                  // param is converted to UNICODE before being passed to DLL function

            // HTTP staging information
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string url;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = Constants.DONUT_MAX_NAME)]
            public string modname;

            // DONUT_MODULE
            public int mod_type;
            public int mod_len;
            public IntPtr mod;                   // points to DONUT_MODULE

            // DONUT_INSTANCE
            public int inst_type;                // DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL
            public int inst_len;                 // size of DONUT_INSTANCE
            public IntPtr inst;                  // points to DONUT_INSTNCE

            // shellcode generated from configuration
            public int pic_len;                  // size of loader/shellcode
            public IntPtr pic;                   // points to loader/shellcode
        }

        public static byte[] GenerateShellcode(DonutConfig config)
        {
            var buffer = DonutCreate(config);
            DonutDelete(config);
            return buffer;
        }

        // Use DllImport to import the Win32 MessageBox function.
        [DllImport("donut")]
        private static extern int DonutCreate(ref DonutConfig donutConfig);

        public class DonutException : Exception
        {
            public DonutException(string message) : base(message) { }
        }

        [DllImport("donut")]
        private static extern int DonutDelete(ref DonutConfig donutConfig);

        [DllImport("donut")]
        private static extern IntPtr DonutError(int errorcode);

        static string GetDonutError(ErrorCode errorcode)
        {
            IntPtr ptr = DonutError((int)errorcode);
            return Marshal.PtrToStringAnsi(ptr);
        }

        private static byte[] DonutCreate(DonutConfig config)
        {
            var createErrorCode = (ErrorCode)DonutCreate(ref config);
            if (createErrorCode != ErrorCode.SUCCESS)
            {
                var errorMessage = GetDonutError(createErrorCode);
                throw new DonutException($"Donut error: {errorMessage}");
            }
            var buffer = new byte[config.pic_len];
            Marshal.Copy(config.pic, buffer, 0, config.pic_len);
            return buffer;
        }

        private static void DonutDelete(DonutConfig config)
        {
            var delErrorCode = (ErrorCode)DonutDelete(ref config);
            if (delErrorCode != ErrorCode.SUCCESS)
            {
                var errorMessage = GetDonutError(delErrorCode);
                throw new DonutException($"Donut error: {errorMessage}");
            }
        }
    }
}
