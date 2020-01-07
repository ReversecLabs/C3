using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Options;
using MWR.C3.WebController.Models;
using MWR.C3.WebController.RandomExtentions;

namespace MWR.C3.WebController.Comms
{
    public class DonutService : IDonutService
    {
        public DonutService(IOptions<DonutServiceOptions> options)
        {
            m_Options = options.Value;
            m_TempPath = options.Value.Tempdir ??
                Environment.GetEnvironmentVariable("TEMPDIR") ??
                Environment.GetEnvironmentVariable("TEMP") ??
                ".";
        }

        private DonutServiceOptions m_Options;
        private string m_TempPath;

        public byte[] GenerateShellcode(byte[] payload, DonutRequest request, Build.Architecture arch)
        {
            // donut api requires files
            var rand = new Random();
            var tmpFilename = rand.NextString(16);
            var tmpPayloadFile = Path.Combine(m_TempPath, tmpFilename + ".dll");
            var tmpDonutFile = Path.Combine(m_TempPath, tmpFilename + ".donut");

            WriteToFile(payload, tmpPayloadFile);

            var config = new DonutLibrary.DonutConfig
            {
                arch = (int)(arch == Build.Architecture.X64 ? DonutLibrary.Architecture.X64 : DonutLibrary.Architecture.X86),
                mod_type = (int)(DonutLibrary.ModuleType.DLL),
                format = (int)request.format,
                compress = (int)request.compress,
                entropy = (int)request.entropy,
                inst_type = (int)DonutLibrary.InstanceType.PIC,
                input = tmpPayloadFile,
                output = tmpDonutFile,
                bypass = (int)request.bypass,
                inst_len = 0
            };

            try
            {
                DonutLibrary.GenerateShellcode(config);
                return File.ReadAllBytes(tmpDonutFile);
            }
            finally
            {
                CleanupFile(tmpPayloadFile);
                CleanupFile(tmpDonutFile);
            }
        }

        private static void WriteToFile(byte[] payload, string filename)
        {
            using (var binWriter = new BinaryWriter(File.Open(filename, FileMode.Create)))
            {
                binWriter.Write(payload);
            }
        }

        private static void CleanupFile(string filename)
        {
            if (File.Exists(filename))
                File.Delete(filename);
        }
    }
}
