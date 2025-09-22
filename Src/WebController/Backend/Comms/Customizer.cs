using FSecure.C3.WebController.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms
{
    public class Customizer : ICustomizer
    {
        private static readonly byte[] patchBufferMarker = System.Text.Encoding.ASCII.GetBytes("15e3eda3-74c8-43d5-a4a1-e2e039542240");
        private static readonly int defaultPatchBufferSize = 4096;
        private static readonly string defaultPayloadTemplateDir = "Resources/PayloadTemplates";
        private static readonly Dictionary<Build.BinaryType, string> payloadTemplateFiles = new Dictionary<Build.BinaryType, string>
        {
            { Build.BinaryType.Exe, "NodeRelayConsoleExe_{0}.exe"},
            { Build.BinaryType.Dll, "NodeRelayDll_{0}.dll"},
            { Build.BinaryType.Shellcode, "CebuLoader_{0}.dll"},
        };

        private static readonly string gatewayFile = "GatewayConsoleExe_{0}.exe";

        private readonly string PayloadTemplateDir;
        private readonly int PatchBufferSize;
        private readonly bool UseDebugBinaries;
        private readonly bool UseRWDIBinaries;

        private CommandQueues commandQueue;

        public Customizer(IConfiguration configuration, CommandQueues cq)
        {
            commandQueue = cq;
            var customizerConfiguration = configuration.GetSection("Customizer");
            PayloadTemplateDir = customizerConfiguration.GetValue(nameof(PayloadTemplateDir), defaultPayloadTemplateDir);
            PatchBufferSize = customizerConfiguration.GetValue(nameof(PatchBufferSize), defaultPatchBufferSize);
            UseDebugBinaries = customizerConfiguration.GetValue(nameof(UseDebugBinaries), false);
            UseRWDIBinaries = customizerConfiguration.GetValue(nameof(UseRWDIBinaries), false);
        }

        public byte[] GetGateway(Build.Architecture arch)
        {
            var c3FileName = Path.Combine(PayloadTemplateDir, GetGatewayFileName(arch));
            return File.ReadAllBytes(c3FileName);
        }

        /// <summary>
        /// Run customizer
        /// </summary>
        /// <param name="targetType">Target type (dll, exe, reflective)</param>
        /// <param name="architecture">Architecture (x64/x86)</param>
        /// <param name="commands">C3 Node relay API commands to run at startup</param>
        /// <returns>Customized C3 node relay binary</returns>
        public async Task<byte[]> CustomizeNodeRelay(RelayBuild build)
        {
            if (build is null)
                throw new ArgumentNullException(nameof(build));

            var c3FileName = Path.Combine(PayloadTemplateDir, GetRelayFileName(build.Type, build.Arch));
            var bin = File.ReadAllBytes(c3FileName);

            // FIXME support more then one startupCommand
            var newBuildResponse = Utils.Cast<GatewayResponses.NewBuild>(await commandQueue.GetResponse(build.ParentGatwayAgentId, new GatewayRequests.NewBuild(build), timeoutMilliseconds: 5000));
            return ApplyPatch(bin, CreatePatch(build.PublicKey, build.BroadcastKey, (uint)(build.BuildId), newBuildResponse.BinaryCommand));
        }

        static public byte[] CreatePatch(byte[] publicKey, byte[] broadcastKey, UInt32 buildId, byte[] returnChannelCommand)
        {
            var rc4key = new byte[32];
            new Random().NextBytes(rc4key);

            var resources = new List<byte[]>
            {
                BitConverter.GetBytes(buildId),
                publicKey,
                broadcastKey,
                returnChannelCommand,
            };

            var ret = rc4key.AsEnumerable()
                .Concat(BitConverter.GetBytes(resources.Count))
                .Concat(BitConverter.GetBytes(true));

            foreach (var resource in resources)
                ret = ret.Concat(GetPreparedResource(rc4key, resource));

            return ret.ToArray();
        }

        public byte[] ApplyPatch(byte[] binary, byte[] patch)
        {
            if (patch.Length > PatchBufferSize)
                throw new CustomizerError("Patch length is longer then placeholder buffer length");

            var pos = Utils.IndexOf(binary, patchBufferMarker);
            if (pos == -1)
                throw new CustomizerError("Failed to find placeholder position marker in binary template");

            Buffer.BlockCopy(patch, 0, binary, pos, patch.Length);
            Array.Clear(binary, pos + patch.Length, PatchBufferSize - patch.Length);
            return binary;
        }

        private static IEnumerable<byte> GetPreparedResource(byte[] password, byte[] resource)
        {
            var len = resource.Length;
            return BitConverter.GetBytes(len)
                .Concat(RC4.Encrypt(password, resource));
        }

        private string GetRelayFileName(Build.BinaryType binaryType, Build.Architecture arch) =>
            String.Format(payloadTemplateFiles[binaryType], GetBinaryDescription(arch));

        private string GetGatewayFileName(Build.Architecture arch) =>
            String.Format(gatewayFile, GetBinaryDescription(arch));

        private string GetBinaryDescription(Build.Architecture arch)
        {
            string config;
            if (this.UseDebugBinaries)
                config = "d";
            else if (this.UseRWDIBinaries)
                config = "rwdi";
            else
                config = "r";
            var ar = arch == Build.Architecture.X64 ? "64" : "86";
            return $"{config}{ar}";
        }
    }
}
