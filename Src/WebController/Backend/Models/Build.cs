using MWR.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace MWR.C3.WebController.Models
{
    public abstract class Build
    {
        public enum BinaryType
        {
            Exe,
            Dll,
            Shellcode,
        }

        public enum Architecture
        {
            X86 = 0,
            X64 = 1,
        }

        [JsonConverter(typeof(StringEnumConverter))]
        public BinaryType Type { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty("architecture")]
        public Architecture Arch { get; set; }

        public byte[] PublicKey { get; set; }

        public byte[] BroadcastKey { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong BuildId { get; set; }

        public JToken Commands { get; set; }
        public JToken Peripherals { get; set; }
        public JToken Channels { get; set; }

        public string Name { get; set; }
    }
}
