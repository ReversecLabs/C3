using MWR.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using static MWR.C3.WebController.Models.Build;

namespace MWR.C3.WebController.Models
{
    public class RelayBuildRequest
    {
        [JsonConverter(typeof(StringEnumConverter))]
        public BinaryType Type { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public Architecture Architecture { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ParentGatewayBuildId { get; set; }

        public string Name { get; set; }

        public JArray StartupCommands { get; set; }

        public DonutRequest Donut { get; set; }
    }

    public class DonutRequest
    {
        public DonutRequest()
        {
            format = DonutLibrary.OutputFormat.BINARY;
            compress = DonutLibrary.ComperssionEngine.NONE;
            entropy = DonutLibrary.EntropyLevel.DEFAULT;
            exitOpt = DonutLibrary.ExitOpt.EXIT_THREAD;
            bypass = DonutLibrary.AmsiWldpBypass.NONE;
        }

        [JsonConverter(typeof(StringEnumConverter))]
        public DonutLibrary.OutputFormat format { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public DonutLibrary.ComperssionEngine compress { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public DonutLibrary.EntropyLevel entropy { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public DonutLibrary.ExitOpt exitOpt { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public DonutLibrary.AmsiWldpBypass bypass { get; set; }
    }
}
