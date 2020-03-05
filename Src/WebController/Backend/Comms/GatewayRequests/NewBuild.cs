using FSecure.C3.WebController.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms.GatewayRequests
{
    public class NewBuild
    {
        public ulong BuildId { get; set; }
        public JToken Command { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public Build.Architecture Arch { get; set; }

        public NewBuild(RelayBuild relayBuild)
        {
            BuildId = relayBuild.BuildId;
            Command = relayBuild.StartupCommands[0].ToObject<Command>().Data;
            Arch = relayBuild.Arch;
        }

        public NewBuild(ulong buildId, JToken command)
        {
            BuildId = buildId;
            Command = command;
        }
    }
}
