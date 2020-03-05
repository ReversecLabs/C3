using FSecure.C3.WebController.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms.GatewayResponses
{
    public partial class GetCapability
    {
        public ulong id { get; set; }
        [JsonProperty("gateway")]
        public Gateway Gate { get; set; }

        public JToken Relay { get; set; }
        public JToken Connectors { get; set; }
        public JToken Channels { get; set; }
        public JToken Peripherals { get; set; }

        public Models.GatewayBuild GetGatewayBuild()
        {
            return new Models.GatewayBuild
            {
                BuildId = Gate.BuildId,
                PublicKey = Gate.PublicKey,
                BroadcastKey = Gate.BroadcastKey,
                Type = Models.Build.BinaryType.Exe,
                Name = !String.IsNullOrWhiteSpace(Gate.Name) ? Gate.Name : $"{Gate.AgentId:x}",
                Connectors = Connectors,
                Channels = Channels,
                RelayCommands = Relay,
                Commands = Gate.Commands,
                Peripherals = Peripherals,
            };
        }

        public class Gateway
        {
            [JsonConverter(typeof(HexStringJsonConverter))]
            public ulong BuildId { get; set; }

            [JsonConverter(typeof(HexStringJsonConverter))]
            public ulong AgentId { get; set; }

            public string Name { get; set; }

            public byte[] PublicKey { get; set; }
            public byte[] BroadcastKey { get; set; }

            public JToken Commands { get; set; }

        }
    }
}
