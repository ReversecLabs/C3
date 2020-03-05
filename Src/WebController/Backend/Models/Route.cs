using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using System;
namespace FSecure.C3.WebController.Models
{
    public class Route
    {
        [JsonIgnore]
        public ulong AgentId { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong OutgoingInterface { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong DestinationAgent { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong ReceivingInterface { get; set; }

        public bool IsNeighbour { get; set; }

        public bool ShouldSerializeIsNeighbour() => IsNeighbour;
    }
}
