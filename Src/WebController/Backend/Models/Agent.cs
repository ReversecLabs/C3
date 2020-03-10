using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public abstract class Agent
    {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong AgentId { get; set; }
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong BuildId { get; set; }
        [JsonIgnore]
        public Build Build { get; set; }
        public ICollection<Channel> Channels { get; set; }
        public ICollection<Peripheral> Peripherals { get; set; }
        public ICollection<Route> Routes { get; set; }
        public string Error { get; set; }
        public bool IsActive { get; set; }
        public int Timestamp { get; set; }

        public bool ShouldSerializeError() => Error != null;
    }
}
