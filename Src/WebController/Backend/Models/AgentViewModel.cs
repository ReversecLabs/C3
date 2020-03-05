using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public abstract class AgentViewModel
    {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong AgentId { get; set; }
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong BuildId { get; set; }
        public string Name { get; set; }
        public ICollection<Channel> Channels { get; set; }
        public ICollection<Peripheral> Peripherals { get; set; }
        public ICollection<Route> Routes { get; set; }
        public string Error { get; set; }
        public bool IsActive { get; set; }
        public int Timestamp { get; set; }

        public bool ShouldSerializeError() => Error != null;

        public AgentViewModel()
        {
        }

        public AgentViewModel(Agent a, string name)
        {
            AgentId = a.AgentId;
            BuildId = a.BuildId;
            Name = name;
            Channels = a.Channels;
            Peripherals = a.Peripherals;
            Routes = a.Routes;
            Error = a.Error;
            IsActive = a.IsActive;
            Timestamp = a.Timestamp;
        }
    }
}
