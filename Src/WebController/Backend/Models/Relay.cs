using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public class Relay : Agent
    {
        [JsonIgnore]
        public ulong GatewayAgentId { get; set; }
        public HostInfo HostInfo { get; set; }

    }
}
