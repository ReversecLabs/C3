using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public class Command
    {
        [JsonIgnore]
        public ulong GatewayAgentId { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong? RelayAgentId { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong? InterfaceId { get; set; }
        public string DeviceType { get; set; }
        public ulong Id { get; set; }
        [Required]
        public string Name { get; set; }
        public JToken Data { get; set; }
    }
}
