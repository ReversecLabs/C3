using Newtonsoft.Json;
using System;
using FSecure.C3.WebController.Comms;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations.Schema;

namespace FSecure.C3.WebController.Models
{
    public class Channel
    {
        [JsonIgnore]
        public ulong AgentId { get; set; }

        [JsonConverter(typeof(HexStringJsonConverter))]
        [JsonProperty("iid")]
        public ulong InterfaceId { get; set; }

        [JsonProperty("type")]
        public ulong Hash { get; set; }
        public string Error { get; set; }
        public bool IsReturnChannel { get; set; }
        public bool IsNegotiationChannel { get; set; }
        public JToken Jitter { get; set; }

        [NotMapped]
        public JToken PropertiesText
        {
            get
            {
                return new JObject
                {
                    ["arguments"] = this.StartupCommand?.SelectToken("arguments"),
                    ["jitter"] = this.Jitter,
                };
            }
        }

        public JToken StartupCommand { get; set; }
        public bool ShouldSerializeStartupCommand() => false;

        public bool ShouldSerializeIsReturnChannel() => IsReturnChannel;
        public bool ShouldSerializeIsNegotiationChannel() => IsNegotiationChannel;

        public bool ShouldSerializeError() => Error != null;
    }
}
