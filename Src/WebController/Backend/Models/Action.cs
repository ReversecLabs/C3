using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public class Action
    {
        public ulong CommandSeqNo { get;}
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong? relayAgentId { get;}
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong? channelId { get;}
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong? connectorId { get;}
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong? peripheralId { get;}
        [JsonProperty("Command")]
        public JToken CommandData { get;}

        public Action(Models.Command command)
        {
            CommandSeqNo = command.Id;
            relayAgentId = command.RelayAgentId;
            CommandData = command.Data;

            switch (command.DeviceType?.ToLower())
            {
                case null:
                    break;
                case "channel":
                    channelId = command.InterfaceId;
                    break;
                case "peripheral":
                    peripheralId = command.InterfaceId;
                    break;
                case "connector":
                    connectorId = command.InterfaceId;
                    break;
                default:
                    throw new ArgumentException("Unknown device type");
            }
        }
    }
}
