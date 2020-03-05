using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FSecure.C3.WebController.Models
{
    public class GatewayCapabilityView
    {
        [JsonConverter(typeof(HexStringJsonConverter))]
        public ulong BuildId { get; set; }

        public JToken Commands { get; set; }
        public JToken Peripherals { get; set; }
        public JToken Channels { get; set; }

        public string Name { get; set; }
        public JToken Connectors { get; set; }
        public JToken RelayCommands { get; set; }

        [JsonProperty("gateway")]
        public JArray GatewayCommandGroup { get; set; }

        [JsonProperty("relay")]
        public JArray RelayCommandGroup { get; set; }

        public JObject ChannelCommands { get; set; }
        public JObject ConnectorCommands { get; set; }
        public JObject PeripheralCommands { get; set; }

        public GatewayCapabilityView(GatewayBuild gb)
        {
            BuildId = gb.BuildId;
            {
                // populate top-level GatewayCommand
                var defaultValues = new JArray();
                foreach (var command in gb.Commands)
                {
                    defaultValues.Add("gateway:Command:" + command["name"].Value<string>());
                }

                Commands = new JArray
                {
                    new JObject
                    {
                        ["name"] = "GatewayCommandGroup",
                        ["arguments"] = new JArray
                        {
                            new JObject
                            {
                                ["type"] = "form",
                                ["name"] = "Gateway",
                                ["defaultValue"] = defaultValues,
                            },
                        },
                    }
                };
            }
            {
                // populate "gateway" list in json
                GatewayCommandGroup = new JArray
                {
                    new JObject
                    {
                        ["name"] = "Command",
                        ["type"] = 0,
                        ["commands"] = gb.Commands,
                    }
                };
            }
            {
                // populate top-level RelayCommand
                var defaultValues = new JArray();
                var newRelayDefaultValues = new JArray();
                foreach (var command in gb.RelayCommands["commands"])
                {
                    var cn = command["name"].Value<string>();
                    defaultValues.Add("relay:Command:" + cn);
                    if (cn.StartsWith("AddChannel") || cn.StartsWith("AddNegotiationChannel"))
                        newRelayDefaultValues.Add("relay:Command:" + cn);
                }

                var argument = new JObject
                {
                    ["type"] = "form",
                    ["name"] = "Relay",
                };
                var newRelayArgument = argument.DeepClone();
                argument["defaultValue"] = defaultValues;
                newRelayArgument["defaultValue"] = newRelayDefaultValues;

                RelayCommands = new JObject
                {
                    ["commands"] = new JArray
                    {
                        new JObject
                        {
                            ["name"] = "RelayCommandGroup",
                            ["arguments"] = new JArray() { argument },
                        },
                        new JObject
                        {
                            ["name"] = "NewRelayCommandGroup",
                            ["arguments"] = new JArray() { newRelayArgument },
                        }
                    },
                };
            }
            {
                // populate "relay" list in json
                RelayCommandGroup = new JArray
                {
                    new JObject
                    {
                        ["name"] = "Command",
                        ["type"] = 0,
                        ["commands"] = gb.RelayCommands["commands"],
                    }
                };
            }
            {
                // set channels
                Channels = gb.Channels;

                // populate channelCommands form
                var defaultValue = new JArray();
                foreach(var channel in Channels)
                    foreach(var command in channel["commands"])
                        defaultValue.Add($"channels:{channel["name"]}:{command["name"]}");

                ChannelCommands = new JObject
                {
                    ["commands"] = new JArray
                    {
                        new JObject
                        {
                            ["name"] = "ChannelCommandGroup",
                            ["arguments"] = new JArray
                            {
                                new JObject
                                {
                                    ["type"] = "form",
                                    ["name"] = "Channel",
                                    ["defaultValue"] = defaultValue,
                                }
                            },
                        }
                    },
                };
            }
            {
                // set peripherials
                Peripherals = gb.Peripherals;

                // populate peripheralCommands form
                var defaultValue = new JArray();
                foreach (var peripheral in Peripherals)
                    foreach (var command in peripheral["commands"])
                        defaultValue.Add($"peripherals:{peripheral["name"]}:{command["name"]}");

                PeripheralCommands = new JObject
                {
                    ["commands"] = new JArray
                    {
                        new JObject
                        {
                            ["name"] = "PeripheralCommandGroup",
                            ["arguments"] = new JArray
                            {
                                new JObject
                                {
                                    ["type"] = "form",
                                    ["name"] = "Peripheral",
                                    ["defaultValue"] = defaultValue,
                                }
                            },
                        }
                    },
                };
            }
            {
                // set connectors
                Connectors = gb.Connectors;

                // populate connectorsCommand form
                var defaultValue = new JArray();
                foreach (var connector in Connectors)
                    foreach (var command in connector["commands"])
                        defaultValue.Add($"connectors:{connector["name"]}:{command["name"]}");

                ConnectorCommands = new JObject
                {
                    ["commands"] = new JArray
                    {
                        new JObject
                        {
                            ["name"] = "PeripheralCommandGroup",
                            ["arguments"] = new JArray
                            {
                                new JObject
                                {
                                    ["type"] = "form",
                                    ["name"] = "Peripheral",
                                    ["defaultValue"] = defaultValue,
                                }
                            },
                        }
                    },
                };
            }
        }
    }
}
