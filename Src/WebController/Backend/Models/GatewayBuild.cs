using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace FSecure.C3.WebController.Models
{
    public class GatewayBuild: Build
    {
        public JToken Connectors { get; set; }
        public JToken RelayCommands { get; set; }
    }
}
