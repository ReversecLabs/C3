using FSecure.C3.WebController.Comms;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;

namespace FSecure.C3.WebController.Models
{
    public class RelayBuild: Build
    {
        public JToken StartupCommands { get; set; }
        [NotMapped]
        public ulong ParentGatwayAgentId { get; set; }
    }
}
