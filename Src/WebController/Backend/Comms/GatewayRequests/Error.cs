using FSecure.C3.WebController.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms.GatewayRequests
{
    public class Error
    {
        public string Message { get; set; }

        public Error(string message)
        {
            Message = message;
        }
    }
}
