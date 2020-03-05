using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms.GatewayRequests
{
    public class GatewayRequest
    {
        private static ulong RequestSequenceNumber = 0;

        public ulong SequenceNumber;
        public string MessageType { get; }
        public dynamic MessageData { get; }

        public GatewayRequest(dynamic messageData, bool requireResponse = false)
        {
            SequenceNumber = requireResponse ? ++RequestSequenceNumber : 0;
            MessageData = messageData;
            MessageType = messageData.GetType().Name;
        }
    }
}
