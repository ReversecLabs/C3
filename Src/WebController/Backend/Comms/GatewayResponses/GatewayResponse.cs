using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms.GatewayResponses
{
    public class GatewayResponseError : Exception
    {
        public GatewayResponseError(string errorMessage) : base(errorMessage) { }

        public GatewayResponseError(string errorMessage, Exception innerException) : base(errorMessage, innerException) { }
    };

    public class GatewayResponse
    {
        public string MessageType { get; set; }
        public ulong SequenceNumber { get; set; }
        public JToken MessageData { get; set; }
        public JToken Error { get; set; }

        public bool HasError() => Error != null;

        public dynamic GetMessage()
        {
            if (HasError())
                throw new GatewayResponseError(Error.ToString());

            var messageType = Utils.GetType(typeof(GatewayResponse).Namespace, MessageType);
            return MessageData.ToObject(messageType);
        }
    }
}
