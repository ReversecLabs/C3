using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using FSecure.C3.WebController.Comms.GatewayRequests;
using FSecure.C3.WebController.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FSecure.C3.WebController.Comms
{
    public partial class GatewayConnectionHandler
    {
        private async Task StartSendingTask()
        {
            try
            {
                while (true)
                {
                    var request = await commandQueues.Dequeue(gatewayId, anyCTS.Token);
                    await SendRequest(request);
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine($"Connection error {e.Message}");
            }
            catch (TaskCanceledException)
            {
                // Task canceled, stopping
            }
            commandQueues.RemoveGateway(gatewayId);
            selfCTS.Cancel();
            Console.WriteLine("Gateway sending background task stopped.");
        }

        public async Task SendRequest(GatewayRequest action)
        {
            await EncryptAndSend(System.Text.Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(action)));
        }

        public async Task EncryptAndSend(byte[] data)
        {
            var cipher = Crypto.KeyExchange.Encrypt(data, SessionKeys.Item2);
            await tcpClient.SendAsync(cipher);
        }
    }
}
