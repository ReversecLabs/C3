using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Extensions.DependencyInjection;
using FSecure.C3.WebController.Comms.GatewayResponses;
using Newtonsoft.Json;

namespace FSecure.C3.WebController.Comms
{
    public partial class GatewayConnectionHandler
    {
        private Tuple<byte[], byte[]> SessionKeys;

        private class InvalidMessage : Exception
        {
            public InvalidMessage(string errorMessage) : base(errorMessage) { }

            public InvalidMessage(string errorMessage, Exception innerException) : base(errorMessage, innerException) { }
        };

        private async Task StartReceivingTask()
        {
            try
            {
                var cancellationToken = anyCTS.Token;

                await ExchangeKeys(cancellationToken);
                await ProcessInitialMessage(cancellationToken);
                while (true)
                {
                    await ProcessMessages(cancellationToken);
                }
            }
            catch (InvalidMessage e)
            {
                Console.WriteLine($"Invalid initial message, aborting connection. {e.Message}");
            }
            catch (CommandQueues.InvalidGateway e)
            {
                await SendRequest(new GatewayRequests.GatewayRequest(new GatewayRequests.Error(e.Message)));
            }
            catch (Exception e)
            when (e is OperationCanceledException || e is System.IO.IOException)
            {
                // Task canceled, stopping
            }
            catch (Exception e)
            {
                Console.WriteLine($"Unknown exception. Aborting connection. {e.Message}");
            }

            selfCTS.Cancel();
            if (SendingTask != null)
                await SendingTask;
            selfCTS.Dispose();
            anyCTS.Dispose();
            await CloseConnection();
            Console.WriteLine("Gateway receiving background task stopped.");
        }

        private async Task ExchangeKeys(CancellationToken cancellationToken)
        {
            using (var keys = Crypto.KeyExchange.GenerateKeyPair())
            {
                var clientPublicKey = await tcpClient.ReceiveAsync(cancellationToken);
                if (clientPublicKey.Length != Crypto.KeyExchange.KeyBytes)
                    throw new InvalidMessage("Received invalid key");

                SessionKeys = Crypto.KeyExchange.GenerateServerSessionKeys(keys, clientPublicKey);
                await tcpClient.SendAsync(keys.PublicKey);
            }
        }


        private async Task ProcessInitialMessage(CancellationToken cancellationToken)
        {
            var rawResponse = await ReceiveMessage(cancellationToken);
            // Parse response, dispatch

            GatewayResponse response = ParseResponse(rawResponse);
            if (response.MessageType.ToLower() != "getcapability")
                throw new InvalidMessage("First message is not GetCapability");
            await BeginConnection(response);
        }

        private async Task ProcessMessages(CancellationToken cancellationToken)
        {
            try
            {
                var rawResponse = await ReceiveMessage(cancellationToken);

                // Parse response, dispatch
                var response = ParseResponse(rawResponse);
                await ProcessResponse(response);
            }
            catch (TypeLoadException e)
            {
                Console.WriteLine($"Received invlid or unrecognized message type: {e.TypeName}");
            }
            catch (InvalidMessage e)
            {
                Console.WriteLine($"Received invlid or unrecognized message: {e.Message}");
            }
            catch (Microsoft.EntityFrameworkCore.DbUpdateException e)
            {
                Console.WriteLine($"Failed to process message. [{e.GetType().Name}]: {e.InnerException.Message}");
            }
        }

        private async Task<byte[]> ReceiveMessage(CancellationToken ct)
        {
            var message = await tcpClient.ReceiveAsync(ct);
            return Crypto.KeyExchange.Decrypt(message, SessionKeys.Item1);
        }

        private GatewayResponses.GatewayResponse ParseResponse(byte[] responseData)
        {
            var message = System.Text.Encoding.ASCII.GetString(responseData);
            try
            {
                return JsonConvert.DeserializeObject<GatewayResponses.GatewayResponse>(message);
            }
            catch (JsonException e)
            {
                throw new InvalidMessage("Failed to deserialize message", e);
            }
        }

        private async Task BeginConnection(GatewayResponses.GatewayResponse response)
        {
            gatewayId = response.GetMessage().Gate.AgentId;
            if (!commandQueues.AddGateway(gatewayId))
                throw new CommandQueues.InvalidGateway($"Gateway [ID: {gatewayId}] already connected");
            SendingTask = StartSendingTask();
            await ProcessResponse(response);
        }

        private async Task CloseConnection()
        {
            using (var serviceScope = Services.CreateScope())
            {
                var responseProcessor = serviceScope.ServiceProvider.GetRequiredService<GatewayResponseProcessor>();
                await responseProcessor.MarkInactive(gatewayId);
            }
        }

        private async Task ProcessResponse(GatewayResponse response)
        {
            try
            {
                using (var serviceScope = Services.CreateScope())
                {
                    {
                        var commandQueues = serviceScope.ServiceProvider.GetRequiredService<CommandQueues>();
                        commandQueues.TryPostResponse(gatewayId, response);
                    }
                    if (!response.HasError())
                    {
                        var responseProcessor = serviceScope.ServiceProvider.GetRequiredService<GatewayResponseProcessor>();
                        await responseProcessor.ProcessResponse(response.GetMessage());
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Unknown exception during message processing. {e.Message}");
            }
        }
    }
}
