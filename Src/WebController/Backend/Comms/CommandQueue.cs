using System;
using System.Threading;
using System.Threading.Tasks;
using Nito.AsyncEx;
using FSecure.C3.WebController.Models;
using System.Collections.Concurrent;
using FSecure.C3.WebController.Comms.GatewayRequests;
using FSecure.C3.WebController.Comms.GatewayResponses;
using System.Collections.Generic;

namespace FSecure.C3.WebController.Comms
{
    public class CommandQueues
    {
        public class InvalidGateway : Exception
        {
            public InvalidGateway(string message) : base(message) { }
        }

        private readonly ConcurrentDictionary<ulong, CommandQueue> queues;

        public CommandQueues() => queues = new ConcurrentDictionary<ulong, CommandQueue>();

        public void Enqueue(ulong gatewayId, dynamic request) => Get(gatewayId).Enqueue(new GatewayRequest(request));
        public void Enqueue(ulong gatewayId, GatewayRequest request) => Get(gatewayId).Enqueue(request);

        public Task<GatewayRequest> Dequeue(ulong gatewayId, CancellationToken ct) => Get(gatewayId).Dequeue(ct);

        public async Task<dynamic> GetResponse<T>(ulong gatewayId, T command, int timeoutMilliseconds = -1) => await Get(gatewayId).GetResponse(command, timeoutMilliseconds);

        public void TryPostResponse(ulong gatewayId, GatewayResponse response) => Get(gatewayId).TryPostResponse(response);

        public bool AddGateway(ulong gatewayId) => queues.TryAdd(gatewayId, new CommandQueue());

        public void RemoveGateway(ulong gatewayId) => queues.TryRemove(gatewayId, out _);

        private CommandQueue Get(ulong gatewayId)
        {
            try
            {
                return queues[gatewayId];
            }
            catch (KeyNotFoundException)
            {
                throw new InvalidGateway($"Failed to find Gateway's command queue: {gatewayId}");
            }
        }




        private class CommandQueue
        {
            private readonly AsyncCollection<GatewayRequest> Commands;
            private readonly ConcurrentDictionary<ulong, TaskCompletionSource<dynamic>> PendingRequests;

            public CommandQueue()
            {
                Commands = new AsyncCollection<GatewayRequest>();
                PendingRequests = new ConcurrentDictionary<ulong, TaskCompletionSource<dynamic>>();
            }

            public void Enqueue(GatewayRequest command) => Commands.Add(command);

            public Task<GatewayRequest> Dequeue(CancellationToken ct) => Commands.TakeAsync(ct);

            public async Task<dynamic> GetResponse<RequestT>(RequestT message, int timeoutMilliseconds = -1)
            {
                timeoutMilliseconds = timeoutMilliseconds < 0 ? -1 : timeoutMilliseconds;
                var request = new GatewayRequest(message, true);
                PendingRequests.TryAdd(request.SequenceNumber, new TaskCompletionSource<dynamic>());

                // Get a reference to task before enqueueing to avoid deletion from PendingRequests from another thread
                var task = PendingRequests[request.SequenceNumber].Task;
                Enqueue(request);

                var cts = new CancellationTokenSource();
                if (await Task.WhenAny(task, Task.Delay(timeoutMilliseconds, cts.Token)) != task)
                {
                    // task timeouted
                    PendingRequests.TryRemove(request.SequenceNumber, out _);
                    throw new TimeoutException($"Command {request.SequenceNumber} response timeout");
                }

                // task completed, get rid of timer
                cts.Cancel();
                return await task;
            }

            public void TryPostResponse(GatewayResponse response)
            {
                if (response.SequenceNumber == 0)
                    return;

                try
                {
                    PendingRequests[response.SequenceNumber].SetResult(response.GetMessage()) ;
                }
                catch (KeyNotFoundException)
                {
                    // no such response.SequenceNumber -> probably timeouted and already deleted
                }
                catch (GatewayResponseError e)
                {
                    PendingRequests[response.SequenceNumber].SetException(e) ;
                }
                finally
                {
                    PendingRequests.TryRemove(response.SequenceNumber, out _);
                }
            }
        }
    }
}
