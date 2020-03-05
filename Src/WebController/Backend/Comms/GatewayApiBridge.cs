using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using FSecure.C3.Comms;
using FSecure.C3.WebController.Models;

namespace FSecure.C3.WebController.Comms
{
    public partial class GatewayConnectionHandler
    {
        private ulong gatewayId;
        private CancellationTokenSource selfCTS;
        private CancellationTokenSource anyCTS;
        private Task SendingTask;
        private Task ReceivingTask;
        private readonly IServiceProvider Services;
        private MessageFramingTcpClient tcpClient;
        CommandQueues commandQueues;

        public GatewayConnectionHandler(MessageFramingTcpClient client, IServiceProvider services, CancellationToken ct)
        {
            tcpClient = client;
            Services = services;
            commandQueues = services.GetRequiredService<CommandQueues>();
            selfCTS = new CancellationTokenSource();
            anyCTS = CancellationTokenSource.CreateLinkedTokenSource(selfCTS.Token, ct);
            ReceivingTask = StartReceivingTask();
            // Sending task is started after correctly receiving first message
        }
    }
}
