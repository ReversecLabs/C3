using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Serilog;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Linq;
using FSecure.C3.Comms;
using System.Collections.Generic;

namespace FSecure.C3.WebController.Comms
{
    public class GatewaysSyncService : IHostedService
    {
        private Task ListeningTask;
        Serilog.ILogger locallog;
        private CancellationTokenSource CancellationTokenSource;
        private readonly IServiceProvider Services;
        private MessageFramingTcpListener tcpListener;

        public struct Configuration
        {
            public struct ApiBridge
            {
                internal IPAddress ipAddress;
                internal int port;
            };
            internal ApiBridge apiBridge;

            public Configuration(IConfiguration configuration)
            {
                var host = configuration.GetValue<string>("host");
                if (host == "0.0.0.0")
                {
                    apiBridge.ipAddress = IPAddress.Parse(host);
                }
                else
                {
                    apiBridge.ipAddress = Dns.GetHostAddresses(host)
                        .AsEnumerable()
                        .FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                }
                apiBridge.port = configuration.GetValue<int>("port");
                if (apiBridge.ipAddress is null || apiBridge.port == 0)
                    throw new ArgumentException("API bridge host and port cannot be null");
            }
        };
        public Configuration conf { get; }

        public GatewaysSyncService(IServiceProvider services)
        {
            Services = services;
            conf = new Configuration(services.GetRequiredService<IConfiguration>().GetSection("ApiBridge"));
            CancellationTokenSource = new CancellationTokenSource();
            locallog = Log.ForContext<GatewaysSyncService>();
            Console.WriteLine($"Gateway API bridge starts listening on {conf.apiBridge.ipAddress}:{conf.apiBridge.port}");
            tcpListener = new MessageFramingTcpListener(conf.apiBridge.ipAddress, conf.apiBridge.port);
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            ListeningTask = StartListenigTask(CancellationTokenSource.Token);
            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            CancellationTokenSource.Cancel();
            tcpListener.Dispose();
            if (ListeningTask != null)
            {
                locallog.Information("Gateway sync background task is stopping");
                await ListeningTask;
            }
            CancellationTokenSource.Dispose();
        }

        public async Task StartListenigTask(CancellationToken cancellationToken)
        {
            while(!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var newGatewayConnection = await tcpListener.AcceptAsync();
                    new GatewayConnectionHandler(newGatewayConnection, Services, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // stop requested
                }
                catch (ObjectDisposedException)
                {
                    // Dirty trick to stop tcpListener.AcceptAsync which is not cancellable is to call Stop() so the underlying socket throws ObjectDisposedException in EndAccept
                }
            }
        }
    }
}
