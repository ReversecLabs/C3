using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using FSecure.C3.WebController.Comms;
using FSecure.C3.WebController.HttpExtentions;
using FSecure.C3.WebController.LinqExtentions;
using FSecure.C3.WebController.Models;

namespace FSecure.C3.WebController.Controllers
{
    public class CommandControllerHelper
    {
        private readonly C3WebAPIContext context;
        private readonly CommandQueues commandQueues;

        public CommandControllerHelper(C3WebAPIContext c, CommandQueues queues)
        {
            context = c;
            commandQueues = queues;
        }

        public IQueryable<Command> ListCommands(HexId gatewayId, ulong? relayId = null, ulong? interfaceId = null, bool all = false)
        {
            var commands = context.Commands.Where(c => c.GatewayAgentId == gatewayId.Value);

            if (relayId != null || !all)
                commands = commands.Where(c => c.RelayAgentId == relayId);

            if (interfaceId != null || !all)
                commands = commands.Where(c => c.InterfaceId == relayId);

            return commands;
        }

        public Command Get(ulong commandId, HexId gatewayId, ulong? relayId = null, ulong? interfaceId = null)
        {
            return context.Commands
                .Where(c => c.GatewayAgentId == gatewayId.Value)
                .Where(c => c.RelayAgentId == relayId)
                .Where(c => c.InterfaceId == interfaceId)
                .Where(c => c.Id == commandId)
                .FirstOrDefault();
        }

        public async Task AddGatewayCommand(Command command, HexId gatewayId)
        {
            await AddCommand(command, gatewayId);
        }

        public async Task AddRelayCommand(Command command, HexId gatewayId, HexId relayId)
        {
            await AddCommand(command, gatewayId, relayId);
        }

        public async Task AddGatewayDeviceCommand(Command command, HexId gatwayId, HexId deviceId, string deviceType)
        {
            await AddCommand(command, gatwayId, deviceId: deviceId, deviceType: deviceType);
        }

        public async Task AddRelayDeviceCommand(Command command, HexId gatewayId, HexId relayId, HexId deviceId, string deviceType)
        {
            await AddCommand(command, gatewayId, relayId: relayId, deviceId: deviceId, deviceType: deviceType);
        }

        private async Task AddCommand(Command command, HexId gatewayId, HexId relayId = null, HexId deviceId = null, string deviceType = null)
        {
            if (deviceId != null && deviceType is null)
                throw new NullReferenceException("Got DeviceId without device type");

            command.GatewayAgentId = gatewayId.Value;
            command.RelayAgentId = relayId?.Value;
            command.InterfaceId = deviceId?.Value;
            command.DeviceType = deviceType;
            context.Add(command);
            using (var transaction = await context.Database.BeginTransactionAsync())
            {
                // save changes to force command.Id generation
                context.SaveChanges();
                commandQueues.Enqueue(gatewayId.Value, new Models.Action(command));
                // commit only if enqueue doesn't throw
                transaction.Commit();
            }
        }
    }
}
