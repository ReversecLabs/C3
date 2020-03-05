using System;
using System.Linq;
using System.Threading.Tasks;
using FSecure.C3.WebController.Models;

namespace FSecure.C3.WebController.Comms
{
    public class GatewayResponseProcessor
    {
        private readonly C3WebAPIContext DbContext;

        public GatewayResponseProcessor(C3WebAPIContext dbContext) => DbContext = dbContext;

        // Generic version does nothing but prevents RuntimeBinderExceptions
        public async Task ProcessResponse(dynamic ignoreResponse) => await Task.CompletedTask;
        public async Task ProcessResponse(GatewayResponses.GetProfile response) => await UpdateGatewayState(response);
        public async Task ProcessResponse(GatewayResponses.GetCapability response) => await AddGatewayBuild(response);

        public async Task MarkInactive(ulong gatewayAgentId)
        {
            var gateway = DbContext.Gateways.Single(g => g.AgentId == gatewayAgentId);
            gateway.IsActive = false;
            await DbContext.SaveChangesAsync();
        }

        private async Task UpdateGatewayState(Gateway newGatewayState)
        {
            if (newGatewayState is null)
                throw new ArgumentNullException(nameof(newGatewayState));

            using (var transaction = await DbContext.Database.BeginTransactionAsync())
            {
                var oldGatewayState = DbContext.Gateways.Where(g => g.AgentId == newGatewayState.AgentId).FirstOrDefault();
                if (oldGatewayState != null)
                {
                    DbContext.Gateways.Remove(oldGatewayState);
                    // Save to trigger cascading delete on foreign keys
                    await DbContext.SaveChangesAsync();
                }

                DbContext.Gateways.Add(newGatewayState);
                await DbContext.SaveChangesAsync();
                transaction.Commit();
            }
        }

        private async Task AddGatewayBuild(GatewayResponses.GetCapability capability)
        {
            if (capability is null)
                throw new ArgumentNullException(nameof(capability));

            using (var transaction = await DbContext.Database.BeginTransactionAsync())
            {
                var gatewayBuild = capability.GetGatewayBuild();
                var oldGatewayBuild = DbContext.GatewayBuilds.Where(b => b.BuildId == gatewayBuild.BuildId).FirstOrDefault();
                if (oldGatewayBuild != null)
                {
                    DbContext.GatewayBuilds.Remove(oldGatewayBuild);
                    // Save to trigger cascading delete on foreign keys
                    await DbContext.SaveChangesAsync();
                }
                DbContext.GatewayBuilds.Add(gatewayBuild);
                await DbContext.SaveChangesAsync();
                transaction.Commit();
            }
        }
    }
}
