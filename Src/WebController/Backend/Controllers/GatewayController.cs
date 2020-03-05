using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using FSecure.C3.WebController.Models;
using FSecure.C3.WebController.HttpExtentions;
using Microsoft.EntityFrameworkCore;
using FSecure.C3.WebController.Comms;
using FSecure.C3.WebController.LinqExtentions;
using System.IO;
using System.IO.Compression;
using FSecure.C3.WebController.RandomExtentions;

namespace FSecure.C3.WebController.Controllers
{

    [Route("api/[controller]")]
    public class GatewayController : Controller
    {
        private readonly C3WebAPIContext context;

        public GatewayController(C3WebAPIContext c)
        {
            context = c;
        }

        [HttpGet("exe/{architecture}")]
        [Produces("application/octet-stream")]
        public IActionResult GetGatewayExeArchitecture(Build.Architecture architecture, string name, [FromServices] ICustomizer customizer, [FromServices] GatewaysSyncService gss)
        {
            using (var ms = new MemoryStream())
            {
                var rand = new Random();
                var agentId = new HexId(rand.NextU64()).ToString();
                var nameOrAgentId = name ?? agentId;
                using (var zipArchive = new ZipArchive(ms, ZipArchiveMode.Create))
                {
                    var gatewayEntry = zipArchive.CreateEntry($"Gateway{architecture}_{nameOrAgentId}.exe");
                    using (var bw = new BinaryWriter(gatewayEntry.Open()))
                    {
                        bw.Write(customizer.GetGateway(architecture));
                    }

                    var configEntry = zipArchive.CreateEntry("GatewayConfiguration.json");
                    var config = new JObject()
                    {
                        ["BuildId"] = new HexId(rand.NextU16()).ToString(),
                        ["AgentId"] = agentId,
                        ["Name"] = nameOrAgentId,
                        ["API Bridge IP"] = gss.conf.apiBridge.ipAddress.ToString(),
                        ["API Bridge port"] = gss.conf.apiBridge.port,
                    };
                    using (var w = new StreamWriter(configEntry.Open()))
                    {
                        w.Write(config.ToString());
                    }
                }
                return File(ms.ToArray(), "application/zip", $"Gateway_{nameOrAgentId}.zip");
            }
        }

        [HttpGet]
        [Produces("application/json")]
        public IEnumerable<GatewayViewModel> ListGateways(int page = 1, int perPage = 10)
        {
            Response.AddPaginationHeaders(page, perPage, context.Gateways.AsQueryable().Count());
            return context.Gateways
                .Include(g => g.Build)
                .OrderBy(gateway => gateway.AgentId)
                .TakePage(page, perPage)
                .Select(g => new GatewayViewModel(g));
        }

        // GET: api/[controller]/[buildId]
        [HttpGet("{gatewayId}")]
        [Produces("application/json")]
        public ActionResult<GatewayViewModel> GetGateway(HexId gatewayId)
        {
            var gateway = context.Gateways
                    .Include(g => g.Routes)
                    .Include(g => g.Channels)
                    .Include(g => g.Peripherals)
                    .Include(g => g.Connectors)
                    .Include(g => g.Build)
                    .Include(g => g.Relays)
                        .ThenInclude(r => r.Routes)
                    .Include(g => g.Relays)
                        .ThenInclude(r => r.Channels)
                    .Include(g => g.Relays)
                        .ThenInclude(r => r.Peripherals)
                    .Include(g => g.Relays)
                        .ThenInclude(r => r.Build)
                    .FirstOrDefault(g => g.AgentId == gatewayId.Value);

            if (gateway is null)
                return NotFound($"Gateway with id = {gatewayId} not found");

            return new GatewayViewModel(gateway);
        }

        [HttpGet("{gatewayId}/capability")]
        public ActionResult<GatewayCapabilityView> GetGatewayCapability(HexId gatewayId)
        {
            try
            {
                return new GatewayCapabilityView(context.Gateways
                    .Include(g => g.Build)
                    .Single(g => g.AgentId == gatewayId.Value)
                    .Build as GatewayBuild);
            }
            catch (InvalidOperationException e)
            {
                return NotFound($"Gateway with id = {gatewayId} not found. {e.Message}");
            }
        }

        [HttpGet("{gatewayId}/channel")]
        public ActionResult<IEnumerable<Channel>> ListGatewayChannels(HexId gatewayId)
        {
            try
            {
                return context.Gateways
                    .Include(g => g.Channels)
                    .Single(g => g.AgentId == gatewayId.Value)
                    .Channels
                    .ToList();
            }
            catch (InvalidOperationException)
            {
                return NotFound($"Gateway with id = {gatewayId} not found");
            }
        }

        [HttpGet("{gatewayId}/route")]
        public ActionResult<IEnumerable<Route>> ListGatewayRoutes(HexId gatewayId)
        {
            try
            {
                return context.Gateways
                    .Include(g => g.Routes)
                    .Single(g => g.AgentId == gatewayId.Value)
                    .Routes
                    .ToList();
            }
            catch (InvalidOperationException)
            {
                return NotFound($"Gateway with id = {gatewayId} not found");
            }
        }
    }
}
