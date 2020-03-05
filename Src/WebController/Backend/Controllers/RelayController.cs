using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using FSecure.C3.WebController.Models;
using Serilog;
using Serilog.AspNetCore;
using FSecure.C3.WebController.HttpExtentions;
using FSecure.C3.WebController.LinqExtentions;
using Microsoft.EntityFrameworkCore;

namespace FSecure.C3.WebController.Controllers
{

    [Route("api/gateway/{gatewayId}/[controller]")]
    public class RelayController : Controller
    {
        C3WebAPIContext context;

        public RelayController(C3WebAPIContext c)
        {
            context = c;
        }

        [HttpGet]
        [Produces("application/json")]
        public IEnumerable<Relay> ListRelays([FromRoute]HexId gatewayId, int page = 1, int perPage = 10)
        {
            var relays = context.Relays
                .Where(relay => relay.GatewayAgentId == gatewayId.Value)
                .OrderBy(relay => relay.AgentId);
            Response.AddPaginationHeaders(page, perPage, relays.Count());
            return relays.TakePage(page, perPage);
        }

        // GET: api/gateway/{gatewayId}/relay/{relayId}]
        [HttpGet("{relayId}")]
        [Produces("application/json")]
        public ActionResult<Relay> GetRelay([FromRoute]HexId gatewayId, [FromRoute]HexId relayId)
        {
            try
            {
                return context.Relays
                    .Include(r => r.Channels)
                    .Include(r => r.Peripherals)
                    .Include(r => r.Routes)
                    .Where(r => r.GatewayAgentId == gatewayId.Value)
                    .Single(r => r.AgentId == relayId.Value);
            }
            catch (InvalidOperationException)
            {
                return NotFound();
            }
        }
    }
}