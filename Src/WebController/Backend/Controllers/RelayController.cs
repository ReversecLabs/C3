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
        public ActionResult<RelayViewModel> GetRelay([FromRoute]HexId gatewayId, [FromRoute]HexId relayId)
        {
            try
            {
                var relay = context.Relays
                    .Include(r => r.Channels)
                    .Include(r => r.Peripherals)
                    .Include(r => r.Routes)
                    .Where(r => r.GatewayAgentId == gatewayId.Value)
                    .Single(r => r.AgentId == relayId.Value);
                return new RelayViewModel(relay, context.Notes.FirstOrDefault(n => n.AgentId == relay.AgentId));
            }
            catch (InvalidOperationException)
            {
                return NotFound();
            }
        }

        [HttpPut("{relayId}")]
        [Produces("application/json")]
        public async Task<ActionResult> AddNote([FromRoute] HexId gatewayId, [FromRoute] HexId relayId, string name, string description)
        {
            try
            {
                if (context.Relays.Where(r => r.GatewayAgentId == gatewayId.Value).Count(r => r.AgentId == relayId.Value) != 1)
                    throw new InvalidOperationException();

                var note = context.Notes.FirstOrDefault(n => n.AgentId == relayId.Value);
                if (note != null)
                {
                    if (name != null)
                       note.DisplayName = name;
                    if (description != null)
                       note.Description= description;
                }
                else
                {
                    note = new Note
                    {
                        AgentId = relayId.Value,
                        DisplayName = name,
                        Description = description,
                    };
                    context.Add(note);
                }
                await context.SaveChangesAsync();
                return Ok();
            }
            catch (InvalidOperationException)
            {
                return NotFound();
            }
        }
    }
}