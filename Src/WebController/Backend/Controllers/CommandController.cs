using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using FSecure.C3.WebController.Comms;
using FSecure.C3.WebController.HttpExtentions;
using FSecure.C3.WebController.LinqExtentions;
using FSecure.C3.WebController.Models;

namespace FSecure.C3.WebController.Controllers
{
    [Route("api/gateway/{gatewayId}")]
    public class CommandController : Controller
    {
        private readonly C3WebAPIContext context;
        private readonly CommandControllerHelper helper;

        public CommandController(C3WebAPIContext c, CommandQueues commandQueues)
        {
            context = c;
            helper = new CommandControllerHelper(c, commandQueues);
        }

        [HttpGet("command")]
        [Produces("application/json")]
        public ActionResult<IEnumerable<Command>> ListCommands([FromRoute] HexId gatewayId, int page = 1, int perPage = 10, bool all = false)
        {
            var commands = helper.ListCommands(gatewayId, all: all);
            Response.AddPaginationHeaders(page, perPage, commands.Count());
            return commands.OrderByDescending(r => r.Id).TakePage(page, perPage).ToList();
        }

        [HttpGet("command/{commandId}")]
        [Produces("application/json")]
        public ActionResult<Command> Get([FromRoute] HexId gatewayId, ulong commandId)
        {
            var request = helper.Get(commandId, gatewayId);
            if (request == null)
                return NotFound();

            return request;
        }

        [HttpPost("command")]
        public async Task<IActionResult> AddGatewayCommand([FromRoute] HexId gatewayId, [FromBody] Command command)
        {
            if (command == null)
                return BadRequest();

            if (context.Gateways.FirstOrDefault(g => g.AgentId == gatewayId.Value) == null)
                return NotFound();

            try
            {
                await helper.AddGatewayCommand(command, gatewayId);
                return CreatedAtAction(nameof(Get), new { gatewayId, commandId = command.Id }, command);
            }
            catch (ArgumentException e)
            {
                return BadRequest(e.Message);
            }
            catch (CommandQueues.InvalidGateway e)
            {
                return StatusCode(StatusCodes.Status410Gone, $"Failed to add command, because {e.Message}. Try restarting gateway.");
            }
        }

        [HttpPost("{deviceType:regex(channel|peripheral|connector)}/{deviceId}/command")]
        public async Task<IActionResult> AddGatewayDeviceCommand([FromRoute] HexId gatewayId, [FromRoute] string deviceType, [FromRoute] HexId deviceId, [FromBody] Command command)
        {
            if (command == null)
                return BadRequest();

            // TODO add device type dependent validation
            if (context.Gateways.FirstOrDefault(g => g.AgentId == gatewayId.Value) == null)
                return NotFound();

            try
            {
                await helper.AddGatewayDeviceCommand(command, gatewayId, deviceId, deviceType); // TODO change to add(Channel|peripheral|connector) command
                return CreatedAtAction(nameof(Get), new { gatewayId, commandId = command.Id }, command);
            }
            catch (CommandQueues.InvalidGateway e)
            {
                return StatusCode(StatusCodes.Status410Gone, $"Failed to add command, because {e.Message}. Try restarting gateway.");
            }
        }

        // This is not perfect, but allows relay/command api (defined by relay capability) to affect relay data in controller db
        async void RelayAddNote(HexId gatewayId, HexId relayId, Command command)
        {
            try 
            {
                // Id check should be enough, but check also name command for sanity.
                if ((int)command.Data["id"] != 65528 || (string)command.Data["command"] != "Rename")
                    return;

                if (context.Relays.Where(r => r.GatewayAgentId == gatewayId.Value).Count(r => r.AgentId == relayId.Value) != 1)
                    throw new InvalidOperationException();

                var name = command.Data["arguments"].FirstOrDefault(n => (string)n["name"] == "Name")["value"];
                var description = command.Data["arguments"].FirstOrDefault(n => (string)n["name"] == "Description")["value"];
                if (name == null || description == null)
                    return;

                var note = context.Notes.FirstOrDefault(n => n.AgentId == relayId.Value);
                if (note != null)
                {
                    note.DisplayName = (string)name;
                    note.Description = (string)description;
                }
                else
                {
                    note = new Note
                    {
                        AgentId = relayId.Value,
                        DisplayName = (string)name,
                        Description = (string)description,
                    };
                    context.Add(note);
                }
                await context.SaveChangesAsync();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
        }

        [HttpPost("relay/{relayId}/command")]
        public async Task<IActionResult> AddRelayCommand([FromRoute] HexId gatewayId, [FromRoute] HexId relayId, [FromBody] Command command)
        {
            if (command == null)
                return BadRequest();

            if (context.Relays.FirstOrDefault(r => r.GatewayAgentId == gatewayId.Value && r.AgentId == relayId.Value) == null)
                return NotFound();

            try
            {
                RelayAddNote(gatewayId, relayId, command);

                await helper.AddRelayCommand(command, gatewayId, relayId);
                return CreatedAtAction(nameof(Get), new { gatewayId, commandId = command.Id }, command);
            }
            catch (CommandQueues.InvalidGateway e)
            {
                return StatusCode(StatusCodes.Status410Gone, $"Failed to add command, because {e.Message}. Try restarting gateway.");
            }
        }

        [HttpPost("relay/{relayId}/{deviceType:regex(channel|peripheral|connector)}/{deviceId}/command")]
        public async Task<IActionResult> AddRelayDeviceCommand([FromRoute] HexId gatewayId, [FromRoute] HexId relayId, [FromRoute] string deviceType, [FromRoute] HexId deviceId, [FromBody] Command command)
        {
            if (command == null)
                return BadRequest();

            // TODO add device type dependent validation
            if (context.Relays.FirstOrDefault(r => r.GatewayAgentId == gatewayId.Value && r.AgentId == relayId.Value) == null)
                return NotFound();

            try
            {
                await helper.AddRelayDeviceCommand(command, gatewayId, relayId, deviceId, deviceType); // TODO change to add(Channel|peripheral|connector) command
                return CreatedAtAction(nameof(Get), new { gatewayId, commandId = command.Id }, command);
            }
            catch (CommandQueues.InvalidGateway e)
            {
                return StatusCode(StatusCodes.Status410Gone, $"Failed to add command, because {e.Message}. Try restarting gateway.");
            }
        }
    }
}
