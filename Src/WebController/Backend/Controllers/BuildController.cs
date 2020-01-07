using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using MWR.C3.WebController.Models;
using MWR.C3.WebController.HttpExtentions;
using MWR.C3.WebController.LinqExtentions;
using MWR.C3.WebController.Comms;
using System.Threading.Tasks;
using MWR.C3.WebController.Comms.GatewayResponses;
using Microsoft.AspNetCore.Http;

namespace MWR.C3.WebController.Controllers
{
    [Route("api/[controller]")]
    public class BuildController : Controller
    {
        private readonly C3WebAPIContext context;

        public BuildController(C3WebAPIContext c)
        {
            context = c;
        }

        [HttpGet]
        [Produces("application/json")]
        public IEnumerable<RelayBuild> ListBuilds(int page = 1, int perPage = 10)
        {
            Response.AddPaginationHeaders(page, perPage, context.RelayBuilds.AsQueryable().Count());
            return context.RelayBuilds.OrderBy(build => build.BuildId).TakePage(page, perPage);
        }

        // GET: api/[controller]/[buildId]
        [HttpGet("{buildId}")]
        [Produces("application/json")]
        public ActionResult<RelayBuild> GetBuild(HexId buildId)
        {
            if (buildId.Value < 0 || buildId.Value > UInt16.MaxValue)
                return BadRequest("BuildID out of range");

            var build = context.RelayBuilds.Where(r => r.BuildId == buildId.Value).FirstOrDefault();
            if (build != null)
                return build;

            return NotFound();
        }

        [HttpPost("customize")]
        public async Task<IActionResult> Customize([FromBody]RelayBuildRequest request, [FromServices] ICustomizer customizer, [FromServices] IDonutService donut)
        {
            if (request is null)
                return BadRequest("Failed to read RelayBuildRequest");

            RelayBuild newBuild = null;
            System.Action cleanupBuild = () =>
            {
                if (newBuild != null)
                {
                    try
                    {
                        context.RelayBuilds.Remove(newBuild);
                        context.SaveChanges();
                    }
                    catch (Exception)
                    {
                    }
                }
            };
            try
            {
                newBuild = Convert(request);
                byte[] output;
                {
                    context.RelayBuilds.Add(newBuild);
                    context.SaveChanges();
                }
                output = await customizer.CustomizeNodeRelay(newBuild);
                if (request.Type == Build.BinaryType.Shellcode)
                    output = donut.GenerateShellcode(output, request.Donut ?? new DonutRequest(), request.Architecture);
                var buildName = String.IsNullOrEmpty(newBuild.Name) ? "" : $"_{newBuild.Name}";
                return File(output, "application/octet-stream", $"Relay_{newBuild.Arch.ToString().ToLower()}_{newBuild.BuildId:x}{buildName}.{GetBuildExtention(request)}");
            }
            catch (TimeoutException e)
            {
                cleanupBuild();
                return StatusCode(StatusCodes.Status408RequestTimeout, e.Message);
            }
            catch (CommandQueues.InvalidGateway e)
            {
                cleanupBuild();
                return StatusCode(StatusCodes.Status410Gone, $"Failed to add build, because {e.Message}. Try restarting gateway.");
            }
            catch (Exception e)
            when (e is CustomizerError || e is GatewayResponseError)
            {
                cleanupBuild();
                return BadRequest(e.Message);
            }
            catch (Exception e)
            {
                cleanupBuild();
                return StatusCode(StatusCodes.Status500InternalServerError, $"Unknown error. {e.Message}");
            }
        }

        private Models.RelayBuild Convert(RelayBuildRequest request)
        {
            var gatewayAgentId = context.Gateways.First(g => g.BuildId == request.ParentGatewayBuildId).AgentId;
            var gatewayBuild = context.GatewayBuilds.Single(g => g.BuildId == request.ParentGatewayBuildId);
            return new RelayBuild
            {
                Arch = request.Architecture,
                Type = request.Type,
                Name = request.Name,
                StartupCommands = request.StartupCommands,
                BroadcastKey = gatewayBuild.BroadcastKey,
                PublicKey = gatewayBuild.PublicKey,
                Channels = gatewayBuild.Channels,
                Commands = gatewayBuild.RelayCommands["commands"],
                Peripherals = gatewayBuild.Peripherals,
                ParentGatwayAgentId = gatewayAgentId,
            };
        }

        private string GetBuildExtention(RelayBuildRequest request)
        {
            switch (request.Donut?.format)
            {
                case DonutLibrary.OutputFormat.BINARY: return "bin";
                case DonutLibrary.OutputFormat.BASE64: return "b64";
                case DonutLibrary.OutputFormat.RUBY: return "rb";
                case DonutLibrary.OutputFormat.C: return "c";
                case DonutLibrary.OutputFormat.PYTHON: return "py";
                case DonutLibrary.OutputFormat.POWERSHELL: return "ps1";
                case DonutLibrary.OutputFormat.CSHARP: return "cs";
                case DonutLibrary.OutputFormat.HEX: return "hex";
                case null: return request.Type.ToString().ToLower();
                default: throw new ArgumentException("Unrecognized output format");
            }
        }
    }
}
