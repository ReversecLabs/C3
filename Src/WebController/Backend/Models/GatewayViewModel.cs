using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public class GatewayViewModel : AgentViewModel
    {
        public ICollection<RelayViewModel> Relays { get; set; }

        public ICollection<Connector> Connectors { get; set; }

        public GatewayViewModel(Gateway g, IEnumerable<Note> notes): base(g, notes?.FirstOrDefault(n => n.AgentId == g.AgentId))
        {
            Connectors = g.Connectors;
            Relays = g.Relays?.Select(r => new RelayViewModel(r, notes?.FirstOrDefault(n => n.AgentId == r.AgentId))).ToList();
        }
    }
}
