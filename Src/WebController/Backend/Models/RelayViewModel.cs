using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public class RelayViewModel : AgentViewModel
    {
        public HostInfo HostInfo { get; set; }
        public RelayViewModel(Relay r) : base(r, r.Build?.Name)
        {
            HostInfo = r.HostInfo;
        }
    }
}
