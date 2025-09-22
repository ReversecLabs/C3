using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Models
{
    public class Note
    {
        public int NoteId { get; set; }
        public ulong AgentId { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
    }
}
