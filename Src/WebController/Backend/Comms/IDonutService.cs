using MWR.C3.WebController.Models;
using System.Collections.Generic;

namespace MWR.C3.WebController.Comms
{
    public interface IDonutService
    {
        byte[] GenerateShellcode(byte[] payload, DonutRequest request, Build.Architecture arch);
    }

    public class DonutServiceOptions
    {
        public string Tempdir { get; set; }
    }
}
