using MWR.C3.WebController.Models;
using System.Collections.Generic;

namespace MWR.C3.WebController.Comms
{
    public interface IDonutService
    {
        byte[] GenerateShellcode(byte[] payload, DonutRequest request, Build.Architecture arch, Build.BinaryType binaryType);
    }

    public class DonutServiceOptions
    {
        public bool Enable { get; set; }
        public string Tempdir { get; set; }
    }
}
