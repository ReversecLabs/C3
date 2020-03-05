using FSecure.C3.WebController.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.Comms
{
    public class CustomizerError : Exception
    {
        public CustomizerError() { }

        public CustomizerError(string message) : base(message) { }

        public CustomizerError(string message, Exception inner) : base(message, inner) { }
    }

    public interface ICustomizer
    {
        byte[] GetGateway(Build.Architecture arch);

        Task<byte[]> CustomizeNodeRelay(RelayBuild build);
    }
}
