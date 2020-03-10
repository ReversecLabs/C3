using System;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;

namespace FSecure.C3.Comms
{
    /// <summary>
    /// Class representing C3 API bridge
    /// </summary>
    public class MessageFramingTcpListener : IDisposable
    {
        private TcpListener mListener = null;

        public MessageFramingTcpListener(IPAddress addr, int port)
        {
            mListener = new TcpListener(addr, port);
            mListener.Start();
        }

        public MessageFramingTcpClient Accept() => new MessageFramingTcpClient(mListener.AcceptTcpClient());

        public async Task<MessageFramingTcpClient> AcceptAsync() => new MessageFramingTcpClient(await mListener.AcceptTcpClientAsync());

        public void Dispose() => mListener.Stop();
    }
}
