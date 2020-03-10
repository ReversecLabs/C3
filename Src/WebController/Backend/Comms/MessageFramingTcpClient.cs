using System;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace FSecure.C3.Comms
{
    public class ConnectionTerminated : Exception
    {
        public ConnectionTerminated() : base() { }
        public ConnectionTerminated(string message) : base(message) { }
    }

    /// <summary>
    /// Class representing C3 API bridge
    /// </summary>
    public class MessageFramingTcpClient : IDisposable
    {
        private TcpClient mClient = null;

        /// <summary>
        /// Create ApiBride and connect to C3 gateway
        /// </summary>
        /// <param name="addr">IP address of C3 Gateway</param>
        /// <param name="port">port of C3 Gateway API bridge</param>
        /// <exception cref="ArgumentNullException">The addr parameter is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The port parameter is not between System.Net.IPEndPoint.MinPort and System.Net.IPEndPoint.MaxPort.</exception>
        /// <exception cref="System.Net.Sockets.SocketException"> An error occurred when accessing the socket.</exception>
        public MessageFramingTcpClient(string addr, int port)
        {
            mClient = new TcpClient(addr, port);
        }

        public MessageFramingTcpClient(TcpClient tcpClient)
        {
            mClient = tcpClient;
        }

        /// <summary>
        /// Send data to Gateway, prefixed with data's length (4 bytes, network order)
        /// </summary>
        /// <param name="data"></param>
        public void Send(byte[] data)
        {
            var stream = mClient.GetStream();
            stream.Write(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length)), 0, sizeof(UInt32));
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Send data to Gateway, prefixed with data's length (4 bytes, network order)
        /// </summary>
        /// <param name="data"></param>
        public async Task SendAsync(byte[] data)
        {
            var stream = mClient.GetStream();
            await stream.WriteAsync(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length)), 0, sizeof(UInt32));
            await stream.WriteAsync(data, 0, data.Length);
        }

        /// <summary>
        /// Receive data from Gateway. First 4 bytes are interpreted as data length (in network order)
        /// </summary>
        /// <returns></returns>
        public async Task<byte[]> ReceiveAsync(CancellationToken ct)
        {
            var lenBuffer = await ReadAsync(sizeof(UInt32), ct);
            var messageLen = IPAddress.NetworkToHostOrder((int)BitConverter.ToUInt32(lenBuffer));
            return await ReadAsync(messageLen, ct);
        }

        /// <summary>
        /// Release resources
        /// </summary>
        public void Dispose()
        {
            mClient.Dispose();
        }

        private async Task<byte[]> ReadAsync(int size, CancellationToken ct)
        {
            var stream = mClient.GetStream();
            var data = new byte[size];
            var totalRead = 0;
            do
            {
                var current = await stream.ReadAsync(data, totalRead, data.Length - totalRead, ct);
                if (current == 0)
                    throw new OperationCanceledException($"Connection to {mClient.Client.RemoteEndPoint} terminated");
                totalRead += current;
            } while (totalRead != size);
            return data;
        }
    }
}
