using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;


using Microsoft.ServiceBus;
using Microsoft.ServiceBus.Messaging;

namespace servicebus
{
    class Program
    {
        static void Main(string[] args)
        {

            if(args.Length < 3)
            {
                Console.WriteLine("Usage:\nServiceBusSignatureGenerator.exe <service-name> <keyName> <keyValue>");
                return;
            }

            TimeSpan sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
          
            string serviceName = args[0];
            string keyName = args[1];
            string keyValue = args[2];
            

           
            var serviceUri = ServiceBusEnvironment.CreateServiceUri("https", serviceName, "/").ToString();
            string inputToken = SharedAccessSignatureTokenProvider.GetSharedAccessSignature(keyName, keyValue, serviceUri, sinceEpoch);
            Console.WriteLine(inputToken);
        }

    }
}
