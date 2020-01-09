using System;
using System.IO;
using System.Text;


namespace ResourceGenerator
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 2 || !File.Exists(args[0]) || !Directory.Exists(args[1]))
            {
                System.Console.WriteLine("ResourceGenerator require existing input file and output directory.");
                return 1;
            }

            var outputDir = Path.Join(args[1], "gen");
            if (!Directory.Exists(outputDir))
                Directory.CreateDirectory(outputDir);

            var guid = Guid.NewGuid().ToByteArray();
            using (var sw = new StreamWriter(Path.Join(outputDir, "EmbeddedResource.h"), false) { AutoFlush = true })
            {
                sw.Write("#define EMBEDDED_DLL_PAYLOAD \"");
                foreach (var oneByte in guid)
                    sw.Write(String.Format("\\x{0:x2}", oneByte));
                sw.Write("\"\n");
            }


            using (var bw = new BinaryWriter(File.Open(Path.Join(outputDir, "EmbeddedResource.dat"), FileMode.Create)))
            {
                var data = File.ReadAllBytes(args[0]);
                bw.Write(guid);
                bw.Write((byte)0xff);
                bw.Write(BitConverter.GetBytes(data.Length));
                bw.Write(data);
                string exportName = args.Length < 3 ? "" : args[2];
                bw.Write(BitConverter.GetBytes(exportName.Length));
                bw.Write(Encoding.ASCII.GetBytes(exportName));
            }

            return 0;
        }
    }
}
