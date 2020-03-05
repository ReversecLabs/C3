using System;
using System.Linq;

namespace FSecure.C3.WebController.RandomExtentions
{
    public static class RandomExtentions
    {
        public static ushort NextU16(this Random self)
        {
            var buffer = new byte[sizeof(ushort)];
            self.NextBytes(buffer);
            return BitConverter.ToUInt16(buffer);
        }

        public static uint NextU32(this Random self)
        {
            var buffer = new byte[sizeof(uint)];
            self.NextBytes(buffer);
            return BitConverter.ToUInt32(buffer);
        }

        public static ulong NextU64(this Random self)
        {
            var buffer = new byte[sizeof(ulong)];
            self.NextBytes(buffer);
            return BitConverter.ToUInt64(buffer);
        }

        public static string NextString(this Random self, int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[self.Next(s.Length)]).ToArray());
        }
    }
}
