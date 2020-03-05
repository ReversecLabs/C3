using FSecure.C3.WebController.Comms;
using System.ComponentModel;

namespace FSecure.C3.WebController.Models
{
    [TypeConverter(typeof(HexIdTypeConverter))]
    public class HexId
    {
        public ulong Value { get; set; }

        public static HexId TryParse(string s)
        {
            if (ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out ulong value))
            {
                return new HexId
                {
                    Value = value,
                };
            }
            return null;
        }

        public override string ToString()
        {
            return $"{Value:x}";
        }
        public HexId()
        {
        }
        public HexId(ulong value)
        {
            Value = value;
        }
    }
}
