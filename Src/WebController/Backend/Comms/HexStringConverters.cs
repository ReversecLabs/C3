using System;
using System.ComponentModel;
using System.Globalization;
using Newtonsoft.Json;

namespace FSecure.C3.WebController.Comms
{
    public sealed class HexStringJsonConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return typeof(ulong).Equals(objectType);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue($"{value:x}");
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.Value is string str)
                return ulong.Parse(str, NumberStyles.HexNumber);

            throw new JsonSerializationException();
        }
    }

    public class HexIdTypeConverter : TypeConverter
    {
        public override bool CanConvertFrom(ITypeDescriptorContext context, Type sourceType)
        {
            if (sourceType == typeof(string))
            {
                return true;
            }
            return base.CanConvertFrom(context, sourceType);
        }

        public override object ConvertFrom(ITypeDescriptorContext context, CultureInfo culture, object value)
        {
            if (value is string s)
            {
                return Models.HexId.TryParse(s);
            }

            return base.ConvertFrom(context, culture, value);
        }
    }
}
