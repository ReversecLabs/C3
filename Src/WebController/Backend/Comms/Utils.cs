using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FSecure.C3.WebController.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json.Linq;
using System.ComponentModel;
using System.Text;

namespace FSecure.C3.WebController.Comms
{
    public static class Utils
    {
        public static DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddMilliseconds(unixTimeStamp / 10000);
            return dtDateTime;
        }

        public static bool DoesPropertyExist(dynamic obj, string property)
        {
            return ((Type)obj.GetType()).GetProperties().Any(p => p.Name.Equals(property));
        }

        public static Type GetType(string _namespace, string _type)
        {
            var stringBuilder = new StringBuilder();
            var messageTypeQualifiedName = stringBuilder.Append(_namespace).Append('.').Append(_type).ToString();
            return Type.GetType(messageTypeQualifiedName, true);
        }

        static public int IndexOf(byte[] arrayToSearch, byte[] patternToFind)
        {
            if (patternToFind.Length > arrayToSearch.Length)
                return -1;

            for (int i = 0; i < arrayToSearch.Length - patternToFind.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < patternToFind.Length; j++)
                {
                    if (arrayToSearch[i + j] != patternToFind[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    return i;
                }
            }
            return -1;
        }

        public static ResponseT Cast<ResponseT>(dynamic resp)
        {
            if (resp is ResponseT responseT)
                return responseT;
            else
                throw new InvalidOperationException($"Invalid response type. Expected [{typeof(ResponseT)}], got [{resp.GetType().Name}]");
        }
    }

    public class LowercaseContractResolver : DefaultContractResolver
    {
        protected override string ResolvePropertyName(string propertyName)
        {
            return propertyName.ToLower();
        }
    }
}