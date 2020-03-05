using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FSecure.C3.WebController.LinqExtentions
{
    public static class IQueryableExtentions
    {
        public static IQueryable<T> TakePage<T>(this IQueryable<T> self, int page, int perPage)
        {
            int skip = (page - 1) * perPage;
            return self.Skip(skip).Take(perPage);
        }
    }
}
