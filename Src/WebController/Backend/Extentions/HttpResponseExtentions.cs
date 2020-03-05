using System;
using Microsoft.AspNetCore.Http;

namespace FSecure.C3.WebController.HttpExtentions
{
    public static class HttpResponseExtentions
    {
        public static void AddPaginationHeaders(this HttpResponse self, int page, int perPage, int total)
        {
            var totalPages = Math.Ceiling((double) total / perPage);
            self.Headers.Add("X-Page", page.ToString());
            self.Headers.Add("X-Per-Page", perPage.ToString());
            self.Headers.Add("X-Total-Count", total.ToString());
            self.Headers.Add("X-Total-Pages", totalPages.ToString());
        }
    }
}
