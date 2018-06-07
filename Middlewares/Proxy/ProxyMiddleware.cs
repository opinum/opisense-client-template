using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;

namespace OpisenseClientTemplate.Middlewares.Proxy
{
    /// <summary>
    /// Proxy Middleware
    /// </summary>
    public class ProxyMiddleware
    {
        private readonly RequestDelegate next;
        private readonly ProxyOptions options;
        
        public ProxyMiddleware(RequestDelegate next, IOptions<ProxyOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (options.Value.Scheme == null)
            {
                throw new ArgumentException("Options parameter must specify scheme.", nameof(options));
            }
            if (!options.Value.Host.HasValue)
            {
                throw new ArgumentException("Options parameter must specify host.", nameof(options));
            }

            this.next = next ?? throw new ArgumentNullException(nameof(next));
            this.options = options.Value;
        }

        public async Task Invoke(HttpContext context)
        {
            if (context.Request.Path.StartsWithSegments(options.PathFilter))
            {
                var newPath = new PathString(context.Request.Path.ToString().Substring(options.PathFilter.ToString().Length));

                var uri = new Uri(UriHelper.BuildAbsolute(options.Scheme, options.Host, options.PathBase, newPath, context.Request.QueryString.Add(options.AppendQuery)));
                await context.ProxyRequest(uri);
            }
            else
            {
                await next(context);
            }
        }
    }
}