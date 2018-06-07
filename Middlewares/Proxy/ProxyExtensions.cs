using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpisenseClientTemplate.Middlewares.Proxy
{
    public static class ProxyExtensions
    {
        /// <summary>
        /// Runs proxy forwarding requests to the server specified by base uri.
        /// </summary>
        /// <param name="app"></param>
        /// <param name="baseUri">Destination base uri</param>
        /// <param name="pathFilter">Filter to only proxy request coming on a certain path <example>/api</example></param>
        public static void RunProxy(this IApplicationBuilder app, Uri baseUri, PathString pathFilter)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (baseUri == null)
            {
                throw new ArgumentNullException(nameof(baseUri));
            }

            var options = new ProxyOptions
            {
                Scheme = baseUri.Scheme,
                Host = new HostString(baseUri.Authority),
                PathBase = baseUri.AbsolutePath,
                AppendQuery = new QueryString(baseUri.Query),
                PathFilter = pathFilter
            };
            app.UseMiddleware<ProxyMiddleware>(Options.Create(options));
        }

        /// <summary>
        /// Runs proxy forwarding requests to the server specified by options.
        /// </summary>
        /// <param name="app"></param>
        public static void RunProxy(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            app.UseMiddleware<ProxyMiddleware>();
        }

        /// <summary>
        /// Runs proxy forwarding requests to the server specified by options.
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options">Proxy options</param>
        public static void RunProxy(this IApplicationBuilder app, ProxyOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            app.UseMiddleware<ProxyMiddleware>(Options.Create(options));
        }

        /// <summary>
        /// Forwards current request to the specified destination uri.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="destinationUri">Destination Uri</param>
        public static async Task ProxyRequest(this HttpContext context, Uri destinationUri)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (destinationUri == null)
            {
                throw new ArgumentNullException(nameof(destinationUri));
            }

            if (context.WebSockets.IsWebSocketRequest)
            {
                await context.AcceptProxyWebSocketRequest(destinationUri.ToWebSocketScheme());
            }
            else
            {
                var proxyService = context.RequestServices.GetRequiredService<ProxyService>();

                using (var requestMessage = context.CreateProxyHttpRequest(destinationUri))
                {
                    var prepareRequestHandler = proxyService.Options.PrepareRequest;
                    if (prepareRequestHandler != null)
                    {
                        await prepareRequestHandler(context, context.Request, requestMessage);
                    }

                    using (var responseMessage = await context.SendProxyHttpRequest(requestMessage))
                    {
                        if (responseMessage.StatusCode == HttpStatusCode.Unauthorized)
                        {
                            var refreshToken = proxyService.Options.RefreshToken;
                            if (refreshToken != null)
                            {
                                await refreshToken(context, context.Request, requestMessage);

                                using (var requestMessage2 = context.CreateProxyHttpRequest(destinationUri))
                                {
                                    var prepareRequestHandler2 = proxyService.Options.PrepareRequest;
                                    if (prepareRequestHandler2 != null)
                                    {
                                        await prepareRequestHandler2(context, context.Request, requestMessage2);
                                    }

                                    using (var responseMessage2 = await context.SendProxyHttpRequest(requestMessage2))
                                    {
                                        await context.CopyProxyHttpResponse(responseMessage2);
                                    }
                                }
                            }
                        }
                        else
                        {
                            await context.CopyProxyHttpResponse(responseMessage);
                        }
                    }
                }
            }
        }
    }
}