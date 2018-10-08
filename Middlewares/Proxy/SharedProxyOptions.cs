using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace OpisenseClientTemplate.Middlewares.Proxy
{
    /// <summary>
    /// Shared Proxy Options
    /// </summary>
    public class SharedProxyOptions
    {
        private int? webSocketBufferSize;

        /// <summary>
        /// Message handler used for http message forwarding.
        /// </summary>
        public HttpMessageHandler MessageHandler { get; set; }

        /// <summary>
        /// Allows to modify HttpRequestMessage before it is sent to the Message Handler.
        /// </summary>
        public Func<HttpContext, HttpRequest, HttpRequestMessage, Task> PrepareRequest { get; set; }
        /// <summary>
        /// Allows to modify HttpRequestMessage before it is sent to the Message Handler.
        /// </summary>
        public Func<HttpContext, HttpRequest, HttpRequestMessage,string, Task> PrepareRequestWithAccessToken { get; set; }

        /// <summary>
        /// Allows to refresh the auth token in case it is expired.
        /// </summary>
        public Func<HttpContext, HttpRequest, HttpRequestMessage, Task<(bool, string)>> RefreshToken { get; set; }

        /// <summary>
        /// Keep-alive interval for proxied Web Socket connections.
        /// </summary>
        public TimeSpan? WebSocketKeepAliveInterval { get; set; }

        /// <summary>
        /// Internal send and receive buffers size for proxied Web Socket connections.
        /// </summary>
        public int? WebSocketBufferSize
        {
            get => webSocketBufferSize;
            set
            {
                if (value.HasValue && value.Value <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value));
                }
                webSocketBufferSize = value;
            }
        }
    }
}