using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpisenseClientTemplate.Middlewares.Proxy;

namespace OpisenseClientTemplate.Middlewares
{
    public static class OpisenseApiProxyMiddlewareExtensions
    {
        public static IServiceCollection AddOpisenseProxy(this IServiceCollection services, IdentityServerConfiguration identityServerConfiguration)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            return services.AddProxy(options =>
            {
                options.PrepareRequest = async (context, originalRequest, message) =>
                {
                    var accessToken = await context.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, "access_token");
                    message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                };

                options.PrepareRequestWithAccessToken = async (context, originalRequest,message, accessToken) =>
                {
                    message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                };

                options.RefreshToken = async (context, originalRequest, message) =>
                {
                    var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                  return  await TokenRefreshCoordinator.Refresh(userId, () => RefreshToken(context, identityServerConfiguration));
                };
            });
        }

        private static async Task<(bool, string)> RefreshToken(HttpContext context, IdentityServerConfiguration identityServerConfiguration)
        {
            var tokenClient = new TokenClient(
                identityServerConfiguration.IdentityServerUrl + "/connect/token",
                identityServerConfiguration.ClientId,
                identityServerConfiguration.ClientSecret);

            var refreshToken = await context.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, "refresh_token");
            var response = await tokenClient.RequestRefreshTokenAsync(refreshToken);

            if (response.IsError)
            {
                //logger.Warn($"Failed to refresh token for user {principal.Identity.GetUserId()}, returning 401");

                //TODO
                //throw new HttpResponseException(HttpStatusCode.Unauthorized);

                return (false, null);
            }

            context.Items["RefreshTokenResponse"] = response;
            var tokens = new List<AuthenticationToken>
                {
                    new AuthenticationToken {Name = OpenIdConnectParameterNames.IdToken, Value = await context.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme,"id_token")},
                    new AuthenticationToken {Name = OpenIdConnectParameterNames.AccessToken, Value = response.AccessToken},
                    new AuthenticationToken {Name = OpenIdConnectParameterNames.RefreshToken, Value = response.RefreshToken}
                };
            var expiresAt = DateTime.UtcNow + TimeSpan.FromSeconds(response.ExpiresIn);
            tokens.Add(new AuthenticationToken { Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) });

            var info = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            info.Properties.StoreTokens(tokens);

            //await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, info.Principal, info.Properties);

            context.Response.OnStarting(async () =>
             {
                 await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, info.Principal, info.Properties);
             });

            return (true, response.AccessToken);
        }
    }

    /// <summary>
    /// This class is used to prevent multiple token refresh hapenning at the same time for the same user.
    /// </summary>
    internal static class TokenRefreshCoordinator
    {
        //private static readonly ILog Logger = LogManager.GetLogger(typeof(OpisenseApiSecurityHandler));

        static readonly ConcurrentDictionary<string, AccessTokenRefreshContext> LockPerUser =
            new ConcurrentDictionary<string, AccessTokenRefreshContext>();

        public static async Task<(bool, string)> Refresh(string userId, Func<Task<(bool, string)>> doRefresh)
        {
            if (LockPerUser.TryAdd(userId, new AccessTokenRefreshContext()))
            {
                var contextId = LockPerUser[userId].ContextId;
                //logger.Debug($"Access token refresh for user<{userId}> context<{contextId}> - Calling Refresh(method)");
                var freshAccessToken = (false, String.Empty);
                try
                {
                    freshAccessToken = await doRefresh();
                }
                finally
                {
                    LockPerUser.TryRemove(userId, out var currentContext);

                    currentContext.UnlockWaiters(freshAccessToken);
                }
                return freshAccessToken;
            }

            if (LockPerUser.TryGetValue(userId, out AccessTokenRefreshContext context))
            {
                //Logger<>.Debug($"Access token refresh for user<{userId}> context<{context.ContextId}> - Waiting for semaphore");
                try
                {
                    await context.WaitAsync();
                }
                catch (ObjectDisposedException)
                {
                    //Logger<>.Debug($"Access token refresh for user<{userId}> context<{context.ContextId}> - Semaphore released");
                    return (true, context.FreshAccessToken);
                }
                catch (Exception ex)
                {
                    //Logger<>.Debug($"Access token refresh for user<{userId}> context<{context.ContextId}> - Semaphore released");
                    return (true, context.FreshAccessToken);
                }
            }

            //At this point, there was a race condition: we could not Add the userId key but were not able to get the dictionary value (LockPerUser.TryRemove was called in between)
            //Logger<>.Debug($"Access token refresh for user<{userId}> - Got refresh token without dictionary lock");
            return await doRefresh();
        }
    }

    internal class AccessTokenRefreshContext
    {
        private readonly CancellationTokenSource cancellationTokenSource;
        public SemaphoreSlim Semaphore { get; }
        public string FreshAccessToken { get; private set; }
        public Guid ContextId { get; }

        public AccessTokenRefreshContext()
        {
            Semaphore = new SemaphoreSlim(0, 1);
            FreshAccessToken = string.Empty;
            ContextId = Guid.NewGuid();
            this.cancellationTokenSource = new CancellationTokenSource();
        }

        public void UnlockWaiters((bool, string) result)
        {
            FreshAccessToken = result.Item2;
            cancellationTokenSource.Cancel();
            Semaphore.Dispose();
        }

        public async Task WaitAsync()
        {
            await Semaphore.WaitAsync(cancellationTokenSource.Token);
        }
    }
}