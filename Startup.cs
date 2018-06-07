using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Web;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.SpaServices.AngularCli;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpisenseClientTemplate.Middlewares;
using OpisenseClientTemplate.Middlewares.Proxy;

namespace OpisenseClientTemplate
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        string redirectCookieName = "X-OpiSense-RedirectAfterLogin";
        private readonly OpisenseSettings opisenseSettings = new OpisenseSettings();

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            Configuration.Bind("OpisenseSettings", opisenseSettings);
            services.AddSingleton(opisenseSettings);

            // In production, the Angular files will be served from this directory
            services.AddSpaStaticFiles(configuration =>
            {
                configuration.RootPath = "ClientApp/dist";
            });
            
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = "oidc";
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.SlidingExpiration = true;
                    options.Cookie.Name = "Opisense.Authll";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);

                    options.Events.OnSignedIn = async ctx =>
                    {
                        if (!IsAjaxRequest(ctx.Request))
                        {
                            var redirectUrl = ctx.Request.Cookies[redirectCookieName];
                            if (redirectUrl != null)
                            {
                                ctx.Response.Cookies.Delete(redirectCookieName);
                                ctx.Response.Redirect(redirectUrl);
                            }
                        }
                    };

                })
                .AddOpenIdConnect("oidc", options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.Authority = opisenseSettings.IdentityServerConfiguration.IdentityServerUrl;
                    options.ClientId = opisenseSettings.IdentityServerConfiguration.ClientId;
                    options.ClientSecret = opisenseSettings.IdentityServerConfiguration.ClientSecret;

                    // options.GetClaimsFromUserInfoEndpoint = true;
                    options.SaveTokens = true;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = JwtClaimTypes.Name,
                        RoleClaimType = JwtClaimTypes.Role,
                    };

                    options.Scope.Clear();
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("roles");
                    options.Scope.Add(ScopeConstants.Api);
                    options.Scope.Add(ScopeConstants.OfflineAccess);
                    options.Scope.Add("opisense");

                    options.ResponseType = "code id_token";

                    // options.CallbackPath = new PathString("/oidctoken");

                    options.UseTokenLifetime = false;

                    options.RequireHttpsMetadata = false;

                    options.ClaimActions.Remove("amr");

                    options.Events.OnRedirectToIdentityProvider = async notification =>
                    {
                        notification.ProtocolMessage.AcrValues = $"tenant:{opisenseSettings.IdentityServerConfiguration.Tenant} " +
                                                                 $"clientId:Opisense " +
                                                                 $"redirectUri:{HttpUtility.UrlEncode($"{notification.Request.Scheme}://{notification.Request.Host}/oidctoken")}";

                        if (!IsAjaxRequest(notification.Request))
                        {
                            notification.Response.Cookies.Append(redirectCookieName, GetCallbackPathForDeepLinking(notification.Request));
                        }
                        else if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            notification.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
                            notification.HandleResponse();
                        }

                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            notification.ProtocolMessage.IdTokenHint = await notification.HttpContext.GetTokenAsync("id_token");
                        }
                    };

                    options.Events.OnAuthenticationFailed = async notification =>
                    {
                        if (notification.Exception is OpenIdConnectProtocolInvalidNonceException)
                        {
                            notification.SkipHandler();
                        }
                    };

                    options.Events.OnRemoteFailure = async notification =>
                    {
                        // TODO : Add Logs
                    };

                });

            services.AddMvc(config =>
            {
                // Require a authenticated user
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();

                config.Filters.Add(new AuthorizeFilter(policy));
            });

            services.AddOpisenseProxy(opisenseSettings.IdentityServerConfiguration);
        }

        private string GetCallbackPathForDeepLinking(HttpRequest request)
        {
            if (request.Path.StartsWithSegments(new PathString("/swagger")))
            {
                return request.ToString();
            }

            if (request.Headers.TryGetValue("X-Original-URL", out var originalUrl))
            {
                if (originalUrl.Count > 0)
                {
                    return originalUrl[0];
                }
            }

            return "/";
        }

        private bool IsAjaxRequest(HttpRequest request)
        {
            var query = request.Query;
            if ((query != null) && (query["X-Requested-With"] == "XMLHttpRequest"))
            {
                return true;
            }
            IHeaderDictionary headers = request.Headers;
            return ((headers != null) && (headers["X-Requested-With"] == "XMLHttpRequest"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();
            app.UseStaticFiles();
            app.UseSpaStaticFiles();

            // IMPORTANT NOTE: we are telling the Proxy Middleware to register on /api. This means that if you want to host your own API in this project, you cannot use /api
            // See SampleDataController for usage
            app.RunProxy(new Uri(opisenseSettings.ApiBaseUrl), new PathString("/api"));

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });

            // This Middleware forces the usage of the oidc security challenge BEFORE entering into the SPA
            app.Use(async (context, next) =>
            {
                if (!context.User.Identity.IsAuthenticated)
                {
                    await context.ChallengeAsync("oidc");
                }
                else
                {
                    await next();
                }
            });

            app.UseSpa(spa =>
            {
                // To learn more about options for serving an Angular SPA from ASP.NET Core,
                // see https://go.microsoft.com/fwlink/?linkid=864501
                spa.Options.SourcePath = "ClientApp";

                if (env.IsDevelopment())
                {
                    spa.UseAngularCliServer(npmScript: "start");
                }
            });
        }
    }

    public static class ScopeConstants
    {
        public const string Api = "opisense-api";
        public const string OfflineAccess = "offline_access";
    }

    public class OpisenseSettings
    {
        public string ApiBaseUrl { get; set; }
        public IdentityServerConfiguration IdentityServerConfiguration { get; set; }
    }

    public class IdentityServerConfiguration
    {
        public string IdentityServerUrl { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Tenant { get; set; }
    }
}
