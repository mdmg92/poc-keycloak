using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace ApiBanking.Autentication.WebApi3
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            IdentityModelEventSource.ShowPII = true;

            ConfiguroKeycloakAuthentication(services);
        }

        private void ConfiguroKeycloakAuthentication(IServiceCollection services)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var httpClientHandler = new HttpClientHandler
            {
                UseProxy = false,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            services.AddAuthentication(o =>
                {
                    o.DefaultScheme             = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultChallengeScheme    = OpenIdConnectDefaults.AuthenticationScheme;
                    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    o.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
                }).AddJwtBearer(opt =>
                {
                    opt.RequireHttpsMetadata = false;
                    opt.Authority            = Configuration["Keycloak:Jwt:Authority"];
                    opt.Audience             = Configuration["Keycloak:Jwt:Audience"];
                    opt.IncludeErrorDetails  = true;
                    opt.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateAudience         = false,
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer           = true,
                        ValidIssuer              = Configuration["Keycloak:Jwt:ValidIssuer"],
                        ValidateLifetime         = true
                    };
                    opt.Events = new JwtBearerEvents()
                    {
                        OnAuthenticationFailed = c =>
                        {
                            c.NoResult();
                            if (!c.Response.HasStarted)
                            {
                                c.Response.StatusCode = 401;
                            }

                            c.Response.ContentType = "text/plain";
                            return c.Response.WriteAsync(c.Exception.ToString());
                        }
                    };
                    opt.BackchannelHttpHandler = httpClientHandler;
                }).AddCookie("Cookies")
                .AddOpenIdConnect(opt =>
                {
                    opt.BackchannelHttpHandler        = httpClientHandler;
                    opt.Authority                     = Configuration["Keycloak:OpenIdConnect:Authority"];
                    opt.ClientId                      = Configuration["Keycloak:OpenIdConnect:ClientId"];
                    opt.RequireHttpsMetadata          = false;
                    opt.SaveTokens                    = true;
                    opt.GetClaimsFromUserInfoEndpoint = true;
                    opt.ResponseType                  = OpenIdConnectResponseType.CodeIdToken;
                });

            services.AddCors(confg =>
            {
                confg.AddPolicy("AllowAll", p =>
                {
                    p.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
            });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseCors("AllowAll");
            
            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {endpoints.MapDefaultControllerRoute(); });
        }
    }
}