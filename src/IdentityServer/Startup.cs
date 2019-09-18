using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection;
using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace IdentityServer
{
    public class Startup
    {
        public IHostingEnvironment Environment { get; }

        public Startup(IHostingEnvironment environment)
        {
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            const string connectionString = @"
                Data Source=DESKTOP-7ML2D8L;
                Database=IdentityServer4;
                User ID=sa;
                Password=sapassword;
                ";
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;


            var builder = services.AddIdentityServer()
                .AddTestUsers(Config.GetUsers())
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseSqlServer(connectionString,
                            sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = b =>
                        b.UseSqlServer(connectionString,
                            sql => sql.MigrationsAssembly(migrationsAssembly));

                    options.EnableTokenCleanup = true;
                });


            // JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            // services.AddAuthentication()
            //     .AddOpenIdConnect("oidc", "OpenID Connect", options =>
            //         {
            //             options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //             options.SignOutScheme = IdentityServerConstants.SignoutScheme;
            //             options.SaveTokens = true;
            //             options.RequireHttpsMetadata = false;

            //             options.Authority = "http://localhost:5000";
            //             options.ClientId = "implicit";

            //             options.TokenValidationParameters = new TokenValidationParameters
            //             {
            //                 NameClaimType = "name",
            //                 RoleClaimType = "role"
            //             };
            //         });

            // if (Environment.IsDevelopment())
            // {
            //     builder.AddDeveloperSigningCredential();
            // }
            // else
            // {
                X509Certificate2 cert = null;
                using (var certStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                 
                    certStore.Open(OpenFlags.ReadOnly);
                    var certCollection = certStore.Certificates.Find(
                        X509FindType.FindByThumbprint,
                        "1a6712fc72aa71224676373d3bcc5ce9ca1f2fb8",
                        false
                    );

                    if (certCollection.Count > 0)
                    {
                        cert = certCollection[0];
                    }
                }
                
                if (cert == null)
                {
                    services.AddIdentityServer().AddSigningCredential(cert);
                }
            // }
        }

        public void Configure(IApplicationBuilder app)
        {
            InitializeDatabase(app);
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseStaticFiles();
            app.UseIdentityServer();
            app.UseMvcWithDefaultRoute();
        }

        private void InitializeDatabase(IApplicationBuilder app)
        {
            using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();
                var grantContext = serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>();
                grantContext.Database.Migrate();
                if (!context.Clients.Any())
                {
                    foreach (var client in Config.GetClients())
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }
                else
                {
                    foreach (var client in Config.GetClients())
                    {
                        var item = context.Clients
                            .Include(x => x.RedirectUris)
                            .Include(x => x.PostLogoutRedirectUris)
                            .Include(x => x.ClientSecrets)
                            .Include(x => x.Claims)
                            .Include(x => x.AllowedScopes)
                            .Include(x => x.AllowedCorsOrigins)
                            .Include(x => x.AllowedGrantTypes)
                            .Where(c => c.ClientId == client.ClientId).FirstOrDefault();

                        if (item != null)
                        {
                            context.Clients.Remove(item);
                        }

                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();

                }
                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in Config.GetIdentityResources())
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                else
                {
                    foreach (var resource in Config.GetIdentityResources())
                    {
                        var item = context.IdentityResources.Where(c => c.Name == resource.Name).FirstOrDefault();
                        if (item != null)
                        {
                            context.IdentityResources.Remove(item);
                        }
                        context.IdentityResources.Add(resource.ToEntity());
                    }

                    context.SaveChanges();
                }
                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.GetApis())
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                else
                {
                    foreach (var resource in Config.GetApis())
                    {
                        var item = context.ApiResources.Where(x => x.Name == resource.Name).FirstOrDefault();
                        if (item != null)
                        {
                            context.ApiResources.Remove(item);
                        }
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
            }
        }
    }
}
