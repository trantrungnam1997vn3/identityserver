using System.Linq;
using System.Reflection;

using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;


namespace IdentityServer
{
    public class Startup
    {
        public IHostingEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IHostingEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            // string connectionString = Configuration.GetConnectionString("DefaultConnection");
            string connectionString = "Data Source=DESKTOP-999UR4G;Database=IdentityServer4;User ID=sa;Password=sapassword;MultipleActiveResultSets=true";
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

            X509Certificate2 cert = null;
            using (var certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                certStore.Open(OpenFlags.ReadOnly);
                var certCollection = certStore.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    // Configuration.GetConnectionString("Thumbprint-Key"),
                    "0823a8a79c28a755a73a4fada7cdad306bc1ee99",
                    false
                );

                var x = Configuration.GetConnectionString("Thumbprint-Key");

                if (certCollection.Count > 0)
                {
                    cert = certCollection[0];
                }

                if (cert != null)
                {
                    builder.AddSigningCredential(cert);
                }
            }
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
