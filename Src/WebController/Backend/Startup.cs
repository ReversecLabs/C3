using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Swashbuckle.AspNetCore.Swagger;
using FSecure.C3.Comms;
using FSecure.C3.WebController.Models;
using FSecure.C3.WebController.Comms;
using System.Threading;

namespace FSecure.C3.WebController
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
            CheckCryptoLib();
            services.AddMvc()
                .SetCompatibilityVersion(CompatibilityVersion.Version_2_1)
                .AddJsonOptions(options => {
                    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
                    options.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
                });
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Info { Title = "C3 API", Version = "v1" });
            });
            services.Configure<DonutServiceOptions>(Configuration.GetSection("Donut"));
            services.AddTransient<IDonutService, DonutService>();
            services.AddTransient<ICustomizer, Customizer>();
            services.AddScoped<GatewayResponseProcessor>();
            services.AddDbContext<C3WebAPIContext>(options => options.UseSqlite("Data Source=C3API.db"));
            services.AddSingleton<CommandQueues, CommandQueues>();
            services.AddSingleton<GatewaysSyncService>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, Microsoft.AspNetCore.Hosting.IHostingEnvironment env)
        {

            using (var serviceScope = app.ApplicationServices.CreateScope())
            {
                var db = serviceScope.ServiceProvider.GetRequiredService<C3WebAPIContext>().Database;
                db.Migrate();
                db.EnsureCreated();
            }
            {
                var gss = app.ApplicationServices.GetRequiredService<GatewaysSyncService>();
                var ct = new CancellationTokenSource();
                gss.StartAsync(ct.Token).Wait();
            }


            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseMvc();
            app.UseSwagger();
            app.UseDefaultFiles();
            app.UseStaticFiles();
            // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.), specifying the Swagger JSON endpoint.
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "C3 Web API");
            });
        }

        private static void CheckCryptoLib()
        {
            Sodium.SodiumCore.Init();
        }
    }
}
