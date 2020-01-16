using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.AspNetCore;
using Serilog.Sinks.File;
using Serilog.Events;
using Serilog.Context;

namespace MWR.C3.WebController
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .Enrich.FromLogContext()
                .WriteTo.Console(
                    restrictedToMinimumLevel: LogEventLevel.Warning,
                    outputTemplate: "[{Level:u3}] [{Timestamp:yyyy-MM-dd HH:mm:ss}] [{SourceContext}] {Message:lj}{NewLine}{Exception}")
                .WriteTo.File("c3-web-api-log-.txt",
                    rollingInterval: RollingInterval.Day,
                    outputTemplate: "[{Level:u3}] [{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}] [{SourceContext}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();

            try
            {
                Log.Information("Starting web host");
                CreateWebHostBuilder(args).Build().Run();
            }
            catch (TypeInitializationException e) when (e.InnerException is DllNotFoundException)
            {
                Log.Fatal(@"Failed to load soduim library. Check if you have  Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017 and 2019 installed: https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads");
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseIISIntegration()
                .UseSerilog();
    }
}
