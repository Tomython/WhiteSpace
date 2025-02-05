using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace MinimalWebServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseUrls("http://*:5000");
                    webBuilder.Configure(app =>
                    {
                        app.UseDefaultFiles();
                        app.UseStaticFiles(); // Эта строка для обслуживания статичных файлов (например, index.html)
                    });
                });
    }
}
