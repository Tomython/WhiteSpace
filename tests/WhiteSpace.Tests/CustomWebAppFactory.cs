using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using WhiteSpace.Infrastructure;

public class CustomWebAppFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Прогоняем миграции перед тестом на реальной SQLite-файловой БД
            using var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<WhiteSpaceDbContext>();
            db.Database.EnsureDeleted(); // чистый старт на каждый запуск тестов
            db.Database.Migrate();
        });
    }
}