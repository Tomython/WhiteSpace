using Microsoft.EntityFrameworkCore;
using WhiteSpace.Infrastructure;
using WhiteSpace.Domain;

var b = WebApplication.CreateBuilder(args);
b.Services.AddDbContext<WhiteSpaceDbContext>(opt =>
    opt.UseSqlite(b.Configuration.GetConnectionString("Default") 
                  ?? "Data Source=./whitespace-dev.db"));
var app = b.Build();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/users/seed", async (WhiteSpaceDbContext db) => {
  if (!db.Users.Any()) { db.Users.Add(new User{ Username="alice", Email="alice@example.com"}); await db.SaveChangesAsync(); }
  return Results.Ok(new { ok = true });
});
app.MapGet("/users", async (WhiteSpaceDbContext db) => Results.Ok(await db.Users.OrderBy(x=>x.CreatedAt).ToListAsync()));

app.Run();
