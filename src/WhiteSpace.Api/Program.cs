// Program.cs — FIXED

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WhiteSpace.Domain;
using WhiteSpace.Infrastructure;

// ---- services ----
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<WhiteSpaceDbContext>(opt =>
    opt.UseSqlite(builder.Configuration.GetConnectionString("Default")
                   ?? "Data Source=./whitespace-dev.db"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        var key = Encoding.UTF8.GetBytes(builder.Configuration["Auth:JwtKey"]!);
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Auth:JwtIssuer"],
            ValidAudience = builder.Configuration["Auth:JwtAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// ---- endpoints ----
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/auth/register", async (RegisterRequest req, WhiteSpaceDbContext db) =>
{
    var exists = await db.Users.AnyAsync(u => u.Username == req.Username || u.Email == req.Email);
    if (exists) return Results.Conflict(new { message = "User exists" });

    var user = new User
    {
        Username = req.Username,
        Email = req.Email,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password)
    };
    db.Users.Add(user);
    await db.SaveChangesAsync();

    var token = JwtHelper.CreateToken(user, app.Configuration);
    return Results.Ok(new { token, username = user.Username });
})
.WithTags("Auth");

app.MapPost("/auth/login", async (LoginRequest req, WhiteSpaceDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u =>
        u.Username == req.UsernameOrEmail || u.Email == req.UsernameOrEmail);
    if (user is null) return Results.Unauthorized();
    if (!BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash)) return Results.Unauthorized();

    var token = JwtHelper.CreateToken(user, app.Configuration);
    return Results.Ok(new { token, username = user.Username });
})
.WithTags("Auth");

app.MapPost("/posts", async (PostCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var userIdStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userIdStr)) return Results.Unauthorized();

    if (string.IsNullOrWhiteSpace(req.Body) || req.Body.Length > 4000)
        return Results.BadRequest(new { message = "Body length 1..4000 required" });

    var post = new Post { AuthorId = Guid.Parse(userIdStr), Body = req.Body };
    db.Posts.Add(post);
    await db.SaveChangesAsync();
    return Results.Created($"/posts/{post.Id}", new { post.Id });
})
.RequireAuthorization()
.WithTags("Posts");

app.MapGet("/feed", async (WhiteSpaceDbContext db) =>
{
    var q =
        from p in db.Posts.OrderByDescending(x => x.CreatedAt).Take(50)
        join u in db.Users on p.AuthorId equals u.Id
        select new PostDto(p.Id, u.Username, p.Body, p.CreatedAt);

    var list = await q.ToListAsync();
    return Results.Ok(list);
})
.WithTags("Posts");

app.Run();

// ---- types & helpers (После app.Run!) ----

record RegisterRequest(string Username, string Email, string Password);
record LoginRequest(string UsernameOrEmail, string Password);
record PostCreate(string Body);
record PostDto(Guid Id, string Author, string Body, DateTime CreatedAt);

static class JwtHelper
{
    public static string CreateToken(User user, IConfiguration config)
    {
        var issuer = config["Auth:JwtIssuer"]!;
        var audience = config["Auth:JwtAudience"]!;
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Auth:JwtKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username)
        };

        var jwt = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddDays(7),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
