// Program.cs — FIXED

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using WhiteSpace.Domain;
using WhiteSpace.Infrastructure;
using System.Text.Json.Serialization;

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

builder.Services.AddCors(opt =>
{
    opt.AddPolicy("dev", p => p
        .AllowAnyOrigin()
        .AllowAnyHeader()
        .AllowAnyMethod());
});

var app = builder.Build();

app.UseCors("dev");
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// ==== CHANNELS ====

app.MapPost("/channels", async (ChannelCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var ownerId = Guid.Parse(uidStr);

    if (string.IsNullOrWhiteSpace(req.Name) || req.Name.Length > 64)
        return Results.BadRequest(new { message = "Name length 1..64 required" });

    var ch = new Channel
    {
        Name = req.Name.Trim(),
        IsPrivate = req.IsPrivate,
        Code = req.IsPrivate ? CodeGen.Secret(8) : null,
        OwnerId = ownerId
    };

    db.Channels.Add(ch);
    db.ChannelMembers.Add(new ChannelMember { ChannelId = ch.Id, UserId = ownerId, Role = "owner" });
    await db.SaveChangesAsync();

    return Results.Ok(new { ch.Id, ch.Name, ch.IsPrivate, ch.Code });
})
.RequireAuthorization()
.WithTags("Channels");

app.MapPost("/channels/join", async (JoinByCode req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    if (string.IsNullOrWhiteSpace(req.Code))
        return Results.BadRequest(new { message = "code required" });

    var ch = await db.Channels.FirstOrDefaultAsync(c => c.Code == req.Code);
    if (ch is null) return Results.NotFound(new { message = "channel not found" });

    var already = await db.ChannelMembers.FindAsync(ch.Id, userId);
    if (already is null)
    {
        db.ChannelMembers.Add(new ChannelMember { ChannelId = ch.Id, UserId = userId, Role = "member" });
        await db.SaveChangesAsync();
    }
    return Results.Ok(new { ch.Id, ch.Name, ch.IsPrivate });
})
.RequireAuthorization()
.WithTags("Channels");

app.MapGet("/channels/{id:guid}", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  var userId = string.IsNullOrEmpty(uidStr) ? Guid.Empty : Guid.Parse(uidStr);

  var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
  if (ch is null) return Results.NotFound();

  var isMember = await db.ChannelMembers.AnyAsync(m => m.ChannelId == id && m.UserId == userId);
  return Results.Ok(new { ch.Id, ch.Name, ch.IsPrivate, isMember });
})
.RequireAuthorization()
.WithTags("Channels");

// ==== COMMENTS ====

app.MapPost("/posts/{id:guid}/comments", async (Guid id, CommentCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    if (string.IsNullOrWhiteSpace(req.Body) || req.Body.Length > 1000)
        return Results.BadRequest(new { message = "Body length 1..1000 required" });

    var post = await db.Posts.FindAsync(id);
    if (post is null) return Results.NotFound(new { message = "post not found" });

    var c = new Comment { PostId = id, AuthorId = userId, Body = req.Body.Trim() };
    db.Comments.Add(c);
    await db.SaveChangesAsync();
    return Results.Created($"/posts/{id}/comments/{c.Id}", new { c.Id });
})
.RequireAuthorization()
.WithTags("Comments");

app.MapGet("/posts/{id:guid}/comments", async (Guid id, WhiteSpaceDbContext db) =>
{
    var post = await db.Posts.FindAsync(id);
    if (post is null) return Results.NotFound();

    var q =
        from c in db.Comments.Where(x => x.PostId == id).OrderBy(x => x.CreatedAt)
        join u in db.Users on c.AuthorId equals u.Id
        select new { c.Id, author = u.Username, c.Body, c.CreatedAt };

    var list = await q.ToListAsync();
    return Results.Ok(list);
})
.WithTags("Comments");

// ==== LIKES ====

app.MapPost("/posts/{id:guid}/like", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    if (await db.Posts.FindAsync(id) is null)
        return Results.NotFound(new { message = "post not found" });

    var like = await db.Likes.FindAsync(id, userId);
    if (like is null)
    {
        db.Likes.Add(new Like { PostId = id, UserId = userId });
        await db.SaveChangesAsync();
    }
    return Results.Ok(new { liked = true });
})
.RequireAuthorization()
.WithTags("Likes");

app.MapDelete("/posts/{id:guid}/like", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    var like = await db.Likes.FindAsync(id, userId);
    if (like is not null)
    {
        db.Likes.Remove(like);
        await db.SaveChangesAsync();
    }
    return Results.Ok(new { liked = false });
})
.RequireAuthorization()
.WithTags("Likes");

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
record PostCreate([property: JsonPropertyName("body")] string Body);
record PostDto(Guid Id, string Author, string Body, DateTime CreatedAt);

record ChannelCreate([property: JsonPropertyName("name")] string Name,
                     [property: JsonPropertyName("isPrivate")] bool IsPrivate);

record JoinByCode([property: JsonPropertyName("code")] string Code);

record CommentCreate([property: JsonPropertyName("body")] string Body);

static class CodeGen
{
  public static string Secret(int len)
  {
    const string alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    var rng = Random.Shared;
    return new string(Enumerable.Range(0, len)
               .Select(_ => alphabet[rng.Next(alphabet.Length)]).ToArray());
  }
}

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
