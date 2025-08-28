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
using System.ComponentModel.DataAnnotations;
using Microsoft.OpenApi.Models;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.AspNetCore.Server.Kestrel.Core;

// ---- services ----
var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(o =>
{
    o.ConfigureEndpointDefaults(lo => lo.Protocols = HttpProtocols.Http1);
});

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

builder.Services.AddCors(o =>
{
  o.AddPolicy("dev",  p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
  o.AddPolicy("prod", p => p.WithOrigins("https://app.yourdomain.tld")
                            .AllowAnyHeader().AllowAnyMethod());
});


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "WhiteSpace API", Version = "v1" });

    // JWT auth в Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "Вставь токен без 'Bearer '"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        { new OpenApiSecurityScheme{ Reference = new OpenApiReference{
              Type = ReferenceType.SecurityScheme, Id = "Bearer"}}, Array.Empty<string>() }
    });
});

builder.Services.AddRateLimiter(o =>
{
    // пусть отдаёт 429 вместо 503 при отказе
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    o.AddFixedWindowLimiter("api", options =>
    {
        options.PermitLimit = 300;                 // запас на всплески
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueLimit = 50;                   // очередь спасает короткие пики
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });

    o.AddFixedWindowLimiter("auth", options =>
    {
        options.PermitLimit = 30;
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueLimit = 20;
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });

    o.AddFixedWindowLimiter("join", options =>
    {
        options.PermitLimit = 60;
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueLimit = 20;
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
});


var app = builder.Build();

app.Use(async (ctx, next) =>
{
    var sw = Stopwatch.StartNew();

    // Заголовок X-Request-ID добавляем до старта ответа
    ctx.Response.OnStarting(() =>
    {
        // только если ещё не проставлен
        if (!ctx.Response.HasStarted)
        {
            ctx.Response.Headers["X-Request-ID"] = ctx.TraceIdentifier;
        }
        else
        {
            // даже если уже стартовал — OnStarting всё равно вызовется вовремя
            // (HasStarted здесь скорее перестраховка)
        }
        return Task.CompletedTask;
    });

    try
    {
        await next();
    }
    finally
    {
        sw.Stop();
        app.Logger.LogInformation("{method} {path} => {status} in {ms}ms",
            ctx.Request.Method, ctx.Request.Path, ctx.Response.StatusCode, sw.ElapsedMilliseconds);
    }
});

// prod: HSTS + HTTPS редирект
if (!app.Environment.IsDevelopment())
{
  app.UseHsts();
  app.UseHttpsRedirection();
}

// CORS
if (app.Environment.IsDevelopment()) app.UseCors("dev");
else app.UseCors("prod");

// Статика
app.UseDefaultFiles();
app.UseStaticFiles();

// Rate limiter
app.UseRateLimiter();

// AuthN/AuthZ
app.UseAuthentication();
app.UseAuthorization();

// Swagger только в dev
if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}


app.MapGet("/version", () =>
{
    var asm = typeof(Program).Assembly.GetName();
    var version = asm.Version?.ToString() ?? "unknown";
    var env = app.Environment.EnvironmentName;
    var commit = app.Configuration["Build:Commit"] ?? "n/a";
    return Results.Ok(new { name = asm.Name, version, env, commit, time = DateTime.UtcNow });
}).DisableRateLimiting();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok", time = DateTime.UtcNow }))
   .DisableRateLimiting();

app.MapGet("/healthz/db", async (WhiteSpaceDbContext db) =>
{
    try { await db.Database.ExecuteSqlRawAsync("SELECT 1"); return Results.Ok(new { db = "ok" }); }
    catch (Exception ex)
    {
        return Results.Problem(
            title: "db unavailable",
            statusCode: 503,
            extensions: new Dictionary<string, object?> { ["error"] = ex.Message } // object? !
        );
    }
}).DisableRateLimiting();


// ==== CHANNELS ====

app.MapPost("/channels", async (ChannelCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

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
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

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
.WithTags("Channels")
.RequireRateLimiting("join");

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

// создать пост в канале
app.MapPost("/channels/{id:guid}/posts", async (Guid id, PostCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
    if (ch is null) return Results.NotFound(new { message = "channel not found" });

    // приватные: нужен membership
    if (ch.IsPrivate && !await db.ChannelMembers.AnyAsync(m => m.ChannelId == id && m.UserId == userId))
        return Results.Forbid();

    var post = new Post { AuthorId = userId, Body = req.Body, ChannelId = id };
    db.Posts.Add(post);
    await db.SaveChangesAsync();
    return Results.Created($"/channels/{id}/posts/{post.Id}", new { post.Id });
})
.RequireAuthorization()
.WithTags("ChannelPosts");

// фид канала
app.MapGet("/channels/{id:guid}/feed", async (Guid id, int skip, int take, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
    if (ch is null) return Results.NotFound(new { message = "channel not found" });

    if (ch.IsPrivate)
    {
        var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
        var userId = Guid.Parse(uidStr);
        var member = await db.ChannelMembers.AnyAsync(m => m.ChannelId == id && m.UserId == userId);
        if (!member) return Results.Forbid();
    }

    take = Math.Clamp(take == 0 ? 50 : take, 1, 100);

    var q =
        from p in db.Posts.Where(p => p.ChannelId == id)
                           .OrderByDescending(x => x.CreatedAt)
                           .Skip(skip).Take(take)
        join u in db.Users on p.AuthorId equals u.Id
        select new PostDto(p.Id, u.Username, p.Body, p.CreatedAt);

    return Results.Ok(await q.ToListAsync());
})
.WithTags("ChannelPosts");

app.MapGet("/my/channels", async (ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
  var userId = Guid.Parse(uidStr);

  var q =
      from m in db.ChannelMembers.Where(m => m.UserId == userId)
      join c in db.Channels on m.ChannelId equals c.Id
      select new { c.Id, c.Name, c.IsPrivate, m.Role };

  return Results.Ok(await q.ToListAsync());
})
.RequireAuthorization()
.WithTags("Channels");

app.MapPatch("/channels/{id:guid}", async (Guid id, ChannelUpdate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
  var userId = Guid.Parse(uidStr);

  var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
  if (ch is null) return Results.NotFound(new { message = "channel not found" });
  if (ch.OwnerId != userId) return Results.Forbid();

  if (req.Name is { } name)
  {
    if (string.IsNullOrWhiteSpace(name) || name.Length > 64)
      return Results.BadRequest(new { message = "Name length 1..64 required" });
    ch.Name = name.Trim();
  }

  if (req.IsPrivate is bool priv)
  {
    ch.IsPrivate = priv;
    ch.Code = priv ? (string.IsNullOrEmpty(ch.Code) ? CodeGen.Secret(8) : ch.Code) : null;
  }

  await db.SaveChangesAsync();
  return Results.Ok(new { ch.Id, ch.Name, ch.IsPrivate, ch.Code });
})
.RequireAuthorization()
.WithTags("Channels");

app.MapPost("/channels/{id:guid}/regen-code", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
  var userId = Guid.Parse(uidStr);

  var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
  if (ch is null) return Results.NotFound(new { message = "channel not found" });
  if (ch.OwnerId != userId) return Results.Forbid();
  if (!ch.IsPrivate) return Results.BadRequest(new { message = "channel is public" });

  ch.Code = CodeGen.Secret(8);
  await db.SaveChangesAsync();
  return Results.Ok(new { ch.Id, ch.Code });
})
.RequireAuthorization()
.WithTags("Channels");

app.MapPost("/channels/{id:guid}/leave", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
  var userId = Guid.Parse(uidStr);

  var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
  if (ch is null) return Results.NotFound(new { message = "channel not found" });

  // Для простоты: владелец не может «выйти» — либо удаляй канал, либо передай владение
  if (ch.OwnerId == userId) return Results.BadRequest(new { message = "owner cannot leave; delete or transfer ownership" });

  var m = await db.ChannelMembers.FindAsync(id, userId);
  if (m is not null)
  {
    db.ChannelMembers.Remove(m);
    await db.SaveChangesAsync();
  }
  return Results.Ok(new { left = true });
})
.RequireAuthorization()
.WithTags("Channels");

app.MapDelete("/channels/{id:guid}", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
  var userId = Guid.Parse(uidStr);

  var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
  if (ch is null) return Results.NotFound(new { message = "channel not found" });
  if (ch.OwnerId != userId) return Results.Forbid();

  // ручной каскад
  var postIds = await db.Posts.Where(p => p.ChannelId == id).Select(p => p.Id).ToListAsync();
  if (postIds.Count > 0)
  {
    db.Comments.RemoveRange(db.Comments.Where(c => postIds.Contains(c.PostId)));
    db.Likes.RemoveRange(db.Likes.Where(l => postIds.Contains(l.PostId)));
    db.Posts.RemoveRange(db.Posts.Where(p => p.ChannelId == id));
  }
  db.ChannelMembers.RemoveRange(db.ChannelMembers.Where(m => m.ChannelId == id));
  db.Channels.Remove(ch);
  await db.SaveChangesAsync();

  return Results.Ok(new { deleted = true });
})
.RequireAuthorization()
.WithTags("Channels");

// ==== CHANNEL MEMBERS MGMT ====

app.MapGet("/channels/{id:guid}/members", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
    if (ch is null) return Results.NotFound(new { message = "channel not found" });

    // только участники (владалец/участник/модератор) видят список
    var isOwner = ch.OwnerId == meId;
    var membership = await db.ChannelMembers.FindAsync(id, meId);
    if (!isOwner && membership is null) return Results.Forbid();

    var q =
        from m in db.ChannelMembers.Where(x => x.ChannelId == id)
        join u in db.Users on m.UserId equals u.Id
        orderby u.Username
        select new { username = u.Username, role = m.Role };

    var list = await q.ToListAsync();
    // включим владельца в выдачу
    var ownerUser = await db.Users.FindAsync(ch.OwnerId);
    if (ownerUser != null && !list.Any(x => x.username == ownerUser.Username))
        list.Insert(0, new { username = ownerUser.Username, role = "owner" });

    return Results.Ok(list);
})
.RequireAuthorization()
.WithTags("Channels");

app.MapPost("/channels/{id:guid}/members/{username}/role", async (Guid id, string username, RoleChange req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
    if (ch is null) return Results.NotFound(new { message = "channel not found" });

    // менять роли может только владелец
    if (ch.OwnerId != meId) return Results.Forbid();

    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
    if (user is null) return Results.NotFound(new { message = "user not found" });

    if (user.Id == ch.OwnerId) return Results.BadRequest(new { message = "owner role is immutable" });

    var member = await db.ChannelMembers.FindAsync(id, user.Id);
    if (member is null) return Results.NotFound(new { message = "member not found" });

    // допускаем только mod/member
    member.Role = req.Role.ToLowerInvariant(); // "mod" или "member"
    await db.SaveChangesAsync();
    return Results.Ok(new { updated = true, username = username, role = member.Role });
})
.RequireAuthorization()
.WithTags("Channels");

app.MapDelete("/channels/{id:guid}/members/{username}", async (Guid id, string username, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var ch = await db.Channels.FirstOrDefaultAsync(c => c.Id == id);
    if (ch is null) return Results.NotFound(new { message = "channel not found" });

    var meMember = await db.ChannelMembers.FindAsync(id, meId);
    var isOwner = ch.OwnerId == meId;
    var isMod = meMember is not null && meMember.Role != "member";

    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
    if (user is null) return Results.NotFound(new { message = "user not found" });

    if (user.Id == ch.OwnerId) return Results.BadRequest(new { message = "cannot kick owner" });

    var victim = await db.ChannelMembers.FindAsync(id, user.Id);
    if (victim is null) return Results.NotFound(new { message = "member not found" });

    // правила:
    // - владелец может кикнуть любого участника (кроме владельца)
    // - модератор может кикнуть только member (не модератора и не владельца)
    // - обычный участник не может никого кикать
    if (!(isOwner || (isMod && victim.Role == "member")))
        return Results.Forbid();

    db.ChannelMembers.Remove(victim);
    await db.SaveChangesAsync();
    return Results.Ok(new { kicked = true, username = username });
})
.RequireAuthorization()
.WithTags("Channels");

// ==== COMMENTS ====

app.MapPost("/posts/{id:guid}/comments", async (Guid id, CommentCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

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
  var (ok, errors) = Validate(req);
  if (!ok) return Results.ValidationProblem(errors);

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
.WithTags("Auth")
.RequireRateLimiting("auth");

app.MapPost("/auth/login", async (LoginRequest req, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var user = await db.Users.FirstOrDefaultAsync(u =>
        u.Username == req.UsernameOrEmail || u.Email == req.UsernameOrEmail);
    if (user is null) return Results.Unauthorized();
    if (!BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash)) return Results.Unauthorized();

    var token = JwtHelper.CreateToken(user, app.Configuration);
    return Results.Ok(new { token, username = user.Username });
})
.RequireRateLimiting("login")
.WithTags("Auth");

// == posts ==

app.MapPost("/posts", async (PostCreate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var (ok, errors) = Validate(req);
  if (!ok) return Results.ValidationProblem(errors);

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

// ==== MODERATION: POSTS ====

app.MapPatch("/posts/{id:guid}", async (Guid id, PostUpdate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var post = await db.Posts.FindAsync(id);
    if (post is null) return Results.NotFound();

    // автор или владелец/модератор канала
    var canModerate = post.AuthorId == meId || (post.ChannelId != null &&
        (await db.Channels.AnyAsync(c => c.Id == post.ChannelId && c.OwnerId == meId) ||
         await db.ChannelMembers.AnyAsync(m => m.ChannelId == post.ChannelId && m.UserId == meId && m.Role != "member")));

    if (!canModerate) return Results.Forbid();

    post.Body = req.Body.Trim();
    await db.SaveChangesAsync();
    return Results.Ok(new { updated = true });
})
.RequireAuthorization()
.WithTags("Posts");

app.MapDelete("/posts/{id:guid}", async (Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var post = await db.Posts.FindAsync(id);
    if (post is null) return Results.NotFound();

    var canModerate = post.AuthorId == meId || (post.ChannelId != null &&
        (await db.Channels.AnyAsync(c => c.Id == post.ChannelId && c.OwnerId == meId) ||
         await db.ChannelMembers.AnyAsync(m => m.ChannelId == post.ChannelId && m.UserId == meId && m.Role != "member")));

    if (!canModerate) return Results.Forbid();

    // ручной каскад: комменты и лайки
    db.Comments.RemoveRange(db.Comments.Where(c => c.PostId == id));
    db.Likes.RemoveRange(db.Likes.Where(l => l.PostId == id));
    db.Posts.Remove(post);
    await db.SaveChangesAsync();
    return Results.Ok(new { deleted = true });
})
.RequireAuthorization()
.WithTags("Posts");

// ==== MODERATION: COMMENTS ====

app.MapPatch("/posts/{postId:guid}/comments/{id:guid}", async (Guid postId, Guid id, CommentUpdate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var comment = await db.Comments.FindAsync(id);
    if (comment is null || comment.PostId != postId) return Results.NotFound();

    var post = await db.Posts.FindAsync(postId);
    if (post is null) return Results.NotFound();

    var canModerate = comment.AuthorId == meId || post.AuthorId == meId || (post.ChannelId != null &&
        (await db.Channels.AnyAsync(c => c.Id == post.ChannelId && c.OwnerId == meId) ||
         await db.ChannelMembers.AnyAsync(m => m.ChannelId == post.ChannelId && m.UserId == meId && m.Role != "member")));

    if (!canModerate) return Results.Forbid();

    comment.Body = req.Body.Trim();
    await db.SaveChangesAsync();
    return Results.Ok(new { updated = true });
})
.RequireAuthorization()
.WithTags("Comments");

app.MapDelete("/posts/{postId:guid}/comments/{id:guid}", async (Guid postId, Guid id, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var comment = await db.Comments.FindAsync(id);
    if (comment is null || comment.PostId != postId) return Results.NotFound();

    var post = await db.Posts.FindAsync(postId);
    if (post is null) return Results.NotFound();

    var canModerate = comment.AuthorId == meId || post.AuthorId == meId || (post.ChannelId != null &&
        (await db.Channels.AnyAsync(c => c.Id == post.ChannelId && c.OwnerId == meId) ||
         await db.ChannelMembers.AnyAsync(m => m.ChannelId == post.ChannelId && m.UserId == meId && m.Role != "member")));

    if (!canModerate) return Results.Forbid();

    db.Comments.Remove(comment);
    await db.SaveChangesAsync();
    return Results.Ok(new { deleted = true });
})
.RequireAuthorization()
.WithTags("Comments");

// == feed ==

app.MapGet("/feed", async (int skip, int take, WhiteSpaceDbContext db) =>
{
  take = Math.Clamp(take == 0 ? 50 : take, 1, 100);
  var q =
      from p in db.Posts.OrderByDescending(x => x.CreatedAt).Skip(skip).Take(take)
      join u in db.Users on p.AuthorId equals u.Id
      select new PostDto(p.Id, u.Username, p.Body, p.CreatedAt);

  return Results.Ok(await q.ToListAsync());
})
.WithTags("Posts");

app.MapGet("/my/feed", async (int skip, int take, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    take = Math.Clamp(take == 0 ? 50 : take, 1, 100);

    var followingIds = db.Follows.Where(f => f.FollowerId == userId)
                                 .Select(f => f.FolloweeId);

    var q =
        from p in db.Posts
        where
            // общий фид: мои и тех, на кого подписан
            (p.ChannelId == null && (p.AuthorId == userId || followingIds.Contains(p.AuthorId)))
            ||
            // посты в каналах, где я участник
            (p.ChannelId != null && db.ChannelMembers.Any(m => m.UserId == userId && m.ChannelId == p.ChannelId))
        orderby p.CreatedAt descending
        select new PostDto(p.Id,
            db.Users.Where(u => u.Id == p.AuthorId).Select(u => u.Username).First(),
            p.Body, p.CreatedAt);

    var list = await q.Skip(skip).Take(take).ToListAsync();
    return Results.Ok(list);
})
.RequireAuthorization()
.WithTags("Posts");

// ==== ME / ACCOUNT ====

app.MapGet("/me", async (ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    var user = await db.Users.FindAsync(userId);
    if (user is null) return Results.Unauthorized();

    var posts = await db.Posts.CountAsync(p => p.AuthorId == userId);
    var channelsOwned = await db.Channels.CountAsync(c => c.OwnerId == userId);
    var channelsMember = await db.ChannelMembers.CountAsync(m => m.UserId == userId);

    return Results.Ok(new {
        id = user.Id, username = user.Username, email = user.Email,
        posts, channelsOwned, channelsMember
    });
})
.RequireAuthorization()
.WithTags("Users");

app.MapPatch("/me", async (UserUpdate req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    var user = await db.Users.FindAsync(userId);
    if (user is null) return Results.Unauthorized();

    if (req.Username is { } newUsername && newUsername != user.Username)
    {
        var exists = await db.Users.AnyAsync(u => u.Username == newUsername);
        if (exists) return Results.Conflict(new { message = "username taken" });
        user.Username = newUsername.Trim();
    }

    if (req.Email is { } newEmail && newEmail != user.Email)
    {
        var exists = await db.Users.AnyAsync(u => u.Email == newEmail);
        if (exists) return Results.Conflict(new { message = "email taken" });
        user.Email = newEmail.Trim();
    }

    await db.SaveChangesAsync();
    return Results.Ok(new { user.Id, user.Username, user.Email });
})
.RequireAuthorization()
.WithTags("Users");

app.MapPost("/me/change-password", async (ChangePassword req, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var (ok, errors) = Validate(req);
    if (!ok) return Results.ValidationProblem(errors);

    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var userId = Guid.Parse(uidStr);

    var user = await db.Users.FindAsync(userId);
    if (user is null) return Results.Unauthorized();

    if (!BCrypt.Net.BCrypt.Verify(req.CurrentPassword, user.PasswordHash))
        return Results.BadRequest(new { message = "current password invalid" });

    user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword);
    await db.SaveChangesAsync();
    return Results.Ok(new { updated = true });
})
.RequireAuthorization()
.WithTags("Users");

// ==== PUBLIC PROFILES ====

app.MapGet("/users/{username}", async (string username, WhiteSpaceDbContext db) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
    if (user is null) return Results.NotFound(new { message = "user not found" });

    var posts = await db.Posts.CountAsync(p => p.AuthorId == user.Id);
    var channelsOwned = await db.Channels.CountAsync(c => c.OwnerId == user.Id);

    return Results.Ok(new { username = user.Username, posts, channelsOwned });
})
.WithTags("Users");

app.MapGet("/users/{username}/posts", async (string username, int skip, int take, WhiteSpaceDbContext db) =>
{
  var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
  if (user is null) return Results.NotFound(new { message = "user not found" });

  take = Math.Clamp(take == 0 ? 50 : take, 1, 100);

  var q =
      from p in db.Posts.Where(p => p.AuthorId == user.Id)
                         .OrderByDescending(x => x.CreatedAt)
                         .Skip(skip).Take(take)
      join u in db.Users on p.AuthorId equals u.Id
      select new PostDto(p.Id, u.Username, p.Body, p.CreatedAt);

  return Results.Ok(await q.ToListAsync());
})
.WithTags("Users");

// ==== FOLLOWS ====

app.MapPost("/users/{username}/follow", async (string username, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var target = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
    if (target is null) return Results.NotFound(new { message = "user not found" });
    if (target.Id == meId) return Results.BadRequest(new { message = "cannot follow yourself" });

    var existing = await db.Follows.FindAsync(meId, target.Id);
    if (existing is null)
    {
        db.Follows.Add(new Follow { FollowerId = meId, FolloweeId = target.Id });
        await db.SaveChangesAsync();
    }
    return Results.Ok(new { following = true });
})
.RequireAuthorization()
.WithTags("Users");

app.MapDelete("/users/{username}/follow", async (string username, ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
  var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
  if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
  var meId = Guid.Parse(uidStr);

  var target = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
  if (target is null) return Results.NotFound(new { message = "user not found" });

  var existing = await db.Follows.FindAsync(meId, target.Id);
  if (existing is not null)
  {
    db.Follows.Remove(existing);
    await db.SaveChangesAsync();
  }
  return Results.Ok(new { following = false });
})
.RequireAuthorization()
.WithTags("Users");

app.MapGet("/me/following", async (ClaimsPrincipal me, WhiteSpaceDbContext db) =>
{
    var uidStr = me.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(uidStr)) return Results.Unauthorized();
    var meId = Guid.Parse(uidStr);

    var q =
        from f in db.Follows.Where(f => f.FollowerId == meId)
        join u in db.Users on f.FolloweeId equals u.Id
        select new { u.Username };

    return Results.Ok(await q.ToListAsync());
})
.RequireAuthorization()
.WithTags("Users");

app.MapGet("/users/{username}/followers", async (string username, WhiteSpaceDbContext db) =>
{
  var target = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
  if (target is null) return Results.NotFound(new { message = "user not found" });

  var q =
      from f in db.Follows.Where(f => f.FolloweeId == target.Id)
      join u in db.Users on f.FollowerId equals u.Id
      select new { u.Username };

  return Results.Ok(await q.ToListAsync());
})
.WithTags("Users");

// === SEARCH ===
app.MapGet("/search", async (string q, int skip, int take, WhiteSpaceDbContext db) =>
{
    if (string.IsNullOrWhiteSpace(q) || q.Trim().Length < 2)
        return Results.BadRequest(new { message = "q must be at least 2 chars" });

    q = q.Trim();
    skip = Math.Max(0, skip);
    take = Math.Clamp(take <= 0 ? 20 : take, 1, 50);

    var postsQ =
        from p in db.Posts.Where(p => EF.Functions.Like(p.Body, $"%{q}%"))
                          .OrderByDescending(p => p.CreatedAt)
                          .Skip(skip).Take(take)
        join u in db.Users on p.AuthorId equals u.Id
        select new PostDto(p.Id, u.Username, p.Body, p.CreatedAt);

    var posts = await postsQ.ToListAsync();

    var users = await db.Users
        .Where(u => EF.Functions.Like(u.Username, $"%{q}%"))
        .OrderBy(u => u.Username)
        .Select(u => new { u.Id, u.Username })
        .Take(20).ToListAsync();

    var channels = await db.Channels
        .Where(c => !c.IsPrivate && EF.Functions.Like(c.Name, $"%{q}%"))
        .OrderBy(c => c.Name)
        .Select(c => new { c.Id, c.Name, c.IsPrivate })
        .Take(20).ToListAsync();

    return Results.Ok(new { q, posts, users, channels });
})
.WithTags("Search");


app.Run();

public partial class Program
{  // для WebApplicationFactory

  // ---- types & helpers (После app.Run!) ----

  static (bool ok, Dictionary<string, string[]> errors) Validate<T>(T model)
  {
    var ctx = new ValidationContext(model!);
    var results = new List<ValidationResult>();
    var ok = Validator.TryValidateObject(model!, ctx, results, validateAllProperties: true);

    var errors = results
        .SelectMany(r => (r.MemberNames.Any() ? r.MemberNames : new[] { "" })
            .Select(m => (Member: m, r.ErrorMessage ?? "invalid")))
        .GroupBy(x => x.Member)
        .ToDictionary(g => g.Key, g => g.Select(x => x.Item2).ToArray());

    return (ok, errors);
  }

  record RegisterRequest(
      [property: Required, MinLength(3), MaxLength(32)]
    string Username,
      [property: Required, EmailAddress, MaxLength(256)]
    string Email,
      [property: Required, MinLength(4), MaxLength(64)]
    string Password);

  record LoginRequest(
      [property: Required] string UsernameOrEmail,
      [property: Required] string Password);

  record PostCreate([property: JsonPropertyName("body"), Required, MinLength(1), MaxLength(4000)] string Body);
  record PostDto(Guid Id, string Author, string Body, DateTime CreatedAt);

  record ChannelCreate(
      [property: JsonPropertyName("name"), Required, MinLength(1), MaxLength(64)] string Name,
      [property: JsonPropertyName("isPrivate")] bool IsPrivate);

  record JoinByCode([property: JsonPropertyName("code"), Required, MinLength(4), MaxLength(24)] string Code);

  record CommentCreate([property: JsonPropertyName("body"), Required, MinLength(1), MaxLength(1000)] string Body);

  record ChannelUpdate(string? Name, bool? IsPrivate);

  // Частичное обновление профиля (null = не менять)
  record UserUpdate(
      [property: MinLength(3), MaxLength(32)] string? Username,
      [property: EmailAddress, MaxLength(256)] string? Email);

  record ChangePassword(
      [property: Required] string CurrentPassword,
      [property: Required, MinLength(4), MaxLength(64)] string NewPassword);

  record PostUpdate([property: JsonPropertyName("body"), Required, MinLength(1), MaxLength(4000)] string Body);
  record CommentUpdate([property: JsonPropertyName("body"), Required, MinLength(1), MaxLength(1000)] string Body);

  record RoleChange(
  [property: JsonPropertyName("role"),
   Required,
   RegularExpression("^(mod|member)$", ErrorMessage = "role must be 'mod' or 'member'")]
  string Role);

  static class CodeGen
  {
    public static string Secret(int len)
    {
      const string alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
      Span<char> chars = len <= 256 ? stackalloc char[len] : new char[len];
      for (int i = 0; i < len; i++)
        chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
      return new string(chars);
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
}