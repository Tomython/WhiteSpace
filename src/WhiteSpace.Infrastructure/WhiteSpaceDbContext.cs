using Microsoft.EntityFrameworkCore;
using WhiteSpace.Domain;

namespace WhiteSpace.Infrastructure;

public class WhiteSpaceDbContext : DbContext
{
    public WhiteSpaceDbContext(DbContextOptions<WhiteSpaceDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Post> Posts => Set<Post>();             // ← ДОБАВИЛИ

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasIndex(x => x.Username).IsUnique();
            e.HasIndex(x => x.Email).IsUnique();
            e.Property(x => x.Username).HasMaxLength(32).IsRequired();
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();
            e.Property(x => x.PasswordHash).IsRequired();
        });

        b.Entity<Post>(e =>                               // ← ДОБАВИЛИ
        {
            e.Property(x => x.Body).HasMaxLength(4000).IsRequired();
            e.HasIndex(x => x.CreatedAt);
        });
    }
}
