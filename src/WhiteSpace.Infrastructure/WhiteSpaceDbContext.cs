using Microsoft.EntityFrameworkCore;
using WhiteSpace.Domain;

namespace WhiteSpace.Infrastructure;

public class WhiteSpaceDbContext : DbContext
{
    public WhiteSpaceDbContext(DbContextOptions<WhiteSpaceDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Post> Posts => Set<Post>();             // ← ДОБАВИЛИ
    public DbSet<Channel> Channels => Set<Channel>();
    public DbSet<ChannelMember> ChannelMembers => Set<ChannelMember>();
    public DbSet<Comment> Comments => Set<Comment>();
    public DbSet<Like> Likes => Set<Like>();
    public DbSet<Follow> Follows => Set<Follow>();

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
      e.HasIndex(x => x.ChannelId);
    });

    b.Entity<Channel>(e =>
    {
      e.Property(x => x.Name).HasMaxLength(64).IsRequired();
      e.Property(x => x.Code).HasMaxLength(24);
      e.HasIndex(x => x.Code).IsUnique();
    });

    b.Entity<ChannelMember>(e =>
    {
      e.HasKey(x => new { x.ChannelId, x.UserId });
      e.Property(x => x.Role).HasMaxLength(16);
    });

    b.Entity<Comment>(e =>
    {
      e.Property(x => x.Body).HasMaxLength(1000).IsRequired();
      e.HasIndex(x => new { x.PostId, x.CreatedAt });
      // (не обязательно, но полезно) FK-ограничения без навигаций:
      e.HasOne<User>().WithMany().HasForeignKey(x => x.AuthorId).OnDelete(DeleteBehavior.Restrict);
      e.HasOne<Post>().WithMany().HasForeignKey(x => x.PostId).OnDelete(DeleteBehavior.Cascade);
    });

    b.Entity<Like>(e =>
    {
      e.HasKey(x => new { x.PostId, x.UserId }); // уникальный лайк на пост от юзера
      e.HasIndex(x => x.PostId);
      e.HasOne<Post>().WithMany().HasForeignKey(x => x.PostId).OnDelete(DeleteBehavior.Cascade);
      e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
    });

    b.Entity<Follow>(e =>
    {
        e.HasKey(x => new { x.FollowerId, x.FolloweeId });
        e.HasOne<User>().WithMany().HasForeignKey(x => x.FollowerId).OnDelete(DeleteBehavior.Cascade);
        e.HasOne<User>().WithMany().HasForeignKey(x => x.FolloweeId).OnDelete(DeleteBehavior.Cascade);
        e.HasIndex(x => x.FolloweeId);
    });
  }
}
