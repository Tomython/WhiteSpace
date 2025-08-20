using Microsoft.EntityFrameworkCore;
using WhiteSpace.Domain;

public class WhiteSpaceDbContext(DbContextOptions<WhiteSpaceDbContext> o): DbContext(o) {
  public DbSet<User> Users => Set<User>();
  protected override void OnModelCreating(ModelBuilder b) {
    b.Entity<User>(e => {
      e.HasIndex(x => x.Username).IsUnique();
      e.HasIndex(x => x.Email).IsUnique();
      e.Property(x => x.Username).HasMaxLength(32).IsRequired();
      e.Property(x => x.Email).HasMaxLength(256).IsRequired();
    });
  }
}
