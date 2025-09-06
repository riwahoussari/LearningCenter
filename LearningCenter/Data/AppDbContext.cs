using LearningCenter.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        { }

        public DbSet<AppUser> Users {  get; set; }

        protected override void OnModelCreating(ModelBuilder b)
        {
            base.OnModelCreating(b);

            // Move Identity tables into "auth" schema
            b.HasDefaultSchema("lms");
            b.Entity<AppUser>().ToTable("Users", "auth");
            b.Entity<IdentityUserClaim<string>>().ToTable("UserClaims", "auth");
            b.Entity<IdentityUserLogin<string>>().ToTable("UserLogins", "auth");
            b.Entity<IdentityUserToken<string>>().ToTable("UserTokens", "auth");
            b.Entity<IdentityRole>().ToTable("Roles", "auth");
            b.Entity<IdentityRoleClaim<string>>().ToTable("RoleClaims", "auth");
            b.Entity<IdentityUserRole<string>>().ToTable("UserRoles", "auth");
    
        }

    }
}
