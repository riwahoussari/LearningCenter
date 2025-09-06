using LearningCenter.Models.Entities;
using LearningCenter.Models.Entities.Auth;
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
        public DbSet<StudentProfile> StudentProfiles { get; set; }
        public DbSet<TutorProfile> TutorProfiles { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }


        protected override void OnModelCreating(ModelBuilder b)
        {
            base.OnModelCreating(b);

            // Move Refresh Token entity into "auth" schema
            b.Entity<RefreshToken>().ToTable("RefreshTokens", "auth");

            // Move Identity Framework tables into "auth" schema
            b.HasDefaultSchema("lms");
            b.Entity<AppUser>().ToTable("Users", "auth");
            b.Entity<IdentityUserClaim<string>>().ToTable("UserClaims", "auth");
            b.Entity<IdentityUserLogin<string>>().ToTable("UserLogins", "auth");
            b.Entity<IdentityUserToken<string>>().ToTable("UserTokens", "auth");
            b.Entity<IdentityRole>().ToTable("Roles", "auth");
            b.Entity<IdentityRoleClaim<string>>().ToTable("RoleClaims", "auth");
            b.Entity<IdentityUserRole<string>>().ToTable("UserRoles", "auth");

            // Move Profile tables to "lms" schema
            b.Entity<TutorProfile>().ToTable("TutorProfiles", "lms");
            b.Entity<StudentProfile>().ToTable("StudentProfiles", "lms");

        }

    }
}
