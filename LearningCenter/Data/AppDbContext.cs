using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Data
{
    public class AppDbContext : DbContext
    {
        protected readonly IConfiguration _config;

        public AppDbContext(IConfiguration config)
        {
            _config = config;
        }

        protected override void OnConfiguring (DbContextOptionsBuilder options)
        {
            options.UseNpgsql(_config.GetConnectionString("WebApiDb"));
        }


        public DbSet<TestTable> TestTables { get; set; }
    }
}
