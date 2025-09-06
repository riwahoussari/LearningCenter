using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        { }

    }
}
