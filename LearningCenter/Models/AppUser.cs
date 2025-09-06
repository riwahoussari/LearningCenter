using Microsoft.AspNetCore.Identity;

namespace LearningCenter.Models
{
    public class AppUser : IdentityUser
    {

        // Common profile info
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;


    }
}
