using Microsoft.AspNetCore.Identity;

namespace LearningCenter.Models.Entities
{
    public class AppUser : IdentityUser
    {

        // Common profile info
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;


        // Profile Navigation Links
        public StudentProfile StudentProfile { get; set; }
        public TutorProfile TutorProfile { get; set; }

    }
}
