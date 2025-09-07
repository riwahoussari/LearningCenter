using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace LearningCenter.Models.Entities
{
    public class AppUser : IdentityUser
    {

        // Common profile info
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTimeOffset DateJoined { get; set; } = DateTimeOffset.UtcNow;

    }
}
