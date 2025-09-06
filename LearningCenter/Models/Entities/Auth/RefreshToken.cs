using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace LearningCenter.Models.Entities.Auth
{
    public class RefreshToken
    {
        [Key]
        public Guid Id { get; set; }

        public string Token { get; set; } = string.Empty;

        public string UserId { get; set; } = string.Empty;
        public AppUser User { get; set; }

        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? RevokedAt { get; set; }

        [NotMapped]
        public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
        [NotMapped]
        public bool IsActive => RevokedAt == null && !IsExpired;
    }
}
