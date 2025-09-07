using LearningCenter.Data;
using Microsoft.EntityFrameworkCore;
using LearningCenter.Models.Entities;
using LearningCenter.Models.Entities.Auth;
using System.Security.Cryptography;

namespace LearningCenter.Models.Services
{
    public interface IRefreshTokenService
    {
        Task<RefreshToken> 
            CreateAsync(AppUser user);
        Task<RefreshToken?> GetAsync(string token, bool includeUser = false);
        Task RevokeAsync(string token);
    }

    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly AppDbContext _db;

        public RefreshTokenService(AppDbContext db)
        {
            _db = db;
        }

        public async Task<RefreshToken> CreateAsync(AppUser user)
        {
            var refreshToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                UserId = user.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(7) // configurable
            };

            _db.RefreshTokens.Add(refreshToken);
            await _db.SaveChangesAsync();
            return refreshToken;
        }

        public async Task<RefreshToken?> GetAsync(string token, bool includeUser = false)
        {
            if (includeUser)
            {
                return await _db.RefreshTokens
                    .Include(r => r.User)
                    .FirstOrDefaultAsync(r => r.Token == token);
            }
            return await _db.RefreshTokens.FirstOrDefaultAsync(r => r.Token == token);
        }

        public async Task RevokeAsync(string token)
        {
            var storedToken = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.Token == token);
            if (storedToken != null && storedToken.IsActive)
            {
                storedToken.RevokedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }
        }
    }

}
