using LearningCenter.Data;
using LearningCenter.Models.Constants;
using LearningCenter.Models.DTOs;
using LearningCenter.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Models.Services
{
    public interface ITutorService
    {
        Task<TutorProfile> CreateTutorProfile(string userId, string bio, string expertise);
        Task<TutorProfile> GetTutorByUserIdAsync(string userId);
        Task ApproveTutorAsync(string tutorUserId);
        Task<List<TutorDto>> GetAllTutors();
    }

    public class TutorService : ITutorService
    {
        private readonly AppDbContext _db;
        public TutorService(AppDbContext db) => _db = db;

        public async Task<TutorProfile> CreateTutorProfile(string userId, string bio, string expertise)
        {
            var tutorProfile = new TutorProfile
            {
                UserId = userId,
                Bio = bio,
                Expertise = expertise
            };

            _db.TutorProfiles.Add(tutorProfile);
            await _db.SaveChangesAsync();

            return tutorProfile;
        }
        public async Task<TutorProfile> GetTutorByUserIdAsync(string userId)
        {
            return await _db.TutorProfiles.FirstOrDefaultAsync(t => t.UserId == userId);
        }

        public async Task ApproveTutorAsync(string tutorUserId)
        {
            var tutor = await _db.TutorProfiles.FirstOrDefaultAsync(t => t.UserId == tutorUserId);
            if (tutor == null) throw new Exception("Tutor not found");

            tutor.IsApproved = true;
            await _db.SaveChangesAsync();
        }

        public async Task<List<TutorDto>> GetAllTutors()
        {
            return await _db.TutorProfiles.Include(p => p.User).Select(p => new TutorDto
            {
                ProfileId = p.Id,
                Bio = p.Bio,
                Expertise = p.Expertise,
                IsApproved = p.IsApproved,
                Id = p.User.Id,
                FirstName = p.User.FirstName,
                LastName = p.User.LastName,
                Email = p.User.Email,
                CreatedAt = p.User.CreatedAt,
                Role = RoleConstants.Tutor
            }).ToListAsync();
        }
    }

}
