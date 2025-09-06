using LearningCenter.Data;
using LearningCenter.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Models.Services
{
    public interface ITutorService
    {
        Task<TutorProfile> CreateTutorProfile(string userId, string bio, string expertise);
        Task<TutorProfile> GetTutorByUserIdAsync(string userId);
        Task ApproveTutorAsync(string tutorUserId);
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
 
    }

}
