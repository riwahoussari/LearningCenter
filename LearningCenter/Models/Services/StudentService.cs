using LearningCenter.Data;
using LearningCenter.Models.Entities;

namespace LearningCenter.Models.Services
{
    public interface IStudentService
    {
        Task<StudentProfile> CreateStudentProfile(string userId, string major);
    }

    public class StudentService : IStudentService
    {
        private readonly AppDbContext _db;
        public StudentService(AppDbContext db)
        {
            _db = db;
        }

        public async Task<StudentProfile> CreateStudentProfile(string userId, string major)
        {
            var studentProfile = new StudentProfile
            {
                UserId = userId,
                Major = major
            };

            _db.StudentProfiles.Add(studentProfile);
            await _db.SaveChangesAsync();

            return studentProfile;
        }

    }

}
