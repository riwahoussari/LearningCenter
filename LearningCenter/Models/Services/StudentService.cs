using LearningCenter.Data;
using LearningCenter.Models.Constants;
using LearningCenter.Models.DTOs;
using LearningCenter.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Models.Services
{
    public interface IStudentService
    {
        Task<StudentProfile> CreateStudentProfile(string userId, string major);
        Task<StudentProfile> GetStudentByUserIdAsync(string userId);
        Task<List<StudentDto>> GetAllStudents();
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

        public async Task<StudentProfile> GetStudentByUserIdAsync(string userId)
        {
            return await _db.StudentProfiles.FirstOrDefaultAsync(t => t.UserId == userId);
        }

        public async Task<List<StudentDto>> GetAllStudents()
        {
            return await _db.StudentProfiles.Include(p => p.User).Select(p => new StudentDto
            {
                ProfileId = p.Id,
                Major = p.Major,
                Id = p.User.Id,
                FirstName = p.User.FirstName,
                LastName = p.User.LastName,
                Email = p.User.Email,
                CreatedAt = p.User.CreatedAt,
                Role = RoleConstants.Student
            }).ToListAsync();
        }
    }

}
