using LearningCenter.Data;
using LearningCenter.Models.Entities;

namespace LearningCenter.Services
{
    public interface IProfileMapper
    {
        bool CanHandle(AppUser user);
        object? MapProfile(AppUser user);
    }

    public class StudentProfileMapper : IProfileMapper
    {
        private readonly AppDbContext _db;
        public StudentProfileMapper(AppDbContext db) => _db = db;

        public bool CanHandle(AppUser user) =>
            _db.StudentProfiles.Any(p => p.UserId == user.Id);

        public object? MapProfile(AppUser user) =>
            _db.StudentProfiles
                .Where(p => p.UserId == user.Id)
                .Select(p => new {
                    p.EnrollmentDate,
                    p.Major
                })
                .FirstOrDefault();
    }

    public class TutorProfileMapper : IProfileMapper
    {
        private readonly AppDbContext _context;
        public TutorProfileMapper(AppDbContext context) => _context = context;

        public bool CanHandle(AppUser user) =>
            _context.TutorProfiles.Any(p => p.UserId == user.Id);

        public object? MapProfile(AppUser user) =>
            _context.TutorProfiles
                .Where(p => p.UserId == user.Id)
                .Select(p => new {
                    p.IsApproved,
                    p.Bio,
                    p.Expertise
                })
                .FirstOrDefault();
    }
}
