namespace LearningCenter.Models.Entities
{
    public class StudentProfile
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public AppUser User { get; set; }

        // Additional fields
        public DateTime EnrollmentDate { get; set; } = DateTime.UtcNow;
        public string Major { get; set; }
    }
}
