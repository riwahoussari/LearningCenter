namespace LearningCenter.Models.Entities
{
    public class TutorProfile
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public AppUser User { get; set; }

        // Approval
        public bool IsApproved { get; set; } = false;

        // Additional fields
        public string Bio { get; set; }
        public string Expertise { get; set; }
    }
}
