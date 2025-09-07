namespace LearningCenter.Models.DTOs
{
    public class AdminDto : UserDto
    {
        public string Username { get; set; }
    }

    public class StudentDto : UserDto
    {
        public int ProfileId { get; set; }
        public string Major { get; set; }
    }

    public class TutorDto : UserDto
    {
        public int ProfileId { get; set; }
        public string Bio { get; set; }
        public string Expertise { get; set; }
        public bool IsApproved { get; set; }
    }

    public class UserDto
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
    }
}
