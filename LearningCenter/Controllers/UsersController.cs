

using LearningCenter.Data;
using LearningCenter.Models.Constants;
using LearningCenter.Models.DTOs;
using LearningCenter.Models.Entities;
using LearningCenter.Models.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace LearningCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IStudentService _studentService;
        private readonly ITutorService _tutorService;
        private readonly IUserService _userService;

        public UsersController(
            UserManager<AppUser> userManager, 
            IStudentService studentService,
            ITutorService tutorService,
            IUserService userService
        )
        {
            _userManager = userManager;
            _studentService = studentService;
            _tutorService = tutorService;
            _userService = userService;
        }

        [Authorize(Roles = RoleConstants.Admin)] // admin only routes
        [HttpGet]
        public async Task<IActionResult> GetUsers([FromQuery] string? role)
        {
            if (string.IsNullOrEmpty(role))
            {
                return BadRequest("Role parameter is required");
            }

            if (string.Equals(role, RoleConstants.Admin, StringComparison.OrdinalIgnoreCase))
            {
                return Ok(await _userService.GetAllAdmins());
            }
            else if (string.Equals(role, RoleConstants.Tutor, StringComparison.OrdinalIgnoreCase))
            {
                return Ok(await _tutorService.GetAllTutors());
            }
            else if (string.Equals(role, RoleConstants.Student, StringComparison.OrdinalIgnoreCase))
            {
                return Ok(await _studentService.GetAllStudents());
            }
            else
            {
                return BadRequest($"Role '{role}' doesn't exist.");
            }
        }

        [Authorize]
        [HttpGet("{id}")]
        public async Task<IActionResult> GetUserById(string id)
        {
            // Check if user exists first
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound("User not found");

            var role = await _userService.GetUserRoleAsync(user);

            var userDto = new UserDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                DateJoined = user.DateJoined,
                Role = role
            };

            // Get current user's roles for authorization
            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var currentUserRole = await _userService.GetUserRoleAsync(currentUser);

            // Admin
            if (role == RoleConstants.Admin)
            {
                // Only admins can view admin profiles
                if (currentUserRole != RoleConstants.Admin)
                {
                    return Forbid();
                }

                var adminDto = new AdminDto
                {
                    Id = user.Id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Email = user.Email,
                    DateJoined = user.DateJoined,
                    Username = user.UserName,
                    Role = RoleConstants.Admin
                };
                return Ok(adminDto);
            }

            // Tutor
            else if (role == RoleConstants.Tutor)
            {
                // Anyone can view tutor profiles (no restriction)

                var tutorProfile = await _tutorService.GetTutorByUserIdAsync(user.Id);

                if (tutorProfile != null)
                {
                    var tutorDto = new TutorDto
                    {
                        ProfileId = tutorProfile.Id,
                        Bio = tutorProfile.Bio,
                        Expertise = tutorProfile.Expertise,
                        IsApproved = tutorProfile.IsApproved,
                        Id = user.Id,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        Email = user.Email,
                        DateJoined = user.DateJoined,
                        Role = RoleConstants.Tutor
                    };
                    return Ok(tutorDto);
                }
                return Ok(userDto);
            }

            // Student
            else if (role == RoleConstants.Student )
            {
                // Only admins and tutors can view student profiles
                if (currentUserRole != RoleConstants.Admin &&
                    currentUserRole != RoleConstants.Tutor &&
                    currentUser.Id != user.Id)
                {
                    return Forbid();
                }

                var studentProfile = await _studentService.GetStudentByUserIdAsync(user.Id);

                if (studentProfile != null)
                {
                    var studentDto = new StudentDto
                    {
                        ProfileId = studentProfile.Id,
                        Major = studentProfile.Major,
                        Id = user.Id,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        Email = user.Email,
                        DateJoined = user.DateJoined,
                        Role = RoleConstants.Student
                        
                    };
                    return Ok(studentDto);
                }
                return Ok(userDto);
            }

            return NotFound("User not found");
        }


    }
}
