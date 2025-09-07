using LearningCenter.Models.Constants;
using LearningCenter.Models.DTOs;
using LearningCenter.Models.Entities;
using Microsoft.AspNetCore.Identity;
using System.Data;

namespace LearningCenter.Models.Services
{
    public interface IUserService
    {
        Task<List<AdminDto>> GetAllAdmins();
        Task<string?> GetUserRoleAsync(AppUser user);
    }

    public class UserService : IUserService
    {
        private readonly UserManager<AppUser> _userManager;

        public UserService(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<List<AdminDto>> GetAllAdmins()
        {
            var admins = await _userManager.GetUsersInRoleAsync(RoleConstants.Admin);
            var adminDtos = admins.Select(u => new AdminDto
            {
                Username = u.UserName,
                Id = u.Id,
                FirstName = u.FirstName,
                LastName = u.LastName,
                Email = u.Email,
                CreatedAt = u.CreatedAt,
                Role = RoleConstants.Admin
            }).ToList();

            return adminDtos;
        }

        public async Task<string?> GetUserRoleAsync(AppUser user)
        {
            if (user == null) return null;

            var roles = await _userManager.GetRolesAsync(user);

            if (!roles.Any()) return null;

            if (roles.Contains(RoleConstants.Admin))
                return RoleConstants.Admin;

            if (roles.Contains(RoleConstants.Tutor))
                return RoleConstants.Tutor;

            if (roles.Contains(RoleConstants.Student))
                return RoleConstants.Student;

            return null;
        }
    }
}
