using LearningCenter.Models.Constants;
using Microsoft.AspNetCore.Identity;

namespace LearningCenter.Services
{
    public class RoleSeedService
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleSeedService(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        public async Task SeedRolesAsync()
        {
            string[] roles = { RoleConstants.Admin, RoleConstants.Tutor, RoleConstants.Student };

            foreach (var role in roles)
            {
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    await _roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }
    }
}
