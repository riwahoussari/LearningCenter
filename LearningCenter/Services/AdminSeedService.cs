using LearningCenter.Models.Constants;
using LearningCenter.Models.Entities;
using Microsoft.AspNetCore.Identity;

namespace LearningCenter.Services
{
    public class AdminSeedService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AdminSeedService(
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task SeedAdminAsync()
        {
            Console.WriteLine("\n\n Admin Seeding Service Running \n\n");
            // Check if superadmin already exists
            var existingAdmin = await _userManager.FindByNameAsync("superadmin");

            if (existingAdmin != null)
                return; // Admin already exists

            
            // Get admin credentials from configuration
            var adminEmail = _configuration["SuperAdmin:Email"];
            var adminPassword = _configuration["SuperAdmin:Password"];
            var adminFirstName = _configuration["SuperAdmin:FirstName"];
            var adminLastName = _configuration["SuperAdmin:LastName"];

            if (string.IsNullOrEmpty(adminEmail) || string.IsNullOrEmpty(adminPassword))
            {
                throw new InvalidOperationException("SuperAdmin credentials not found in configuration");
            }

            // Create the superadmin user
            var adminUser = new AppUser
            {
                UserName = "superadmin",
                Email = adminEmail,
                FirstName = adminFirstName ?? "anonymous",
                LastName = adminLastName ?? "anonymous",
                EmailConfirmed = true // Auto-confirm email
            };

            var result = await _userManager.CreateAsync(adminUser, adminPassword);

            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Failed to create admin user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }

            // Add admin role
            await _userManager.AddToRoleAsync(adminUser, RoleConstants.Admin);
        }
    }
}
