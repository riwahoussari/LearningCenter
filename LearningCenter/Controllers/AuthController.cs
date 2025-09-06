using LearningCenter.Models;
using LearningCenter.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LearningCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly IEmailSender _emailSender;

        public AuthController(
            UserManager<AppUser> userManager, 
            SignInManager<AppUser> signInManager, 
            IConfiguration config,
            IEmailSender emailSender
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _config = config;
            _emailSender = emailSender;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var user = new AppUser
            {
                UserName = dto.Email,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await SendEmailConfirmationEmail(user);

            return Ok("User registered successfully. Please check your email to confirm your account.");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest("Invalid user ID");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
                return Ok("Email confirmed successfully!");

            return BadRequest("Email confirmation failed.");
        }

        [HttpPost("resend-email-confirmation")]
        public async Task<IActionResult> ResendConfirmation([FromBody] ResendConfirmationDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user != null && await _userManager.IsEmailConfirmedAsync(user) == false)
                await SendEmailConfirmationEmail(user);

            // return generic message so attackers can’t know if an email is registered
            return Ok("If this email is not confirmed, we sent a new confirmation link");

            // should add rate limiting to prevent spamming someone's inbox
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null) return Unauthorized("Invalid credentials");

            // verify password
            if (await _userManager.CheckPasswordAsync(user, dto.Password) == false)
                return Unauthorized("Invalid credentials");

            // don't login if email is not verified
            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized("Email not confirmed. Please check your inbox.");

            // now use SignInManager for other security features
            var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
            if (!result.Succeeded) return Unauthorized("Invalid credentials");

            
            var token = GenerateJwtToken(user);
            return Ok(new { Token = token });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Ok("User logged out");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);

            // Always return success to prevent email enumeration
            // Don't reveal whether the email exists or not
            if (user != null && await _userManager.IsEmailConfirmedAsync(user))
            {
                await SendPasswordResetEmail(user);
            }

            return Ok("If your email is registered and confirmed, you will receive a password reset link.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return BadRequest("Invalid request");

            var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);

            if (result.Succeeded)
                return Ok("Password reset successfully");

            return BadRequest(result.Errors);
        }

        // Helper functions
        private string GenerateJwtToken(AppUser user)
        {
            var jwtSettings = _config.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName)
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpireMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task SendEmailConfirmationEmail(AppUser user)
        {
            // Generate email confirmation token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Build verification link
            var confirmationLink = Url.Action(
                nameof(ConfirmEmail),
                "Auth",
                new { userId = user.Id, token },
                Request.Scheme);

            // Send email
            await _emailSender.SendEmailAsync(user.Email, "Confirm your email", $"Please confirm your account by clicking this link: {confirmationLink}");
        }

        private async Task SendPasswordResetEmail(AppUser user)
        {
            // Generate password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Build password reset link
            var resetLink = Url.Action(
                nameof(ResetPassword), 
                "Auth", 
                 new { email = user.Email, token }, 
                 Request.Scheme);

            await _emailSender.SendEmailAsync(user.Email, "Reset Your Password", $"Reset your password by clicking this link (this will take a page with a reset password form but that doesn't exist right now so just copy the token and use it in the reset-password post request): \n {resetLink} \n\n Token: {token}");
        }

    }

    // DTOs
    public class RegisterDto
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class ResendConfirmationDto
    {
        public string Email { get; set; }
    }

    public class ForgotPasswordDto
    {
        public string Email { get; set; }
    }

    public class ResetPasswordDto
    {
        public string Email { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }
}
