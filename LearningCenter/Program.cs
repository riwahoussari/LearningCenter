using LearningCenter.Data;
using LearningCenter.Models.Constants;
using LearningCenter.Models.Entities;
using LearningCenter.Models.Services;
using LearningCenter.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Services
// Email Sender
builder.Services.AddScoped<IEmailSender, ConsoleEmailSender>();
// User Profile Services
builder.Services.AddScoped<ITutorService, TutorService>();
builder.Services.AddScoped<IStudentService, StudentService>();
// seeding services
builder.Services.AddScoped<RoleSeedService>();
builder.Services.AddScoped<AdminSeedService>();
// Refresh Token Service
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();


// Db Context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(
        builder.Configuration.GetConnectionString("WebApiDb")
    )
);

// Identity
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
                    {
                        options.SignIn.RequireConfirmedEmail = true;
                        options.User.RequireUniqueEmail = true;
                    }
                 )
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();


// JWT configuration
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]!);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});


builder.Services.AddControllers();

var app = builder.Build();

// Seed roles and admin user on startup
using (var scope = app.Services.CreateScope())
{
    try
    {
        // Seed roles first
        var roleSeeder = scope.ServiceProvider.GetRequiredService<RoleSeedService>();
        await roleSeeder.SeedRolesAsync();

        // Then seed admin user
        var adminSeeder = scope.ServiceProvider.GetRequiredService<AdminSeedService>();
        await adminSeeder.SeedAdminAsync();
    }
    catch (Exception ex)
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding data");
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
