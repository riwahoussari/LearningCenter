using LearningCenter.Data;
using LearningCenter.Models.Constants;
using LearningCenter.Models.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace LearningCenter.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly ITutorService _tutorService;
        public AdminController(ITutorService tutorService)
        {
            _tutorService = tutorService;
        }

        // routes

        [Authorize(Roles = RoleConstants.Admin)]
        [HttpPost("approve-tutor/{tutorUserId}")]
        public async Task<IActionResult> ApproveTutor(string tutorUserId)
        {
            try
            {
                await _tutorService.ApproveTutorAsync(tutorUserId);
                return Ok("Tutor approved successfully.");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }


    }
}
