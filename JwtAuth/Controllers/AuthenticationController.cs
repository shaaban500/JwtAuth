using JwtAuth.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        public AuthenticationController(JwtConfig jwtConfig, UserManager<IdentityUser> userManager)
        {
            _jwtConfig = jwtConfig;
            _userManager = userManager;
        }

    }
}
