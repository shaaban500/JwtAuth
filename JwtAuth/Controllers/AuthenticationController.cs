using JwtAuth.Configurations;
using JwtAuth.DTOs;
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


        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterationRequestDto requestDto)
        {
            // validate incoming request
            if(ModelState.IsValid)
            {
                var userExist = await _userManager.FindByEmailAsync(requestDto.Email);
                
                if(userExist != null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Email is already exist"
                        }
                    });
                }

                // create a new user
                var newUser = new IdentityUser()
                {
                    Email = requestDto.Email,
                    UserName = requestDto.Email
                };


                var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);

                if(isCreated.Succeeded)
                {
                    // Generate the token
                }

                return BadRequest(new AuthResult() 
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Server Error"
                    }
                });

            }
            return BadRequest();
        }





        // Generate token
        private string GenerateJwtToken(IdentityUser user)
        {
            return "";
        }


    }
}
