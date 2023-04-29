using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuth.Configurations;
using JwtAuth.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }


        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto registerDto)
        {
            // validate incoming request
            if(ModelState.IsValid)
            {
                var userExist = await _userManager.FindByEmailAsync(registerDto.Email);
                
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
                    Email = registerDto.Email,
                    UserName = registerDto.Email
                };


                var isCreated = await _userManager.CreateAsync(newUser, registerDto.Password);

                if(isCreated.Succeeded)
                {
                    // Generate the token
                    var token = GenerateJwtToken(newUser);

                    return Ok(new AuthResult()
                    {
                        Result = true,
                        Token = token
                    });
                }


                return BadRequest(new AuthResult() 
                {
                    Result = false,
					Errors = isCreated.Errors.Select(e => e.Description).ToList()
				});

            }

            return BadRequest();
        }



        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginDto)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginDto.Email);

                if (user == null)
                    return BadRequest();


                var isCorrectPassword = await _userManager.CheckPasswordAsync(user, loginDto.Password);

                if (!isCorrectPassword)
                    return BadRequest();


				var token = GenerateJwtToken(user);

				return Ok(new AuthResult()
				{
					Result = true,
					Token = token
				});

			}

            return BadRequest();
        }




        // Generate token
        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);

            // Token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new []
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
					new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())

				}),

                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }


    }
}
