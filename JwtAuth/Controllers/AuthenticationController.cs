using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuth.DTOs;
using JwtAuth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;
        private readonly TokenValidationParameters _tokenValidationParameters;
        public AuthenticationController(UserManager<IdentityUser> userManager, IConfiguration configuration,
            AppDbContext context, TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
            _tokenValidationParameters = tokenValidationParameters;
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
                    var result = await GenerateJwtToken(newUser);
                    return Ok(result);
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


				var result = await GenerateJwtToken(user);
                return Ok(result);
			}

            return BadRequest();
        }



        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if(ModelState.IsValid)
            {
                var result = await VerifyAndGenerateToken(tokenRequest);

                if(result == null)
                    return BadRequest(new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } });

                return Ok(result);

            }

            return BadRequest(new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } });
        }





        // Generate token
        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
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

                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);


            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                Token = RandomStringGeneration(20),
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                IsRevoked = false,
                IsUsed = false,
                UserId = user.Id
            };

            await _context.RefershTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();


            return new AuthResult()
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                Result = true
            };

        }


        // Generate random string to be the refresh token
        private string RandomStringGeneration(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz*-+)(&^%$#@!~";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }




        // verify token request
        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                _tokenValidationParameters.ValidateLifetime = false; // for test

                var tokenVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256);

                    if (result == false)
                        return null;
                }

                var utcExpiryDate = long.Parse(tokenVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampDateTime(utcExpiryDate);
                if(expiryDate > DateTime.Now)
                {
                    return new AuthResult() { Result = false, Errors = new List<string>() { "Expired token" } };
                }

                var storedToken = await _context.RefershTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if(storedToken == null)
                    return new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } };

                if(storedToken.IsUsed)
                    return new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } };

                if (storedToken.IsRevoked)
                    return new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } };

                var jti = tokenVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
                if(storedToken.JwtId != jti)
                    return new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } };

                if(storedToken.ExpiryDate < DateTime.UtcNow)
                    return new AuthResult() { Result = false, Errors = new List<string>() { "Invalid token" } };

                storedToken.IsUsed = true;
                _context.RefershTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser);

            }
            catch (Exception e)
            {
                return new AuthResult() { Result = false, Errors = new List<string>() { "Server Error" } };
            }
        }

        private DateTime UnixTimeStampDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }
    }
}
