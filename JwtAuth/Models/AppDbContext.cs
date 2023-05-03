using JwtAuth.DTOs;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JwtAuth.Models
{
    public class AppDbContext : IdentityDbContext
    {
        public DbSet<RefreshToken> RefershTokens { get; set; }
        public AppDbContext(DbContextOptions<AppDbContext> options): base(options)
        {

        }
    }
}
