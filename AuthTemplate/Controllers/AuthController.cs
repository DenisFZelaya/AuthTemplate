using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthTemplate.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // GET: api/<AuthController>
        [HttpGet]
        [Authorize(Roles = "SUPER,TEST")]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<AuthController>/5
        [HttpGet("{id}")]
        [Authorize(Policy = "AdminPolicy")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<AuthController>
        [HttpPost("login")]
        
        public IActionResult Login([FromBody] LoginRequest model)
        {
            // Aquí deberías autenticar al usuario, verificar credenciales, etc.
            // Por simplicidad, asumiremos que el usuario es autenticado correctamente.

            // Simulación de autenticación (reemplaza esto con tu lógica real de autenticación):
            bool isAuthenticated = true;

            if (isAuthenticated)
            {
                // Generar token JWT
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes("SECRET_KEY_THAT_IS_AT_LEAST_32_CHARACTERS");


                var tokenDescriptor = new SecurityTokenDescriptor
                {
                   
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim(ClaimTypes.Name, "dfz"),
                    new Claim(ClaimTypes.Role, "ADMIN"),
                    new Claim(ClaimTypes.Role, "SUPER"),
                        // Puedes agregar más claims según sea necesario
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return Ok(new { Token = tokenString });
            }
            else
            {
                return Unauthorized("Credenciales inválidas");
            }
        }

        // PUT api/<AuthController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<AuthController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}

public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}