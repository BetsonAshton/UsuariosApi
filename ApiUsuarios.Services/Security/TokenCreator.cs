using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiUsuarios.Services.Security
{
    public class TokenCreator
    {
        /// <summary>
        /// Armazenar o tempo de validade do token em horas
        /// </summary>
        private const int _expirationInHours = 6;

        /// <summary>
        /// Armazenar a chave secreta antifalsificação do token
        /// </summary>
        public const string? SecretKey = "70BADF66-3A09-4C9F-832A-F56DFC7398B9";        

        /// <summary>
        /// Método para gerar o token
        /// </summary>
        public string? GenerateToken(string? emailUsuario)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(SecretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                //gravando o email do usuário (identificação do usuário) dentro do token
                Subject = new ClaimsIdentity(new Claim[] { new Claim(ClaimTypes.Name, emailUsuario) }),

                //definindo o tempo de validade para expiração do token
                Expires = DateTime.UtcNow.AddHours(_expirationInHours),

                //gravando a chave secreta antifalsificação
                SigningCredentials = new SigningCredentials
                    (new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            //gerar e retornar o token:
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
