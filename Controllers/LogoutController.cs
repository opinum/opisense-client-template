using Microsoft.AspNetCore.Mvc;

namespace OpisenseClientTemplate.Controllers
{
    [Route("app/[Controller]")]
    public class LogoutController : Controller
    {
        [HttpPost("")]
        public IActionResult Logout()
        {
            return new SignOutResult(new[] { "oidc", "Cookies" });
        }
    }
}
