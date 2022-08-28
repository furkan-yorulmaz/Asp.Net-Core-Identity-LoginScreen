using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LoginApp.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        public IActionResult List()
        {
            return View();
        }
    }
}
