using Microsoft.AspNetCore.Mvc;

namespace YourSubsystem.Controllers.Web;

/// <summary>
/// OPTIONAL: SessionExpired action for HomeController.
/// Merge this action into your existing HomeController, or create a new HomeController if one doesn't exist.
/// </summary>
[Route("[controller]")]
public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Displays the session expired view when access token is missing or refresh fails.
    /// This action is referenced by the AccessTokenValidationMiddleware.
    /// </summary>
    [HttpGet("SessionExpired")]
    public IActionResult SessionExpired()
    {
        return View();
    }
}
