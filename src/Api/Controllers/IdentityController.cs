using System;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controller
{
    [Route("identity")]
    [Authorize]
    public class IdentityController : ControllerBase
    {
        public IActionResult Get() {
            Console.WriteLine(User.Claims);
            return new JsonResult(from c in User.Claims select new {c.Type, c.Value});
        }
    }
}