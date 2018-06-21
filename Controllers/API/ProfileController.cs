using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using JWT.Models.Data;
using JWT.Models.ViewModels;
using JWT.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace JWT.Controllers.Profile
{
    [Route("api/[controller]")]
    public class ProfileController : Controller
    {
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpPost("login")]
        public JsonResult ProfileDetails()
        {
            var List = new List<string> () {"test", "test2", "test3"};
           return Json(List);
        }
    }
}