using HomeworkASP.Areas.Identity.Pages.Account;
using HomeworkASP.Data;
using HomeworkASP.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace HomeworkASP.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        readonly ApplicationDbContext _dbContext;
        readonly UserManager<IdentityUser> _userManager;
        readonly SignInManager<IdentityUser> _signInManager;

        public HomeController(ILogger<HomeController> logger, ApplicationDbContext context, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _logger = logger;
            _dbContext = context;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Blogs()
        {
            return _dbContext.Blogs != null ?
                        View(_dbContext.Blogs.ToList()) :
                        Problem("Entity set 'ApplicationDbContext.Blogs'  is null.");
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null || _dbContext.Blogs == null)
            {
                return NotFound();
            }

            var blog = await _dbContext.Blogs
                .FirstOrDefaultAsync(m => m.Id == id);
            if (blog == null)
            {
                return NotFound();
            }

            return View(blog);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Name,Url")] Blog blog)
        {
            _dbContext.Add(blog);
            await _dbContext.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
            //return View(blog);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null || _dbContext.Blogs == null)
            {
                return NotFound();
            }

            var blog = await _dbContext.Blogs.FindAsync(id);
            if (blog == null)
            {
                return NotFound();
            }
            return View(blog);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Name,Url")] Blog blog)
        {
            if (id != blog.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _dbContext.Update(blog);
                    await _dbContext.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!BlogExists(blog.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(blog);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (_dbContext.Blogs == null)
            {
                return Problem("Entity set 'ApplicationDbContext.Blogs'  is null.");
            }
            var blog = await _dbContext.Blogs.FindAsync(id);
            if (blog != null)
            {
                _dbContext.Blogs.Remove(blog);
            }

            await _dbContext.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool BlogExists(int id)
        {
            return (_dbContext.Blogs?.Any(e => e.Id == id)).GetValueOrDefault();
        }
        //public async Task<IActionResult> Login([FromBody] LoginModel model)
        //{
        //    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
        //    if (!result.Succeeded)
        //    {
        //        return BadRequest();
        //    }

        //    var user = await _userManager.FindByEmailAsync(model.Email);
        //    var claims = new[]
        //    {
        //    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
        //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //    };

        //    var token = new JwtSecurityToken(
        //        issuer: "https://localhost:7103",
        //        audience: "https://localhost:7103",
        //        claims: claims,
        //        expires: DateTime.UtcNow.AddMinutes(30),
        //        signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345")), SecurityAlgorithms.HmacSha256)
        //    );

        //    return Ok(new
        //    {
        //        token = new JwtSecurityTokenHandler().WriteToken(token),
        //        expiration = DateTime.Now.AddMinutes(30),
        //        userName = user.UserName
        //    });
        //}

        //    [HttpPost("register")]
        //    public async Task<IActionResult> Register([FromBody] Student student)
        //    {
        //        // create user
        //        var user = new IdentityUser { UserName = student.Email, Email = student.Email };
        //        var result = await _userManager.CreateAsync(user, "P@ssw0rd");
        //        if (!result.Succeeded)
        //        {
        //            return BadRequest();
        //        }

        //        // add student to db
        //        _dbContext.Students.Add(student);
        //        await _dbContext.SaveChangesAsync();

        //        // generate jwt token
        //        var claims = new[]
        //        {
        //    new Claim(JwtRegisteredClaimNames.Sub, student.Email),
        //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //};

        //        var token = new JwtSecurityToken(
        //            issuer: "https://localhost:7183",
        //            audience: "https://localhost:7183",
        //            claims: claims,
        //            expires: DateTime.UtcNow.AddMinutes(30),
        //            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345")), SecurityAlgorithms.HmacSha256)
        //        );

        //        // return jwt token
        //        return Ok(new
        //        {
        //            token = new JwtSecurityTokenHandler().WriteToken(token),
        //            expiration = token.ValidTo
        //        });
        //    }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}