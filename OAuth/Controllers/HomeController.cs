using LNF.Repository;
using LNF.Repository.Data;
using OAuth.Models;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace OAuth.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet, Route("authorize")]
        public ActionResult Authorize()
        {
            // This does an automatic grant without showing the confirmation, so it works like a normal login.

            // Set by OAuthProvider to something other than 200 if the request is invalid, for example if client_id is missing from querystring.
            if (Response.StatusCode != 200)
                return View("AuthorizeError");

            // to get here we must already be authenticated via FormsAuthentication
            var identity = (ClaimsIdentity)User.Identity;

            if (identity != null)
            {
                var claimsIdentity = new ClaimsIdentity(identity.Claims, "Bearer", identity.NameClaimType, identity.RoleClaimType);
                HttpContext.GetOwinContext().Authentication.SignIn(claimsIdentity);
                return Content("authorized", "text/plain");
            }
            else
            {
                return new HttpUnauthorizedResult();
            }
        }

        [HttpGet, Route("authorize/confirm")]
        public ActionResult AuthorizeConfirm()
        {
            // to get here we must already be authenticated via FormsAuthentication
            ViewBag.DisplayName = GetDisplayName(User.Identity.Name);

            var clientAppService = new ClientAppService();
            var clientApp = clientAppService.GetClientAppBytId(Request.QueryString["client_id"]);

            return View(clientApp);
        }

        [HttpPost, Route("authorize/confirm")]
        public ActionResult AuthorizeConfirm(string command)
        {
            if (command == "grant")
            {
                // The OAuthProvider will only issue a token in the Authorize action.
                return RedirectToAction("Authorize", new { client_id = Request.QueryString["client_id"], redirect_uri = Request.QueryString["redirect_uri"], response_type = Request.QueryString["response_type"] });
            }
            else if (command == "login")
            {
                FormsAuthentication.SignOut();
                return new HttpUnauthorizedResult();
            }

            // to get here we must already be authenticated via FormsAuthentication
            ViewBag.DisplayName = GetDisplayName(User.Identity.Name);

            var clientAppService = new ClientAppService();
            var clientApp = clientAppService.GetClientAppBytId(Request.QueryString["client_id"]);

            return View(clientApp);
        }

        [HttpGet, Route("logout")]
        public ActionResult LogOut()
        {
            string returnUrl = Request.QueryString["ReturnUrl"];

            if (!string.IsNullOrEmpty(returnUrl))
            {
                var authority = Request.Url.GetLeftPart(UriPartial.Authority);
                returnUrl = returnUrl.Replace(authority, string.Empty);
            }

            var encodedReturnUrl = Server.UrlEncode(returnUrl);

            return Redirect(FormsAuthentication.LoginUrl + $"?ReturnUrl={encodedReturnUrl}");
        }

        private string GetDisplayName(string username)
        {
            var c = DA.Current.Query<Client>().FirstOrDefault(x => x.UserName == username);

            if (c != null)
                return $"{c.FName} {c.LName}";
            else
                return User.Identity.Name;
        }
    }
}