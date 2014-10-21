using System.Diagnostics;
using Kentor.AuthServices;
using System;
using System.Web.Mvc;

namespace SampleApplication.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult SignOut()
        {            
            Debug.Assert(Request.Url != null, "Request.Url != null");
            // ReSharper disable once AssignNullToNotNullAttribute
            Saml2AuthenticationModule.Current.SignOut(new Uri(Url.Action("Index", null, null, Request.Url.Scheme)));

            return new EmptyResult();
        }

        public ActionResult SignIn()
        {
            Saml2AuthenticationModule.Current.SignIn();

            return new EmptyResult();
        }
    }
}
