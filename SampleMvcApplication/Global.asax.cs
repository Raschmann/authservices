using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Kentor.AuthServices;

namespace SampleMvcApplication
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            //SUBSCRIBE TO MODULE EVENTS
            var module = FederatedAuthentication.GetHttpModule<Saml2AuthenticationModule>();
            module.AuthorizationFailed += Saml2AuthenticationModule_AuthorizationFailed;
            module.RedirectingToIdentityProvider += Saml2AuthenticationModule_RedirectingToIdentityProvider;
            module.SecurityTokenReceived += Saml2AuthenticationModule_SecurityTokenReceived;
            module.SecurityTokenValidated += Saml2AuthenticationModule_SecurityTokenValidated;
            module.SessionSecurityTokenCreated += Sanl2AuthenticationModule_SessionSecurityTokenCreated;
            module.SignedIn += Saml2AuthenticationModule_SignedIn;

            WSFederationAuthenticationModule ws;
        }

        void Saml2AuthenticationModule_SignedIn(object sender, EventArgs e)
        {
            //Anything that's needed right after succesful session and before hitting the application code goes here
            System.Diagnostics.Trace.WriteLine("Handling SignIn event");
        }

        void Sanl2AuthenticationModule_SessionSecurityTokenCreated(object sender, SessionSecurityTokenCreatedEventArgs e)
        {
            //Manipulate session token here, for example, changing its expiration value
            System.Diagnostics.Trace.WriteLine("Handling SessionSecurityTokenCreated event");
            System.Diagnostics.Trace.WriteLine("Key valid from: " + e.SessionToken.KeyEffectiveTime);
            System.Diagnostics.Trace.WriteLine("Key expires on: " + e.SessionToken.KeyExpirationTime);
        }

        void Saml2AuthenticationModule_SecurityTokenValidated(object sender, SecurityTokenValidatedEventArgs e)
        {
            //All vlidation SecurityTokenHandler checks are successful
            System.Diagnostics.Trace.WriteLine("Handling SecurityTokenValidated event");
        }

        void Saml2AuthenticationModule_SecurityTokenReceived(object sender, SecurityTokenReceivedEventArgs e)
        {
            //Augment token validation with your cusotm validation checks without invalidating the token.
            System.Diagnostics.Trace.WriteLine("Handling SecurityTokenReceived event");
        }

        void Saml2AuthenticationModule_AuthorizationFailed(object sender, AuthorizationFailedEventArgs e)
        {
            //Use this event to report more details regarding the ahorization failure
            System.Diagnostics.Trace.WriteLine("Handling AuthorizationFailed event");

        }

        void Saml2AuthenticationModule_RedirectingToIdentityProvider(object sender, Kentor.AuthServices.RedirectingToIdentityProviderEventArgs e)
        {
            //Use this event to programmatically modify the sign-in message to the STS.
            System.Diagnostics.Trace.WriteLine("Handling RedirectingToIdentityProvider event");
            System.Diagnostics.Trace.WriteLine("Location: " + e.CommandResult.Location);
            System.Diagnostics.Trace.WriteLine("Content:" + e.CommandResult.Content);
        }
    }
}
