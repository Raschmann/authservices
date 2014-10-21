using Kentor.AuthServices;
using System;
using System.IdentityModel.Services;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace SampleApplication
{
    // Note: For instructions on enabling IIS6 or IIS7 classic mode, 
    // visit http://go.microsoft.com/?LinkId=9394801

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            //SUBSCRIBE TO MODULE EVENTS
            Saml2AuthenticationModule.Current.RedirectingToIdentityProvider += Saml2AuthenticationModule_RedirectingToIdentityProvider;
            Saml2AuthenticationModule.Current.SecurityTokenReceived += Saml2AuthenticationModule_SecurityTokenReceived;
            Saml2AuthenticationModule.Current.SecurityTokenValidated += Saml2AuthenticationModule_SecurityTokenValidated;
            Saml2AuthenticationModule.Current.SessionSecurityTokenCreated += Saml2AuthenticationModule_SessionSecurityTokenCreated;
            Saml2AuthenticationModule.Current.SignedIn += Saml2AuthenticationModule_SignedIn;
            Saml2AuthenticationModule.Current.SigningOut += ModuleOnSigningOut;
            Saml2AuthenticationModule.Current.SignedOut += ModuleOnSignedOut;
        }

        void ModuleOnSignedOut(object sender, EventArgs eventArgs)
        {
            // Anaything after sign out
            System.Diagnostics.Trace.WriteLine("Handling SignOut event");
        }

        void ModuleOnSigningOut(object sender, SigningOutEventArgs signingOutEventArgs)
        {
            // Anaything before signing out
            System.Diagnostics.Trace.WriteLine("Handling SigningOut event");
            System.Diagnostics.Trace.WriteLine("Is IP initiated: " + signingOutEventArgs.IsIPInitiated);
        }

        void Saml2AuthenticationModule_SignedIn(object sender, EventArgs e)
        {
            //Anything that's needed right after succesful session and before hitting the application code goes here
            System.Diagnostics.Trace.WriteLine("Handling SignIn event");
        }

        void Saml2AuthenticationModule_SessionSecurityTokenCreated(object sender, SessionSecurityTokenCreatedEventArgs e)
        {
            //Manipulate session token here, for example, changing its expiration value
            System.Diagnostics.Trace.WriteLine("Handling SessionSecurityTokenCreated event");
            System.Diagnostics.Trace.WriteLine("Key valid from: " + e.SessionToken.KeyEffectiveTime);
            System.Diagnostics.Trace.WriteLine("Key expires on: " + e.SessionToken.KeyExpirationTime);
        }

        void Saml2AuthenticationModule_SecurityTokenValidated(object sender, Kentor.AuthServices.SecurityTokenValidatedEventArgs e)
        {
            //All vlidation SecurityTokenHandler checks are successful
            System.Diagnostics.Trace.WriteLine("Handling SecurityTokenValidated event");
        }

        void Saml2AuthenticationModule_SecurityTokenReceived(object sender, SecurityTokenReceivedEventArgs e)
        {
            //Augment token validation with your cusotm validation checks without invalidating the token.
            System.Diagnostics.Trace.WriteLine("Handling SecurityTokenReceived event");
            System.Diagnostics.Trace.WriteLine("Token id: " + e.SecurityToken.Id);
            System.Diagnostics.Trace.WriteLine("Valid from: " + e.SecurityToken.ValidFrom);
            System.Diagnostics.Trace.WriteLine("Valid to: " + e.SecurityToken.ValidTo);
        }

        void Saml2AuthenticationModule_RedirectingToIdentityProvider(object sender, Kentor.AuthServices.RedirectingToIdentityProviderEventArgs e)
        {
            //Use this event to programmatically modify the sign-in message to the STS.
            System.Diagnostics.Trace.WriteLine("Handling RedirectingToIdentityProvider event");
            System.Diagnostics.Trace.WriteLine("Location: " + e.CommandResult.Location);
            System.Diagnostics.Trace.WriteLine("Http status code: " + e.CommandResult.HttpStatusCode);

            e.CommandResult.HttpParameters.Add("lng", "sk");
        }
    }
}