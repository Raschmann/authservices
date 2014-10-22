using Kentor.AuthServices.Configuration;
using System;
using System.Globalization;
using System.IdentityModel.Metadata;
using System.Linq;
using System.Net;

namespace Kentor.AuthServices
{
    class SignInCommand : ICommand
    {
        public CommandResult Run(HttpRequestData request)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            return CreateResult(new EntityId(request.QueryString["idp"]),
                request.QueryString["ReturnUrl"], request.Url);
        }

        public static CommandResult CreateResult(EntityId idpEntityId, string returnPath, Uri requestUrl)
        {
            IdentityProvider idp;
            if (idpEntityId == null || idpEntityId.Id == null)
            {
                if (KentorAuthServicesSection.Current.DiscoveryServiceUrl != null)
                {
                    return RedirectToDiscoveryService(returnPath);
                }
                idp = IdentityProvider.ActiveIdentityProviders.First();
            }
            else
            {
                if (!IdentityProvider.ActiveIdentityProviders.TryGetValue(idpEntityId, out idp))
                {
                    throw new InvalidOperationException("Unknown idp");
                }
            }

            Uri returnUri = null;
            if (!string.IsNullOrEmpty(returnPath))
            {
                Uri.TryCreate(requestUrl, returnPath, out returnUri);
            }

            var authnRequest = idp.CreateAuthenticateRequest(returnUri);

            var args = new RedirectingToIdentityProviderEventArgs(authnRequest);

            Saml2AuthenticationModule.OnRedirectingToIdentityProvider(args);

            if (args.Cancel)
                return new CommandResult { HttpStatusCode = HttpStatusCode.OK };

            var result = idp.Bind(args.AuthenticationRequest);
            result.HttpParameters = args.HttpParameters;

            return result;
        }

        private static CommandResult RedirectToDiscoveryService(string returnPath)
        {
            string returnUrl = KentorAuthServicesSection.Current.DiscoveryServiceResponseUrl.OriginalString;

            if(!string.IsNullOrEmpty(returnPath))
            {
                returnUrl += "?ReturnUrl=" + Uri.EscapeDataString(returnPath);
            }

            var redirectLocation = string.Format(
                CultureInfo.InvariantCulture,
                "{0}?entityID={1}&return={2}&returnIDParam=idp",
                KentorAuthServicesSection.Current.DiscoveryServiceUrl,
                Uri.EscapeDataString(KentorAuthServicesSection.Current.EntityId),
                Uri.EscapeDataString(returnUrl));

            return new CommandResult
            {
                HttpStatusCode = HttpStatusCode.SeeOther,
                Location = new Uri(redirectLocation)
            };
        }
    }
}
