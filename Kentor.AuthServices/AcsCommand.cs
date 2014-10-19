﻿using Kentor.AuthServices.Configuration;
using System;
using System.IdentityModel.Metadata;
using System.IdentityModel.Services;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Xml;

namespace Kentor.AuthServices
{
    class AcsCommand : ICommand
    {
        public CommandResult Run(HttpRequestData request)
        {
            var binding = Saml2Binding.Get(request);

            if (binding == null) 
                throw new NoSamlResponseFoundException();

            try
            {
                var samlResponse = Saml2Response.Read(binding.Unbind(request));

                samlResponse.Validate(GetSigningKey(samlResponse.Issuer));

                var principal = new ClaimsPrincipal(samlResponse.GetClaims());

                principal = FederatedAuthentication.FederationConfiguration.IdentityConfiguration
                    .ClaimsAuthenticationManager.Authenticate(null, principal);

                return new CommandResult()
                {
                    HttpStatusCode = HttpStatusCode.SeeOther,
                    Location =
                        samlResponse.RequestState != null && samlResponse.RequestState.ReturnUri != null
                            ? samlResponse.RequestState.ReturnUri
                            : KentorAuthServicesSection.Current.ReturnUri,
                    Principal = principal
                };
            }
            catch (FormatException ex)
            {
                var arg = new ErrorEventArgs(ex);
                FederatedAuthentication.GetHttpModule<Saml2AuthenticationModule>().OnSignInError(arg);

                if (!arg.Cancel)
                    throw new BadFormatSamlResponseException(
                        "The SAML Response did not contain valid BASE64 encoded data.", ex);
            }
            catch (XmlException ex)
            {
                var arg = new ErrorEventArgs(ex);
                FederatedAuthentication.GetHttpModule<Saml2AuthenticationModule>().OnSignInError(arg);

                if (!arg.Cancel)
                    throw new BadFormatSamlResponseException(
                        "The SAML response contains incorrect XML", ex);
            }

            throw new NoSamlResponseFoundException();
        }

        private static AsymmetricAlgorithm GetSigningKey(EntityId issuer)
        {
            return IdentityProvider.ActiveIdentityProviders[issuer].SigningKey;
        }
    }
}
