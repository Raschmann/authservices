using System;
using System.Collections.Specialized;
using System.ComponentModel;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Provides data for the RedirectingToIdentityProvider event.
    /// </summary>
    public class RedirectingToIdentityProviderEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the Sign-in command result that will be used to redirect the user to the identity provider.
        /// </summary>
        public Saml2AuthenticationRequest AuthenticationRequest { get; set; }

        /// <summary>
        /// Http parameters the should be included.
        /// </summary>
        public NameValueCollection HttpParameters { get; private set; }

        /// <summary>
        /// Initializes an instance of the RedirectingToIdentityProviderEventArgs class by using the specified Sign-In command result.
        /// </summary>
        /// <param name="authenticationRequest">The Sign-in command result that will be used to redirect the user to the Identity Provider.</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="authenticationRequest"/> is null.</exception>
        public RedirectingToIdentityProviderEventArgs(Saml2AuthenticationRequest authenticationRequest)
        {
            if (authenticationRequest == null)
                throw new ArgumentNullException("authenticationRequest");

            AuthenticationRequest = authenticationRequest;
            HttpParameters = new NameValueCollection();
        }
    }
}
