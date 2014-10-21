using System;
using System.ComponentModel;
using System.Security.Claims;
using System.Security.Permissions;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Provides data for the <see cref="E:System.IdentityModel.Services.WSFederationAuthenticationModule.SecurityTokenValidated"/> event.
    /// </summary>
    public class SecurityTokenValidatedEventArgs : CancelEventArgs
    {
        /// <summary>
        /// Gets or sets the <see cref="T:System.Security.Claims.ClaimsIdentity"/> that results from token validation.
        /// </summary>
        /// 
        /// <returns>
        /// The claims Identity that results from token validation.
        /// </returns>
        public ClaimsIdentity ClaimsIdentity { get; [SecurityPermission(SecurityAction.Demand, ControlPrincipal = true)] set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:System.IdentityModel.Services.SecurityTokenValidatedEventArgs"/> class.
        /// </summary>
        /// <param name="claimsIdentity">The claims principal resulting from validation of the received <see cref="T:System.IdentityModel.Tokens.SecurityToken"/>.</param><exception cref="T:System.ArgumentNullException"><paramref name="claimsIdentity"/> is null.</exception>
        public SecurityTokenValidatedEventArgs(ClaimsIdentity claimsIdentity)
        {
            if (claimsIdentity == null)
                throw new ArgumentNullException("claimsIdentity");

            ClaimsIdentity = claimsIdentity;
        }
    }
}
