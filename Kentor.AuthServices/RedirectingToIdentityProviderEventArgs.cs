using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        public CommandResult CommandResult { get; set; }

        /// <summary>
        /// Initializes an instance of the RedirectingToIdentityProviderEventArgs class by using the specified Sign-In command result.
        /// </summary>
        /// <param name="commandResult">The Sign-in command result that will be used to redirect the user to the Identity Provider.</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="commandResult"/> is null.</exception>
        public RedirectingToIdentityProviderEventArgs(CommandResult commandResult)
        {
            if (commandResult == null)
                throw new ArgumentNullException("commandResult");

            CommandResult = commandResult;
        }
    }
}
