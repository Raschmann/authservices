using System;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Web;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Http Module for SAML2 authentication. The module hijacks the 
    /// ~/Saml2AuthenticationModule/ path of the http application to provide 
    /// authentication services.
    /// </summary>
    // Not included in code coverage as the http module is tightly dependent on IIS.
    [ExcludeFromCodeCoverage]
    public class Saml2AuthenticationModule : IHttpModule
    {
        /// <summary>
        /// Occurs when a security token has been received from a security token service (STS).
        /// </summary>
        public event EventHandler<SecurityTokenReceivedEventArgs> SecurityTokenReceived;

        /// <summary>
        /// Occurs after a security token that was received from the security token service (STS) has been validated but before the session security token is created.
        /// </summary>
        public event EventHandler<SecurityTokenValidatedEventArgs> SecurityTokenValidated;

        /// <summary>
        /// Occurs when a session security token has been created from the security token received from a security token service (STS).
        /// </summary>
        public event EventHandler<SessionSecurityTokenCreatedEventArgs> SessionSecurityTokenCreated;

        /// <summary>
        /// Occurs after the user is signed in.
        /// </summary>
        public event EventHandler SignedIn;

        /// <summary>
        /// Occurs just after deleting the session during sign-out.
        /// </summary>
        public event EventHandler SignedOut;

        /// <summary>
        /// Raised when an error during sign-in occurs.
        /// </summary>
        public event EventHandler<ErrorEventArgs> SignInError;

        /// <summary>
        /// Occurs before deleting the session during sign-out.
        /// </summary>
        public event EventHandler<SigningOutEventArgs> SigningOut;

        /// <summary>
        /// Raised when an error occurs during sign-out.
        /// </summary>
        public event EventHandler<ErrorEventArgs> SignOutError;

        /// <summary>
        /// Occurs when the module is going to redirect the user to the identity provider.
        /// </summary>
        public event EventHandler<RedirectingToIdentityProviderEventArgs> RedirectingToIdentityProvider;

        /// <summary>
        /// Occurs when the module is determining whether it should redirect the user to the configured issuer to authenticate.
        /// </summary>
        public event EventHandler<AuthorizationFailedEventArgs> AuthorizationFailed;

        /// <summary>
        /// Init the module and subscribe to events.
        /// </summary>
        /// <param name="context"></param>
        public void Init(HttpApplication context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            context.BeginRequest += OnBeginRequest;
        }

        const string ModulePath = "~/Saml2AuthenticationModule/";

        /// <summary>
        /// Begin request handler that captures all traffic to ~/Saml2AuthenticationModule/
        /// </summary>
        /// <param name="sender">The http application.</param>
        /// <param name="e">Ignored</param>
        protected virtual void OnBeginRequest(object sender, EventArgs e)
        {
            var application = (HttpApplication)sender;

            if(application.Request.AppRelativeCurrentExecutionFilePath
                .StartsWith(ModulePath, StringComparison.OrdinalIgnoreCase))
            {
                var moduleRelativePath = application.Request.AppRelativeCurrentExecutionFilePath
                    .Substring(ModulePath.Length);

                var command = CommandFactory.GetCommand(moduleRelativePath);
                var commandResult = RunCommand(application, command);

                commandResult.SignInSessionAuthenticationModule();
                commandResult.Apply(new HttpResponseWrapper(application.Response));
            }
        }

        /// <summary>
        /// Raises the SignedIn event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal virtual void OnSignedIn(EventArgs args)
        {
            if (SignedIn == null)
                return;
            SignedIn(this, args);
        }

        /// <summary>
        /// Raises the SignedOut event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal virtual void OnSignedOut(EventArgs args)
        {
            if (SignedOut == null)
                return;

            SignedOut(this, args);
        }

        /// <summary>
        /// Raises the SignInError event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal virtual void OnSignInError(ErrorEventArgs args)
        {
            if (SignInError == null)
                return;

            SignInError(this, args);
        }

        /// <summary>
        /// Raises the SigningOut event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        protected virtual void OnSigningOut(SigningOutEventArgs args)
        {
            if (SigningOut == null)
                return;

            SigningOut(this, args);
        }

        /// <summary>
        /// Raises the SignOutError event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        protected virtual void OnSignOutError(ErrorEventArgs args)
        {
            if (SignOutError == null)
                return;

            SignOutError(this, args);
        }

        public static CommandResult SignIn()
        {
            var request = new HttpRequestWrapper(HttpContext.Current.Request);
            return CommandFactory.GetCommand("SignIn").Run(new HttpRequestData(request));
        }
 
        private static CommandResult RunCommand(HttpApplication application, ICommand command)
        {
            try
            {
                return command.Run(new HttpRequestData(new HttpRequestWrapper(application.Request)));
            }
            catch (AuthServicesException)
            {
                return new CommandResult()
                {
                    HttpStatusCode = HttpStatusCode.InternalServerError
                };
            }
        }

        /// <summary>
        /// IDisposable implementation.
        /// </summary>
        public virtual void Dispose()
        {
            // Deliberately do nothing, unsubscribing from events is not
            // needed by the IIS model. Trying to do so throws exceptions.
        }
    }
}
