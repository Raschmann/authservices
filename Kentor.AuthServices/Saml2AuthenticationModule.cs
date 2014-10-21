using System;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Services;
using System.Net;
using System.Runtime;
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
        /// Gets the current authentication module
        /// </summary>
        public static Saml2AuthenticationModule Current
        {
            [TargetedPatchingOptOut("Performance critical to inline this type of method across NGen image boundaries")]
            get { return FederatedAuthentication.GetHttpModule<Saml2AuthenticationModule>(); }
        }

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

            if (application.Request.AppRelativeCurrentExecutionFilePath == null || 
                !application.Request.AppRelativeCurrentExecutionFilePath.StartsWith(ModulePath, StringComparison.OrdinalIgnoreCase)) 
                return;

            var moduleRelativePath = application.Request.AppRelativeCurrentExecutionFilePath
                .Substring(ModulePath.Length);

            var command = CommandFactory.GetCommand(moduleRelativePath);
            var commandResult = RunCommand(application, command);

            commandResult.SignInSessionAuthenticationModule();
            commandResult.Apply(new HttpResponseWrapper(application.Response));
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

        /// <summary>
        /// Raises the SecurityTokenReceived event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal static void OnSecurityTokenReceived(SecurityTokenReceivedEventArgs args)
        {
            if (Current == null || Current.SecurityTokenReceived == null)
                return;

            Current.SecurityTokenReceived(Current, args);
        }

        /// <summary>
        /// Raises the SecurityTokenReceived event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal static void OnSecurityTokenValidated(SecurityTokenValidatedEventArgs args)
        {
            if (Current == null || Current.SecurityTokenValidated == null)
                return;

            Current.SecurityTokenValidated(Current, args);
        }

        /// <summary>
        /// Raises the SessionSecurityTokenCreated event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal virtual void OnSessionSecurityTokenCreated(SessionSecurityTokenCreatedEventArgs args)
        {
            if (SessionSecurityTokenCreated == null)
                return;

            SessionSecurityTokenCreated(this, args);
        }

        /// <summary>
        /// Raises the RedirectingToIdentityProvider event.
        /// </summary>
        /// <param name="args">The data for the event.</param>
        internal static void OnRedirectingToIdentityProvider(RedirectingToIdentityProviderEventArgs args)
        {
            if (Current == null || Current.RedirectingToIdentityProvider == null)
                return;

            Current.RedirectingToIdentityProvider(Current, args);
        }

        /// <summary>
        /// Requests a redirect to Idp
        /// </summary>
        public void SignIn()
        {
            var request = new HttpRequestWrapper(HttpContext.Current.Request);
            var response = new HttpResponseWrapper(HttpContext.Current.Response);

            CommandFactory.GetCommand("SignIn").Run(new HttpRequestData(request)).Apply(response);
            OnSignedIn(EventArgs.Empty);
        }

        /// <summary>
        /// Signs out of the current session and requests a redirect back to the URL specified in the current HTTP request.
        /// </summary>
        public virtual void SignOut()
        {
            SignOut(HttpContext.Current.Request.Url);
        }

        /// <summary>
        /// Signs out of the current session and requests a redirect back to the specified URL.
        /// </summary>
        /// <param name="redirectUrl">The URL to which the browser should be redirected after the session is deleted.</param>
        /// <exception cref="T:System.ArgumentException"><paramref name="redirectUrl"/> is null.</exception>        
        public virtual void SignOut(Uri redirectUrl)
        {
            SignOut(redirectUrl, false);
        }

        // <summary>
        /// Signs out of the current session and requests a redirect back to the specified URL.
        /// 
        /// <param name="redirectUrl">The URL to which the browser should be redirected after sign-out.</param>
        /// <param name="initiateSignOutCleanup">Always set false. Setting this parameter to true is not supported.</param>
        /// <exception cref="T:System.ArgumentException"><paramref name="redirectUrl"/> is null.</exception>
        /// <exception cref="T:System.NotImplementedException">The Saml2AuthenticationModule class throws this exception if <paramref name="initiateSignOutCleanup"/> is true. Do not set this parameter to true.</exception>
        public virtual void SignOut(Uri redirectUrl, bool initiateSignOutCleanup)
        {
            if (initiateSignOutCleanup)
                throw new NotImplementedException("Initiate sign out cleanup is not implemented");

            if (redirectUrl == null)
                throw new ArgumentException("The value is null.", "redirectUrl");

            SignOut(false);
            Redirect(redirectUrl.AbsoluteUri);
        }

        /// <summary>
        /// Signs out of the current session and raises the appropriate events.
        /// </summary>
        /// <param name="idpRequest">true if the request was initiated by the IP-STS via a single sign-out cleanup request message (LogoutRequets); otherwise, false.</param>        
        public virtual void SignOut(bool idpRequest)
        {
            try
            {
                OnSigningOut(new SigningOutEventArgs(idpRequest));
                FederatedAuthentication.SessionAuthenticationModule.SignOut();
                OnSignedOut(EventArgs.Empty);
            }
            catch (Exception ex)
            {                
                var args = new ErrorEventArgs(ex);
                OnSignOutError(args);

                if (args.Cancel)
                    return;

                throw;
            }
        }

        internal static void Redirect(string redirectUrl)
        {
            var current = HttpContext.Current;

            current.Response.Redirect(redirectUrl, false);

            if (current.ApplicationInstance == null)
                return;

            current.ApplicationInstance.CompleteRequest();
        }
 
        private static CommandResult RunCommand(HttpApplication application, ICommand command)
        {
            try
            {
                return command.Run(new HttpRequestData(new HttpRequestWrapper(application.Request)));
            }
            catch (AuthServicesException)
            {
                return new CommandResult
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
