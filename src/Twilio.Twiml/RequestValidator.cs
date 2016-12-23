using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Twilio.TwiML
{
	/// <summary>
	/// Class used to validate incoming requests from Twilio using 'Request Validation' as described
	/// in the Security section of the Twilio TwiML API documentation.
	/// </summary>
	public class RequestValidator
	{
		/// <summary>
		/// Performs request validation using the current HTTP context passed in manually or from
		/// the ASP.NET MVC ValidateRequestAttribute
		/// </summary>
		/// <param name="context">HttpContext to use for validation</param>
		/// <param name="authToken">AuthToken for the account used to sign the request</param>
		public bool IsValidRequest(HttpContext context, string authToken)
		{
			return IsValidRequest(context, authToken, null);
		}

		/// <summary>
		/// Performs request validation using the current HTTP context passed in manually or from
		/// the ASP.NET MVC ValidateRequestAttribute
		/// </summary>
		/// <param name="context">HttpContext to use for validation</param>
		/// <param name="authToken">AuthToken for the account used to sign the request</param>
		/// <param name="urlOverride">The URL to use for validation, if different from Request.Url (sometimes needed if web site is behind a proxy or load-balancer)</param>
		public bool IsValidRequest(HttpContext context, string authToken, string urlOverride)
        {
            if (context.Request.IsLocal)
            {
                return true;
            }

            // validate request
            // http://www.twilio.com/docs/security-reliability/security
            //
            // According to the notes, under various circumstances the URL used to calculate the
            // signature will exclude the user info and/or the port. Also, a known bug affects
            // whether or not the port is included in the calculation.
            //
            // Since reliably determining which scenario the current request covers would be difficult,
            // and also because of the likelihood of a future bug fix that will change behavior, no attempt
            // is made to determine based upon the request which scenario for signature calculation is
            // required.
            //
            // Instead, the most likely scenario is tested first.  If it fails, the other scenarios
            // are tested one by one.

            var url = string.IsNullOrEmpty(urlOverride) ? context.Request.Url.AbsoluteUri : urlOverride;

            // First try full URL.  This should handle most circumstances
            // so it will efficiently short-circuit the rest if it succeeds
            if (IsValidRequestInternal(context, authToken, url))
            {
                return true;
            }

            var fullUri = string.IsNullOrEmpty(urlOverride) ? context.Request.Url : new System.Uri(urlOverride);

            // Try without port or user info
            url = fullUri.GetComponents(
                        UriComponents.Scheme |
                        UriComponents.Host |
                        UriComponents.Path |
                        UriComponents.Query |
                        UriComponents.KeepDelimiter,
                        UriFormat.UriEscaped);
            if (IsValidRequestInternal(context, authToken, url))
            {
                return true;
            }

            // Try without user info
            url = fullUri.GetComponents(
                        UriComponents.Scheme |
                        UriComponents.Host |
                        UriComponents.Port |
                        UriComponents.Path |
                        UriComponents.Query |
                        UriComponents.KeepDelimiter,
                        UriFormat.UriEscaped);
            if (IsValidRequestInternal(context, authToken, url))
            {
                return true;
            }

            // Try without port
            url = fullUri.GetComponents(
                        UriComponents.Scheme |
                        UriComponents.UserInfo |
                        UriComponents.Host |
                        UriComponents.Path |
                        UriComponents.Query |
                        UriComponents.KeepDelimiter,
                        UriFormat.UriEscaped);
            if (IsValidRequestInternal(context, authToken, url))
            {
                return true;
            }

            // Validation failed all possible URL combinations
            return false;
        }

        /// <summary>
        /// Core signature validation logic using a given URL
        /// </summary>
        /// <param name="context">HttpContext to use for validation</param>
        /// <param name="authToken">AuthToken for the account used to sign the request</param>
        /// <param name="url">The URL to use verbatim in the signature calculation</param>
        private static bool IsValidRequestInternal(HttpContext context, string authToken, string url)
        {
            var value = new StringBuilder();
            value.Append(url);

            // If the request is a POST, take all of the POST parameters and sort them alphabetically.
            if (context.Request.HttpMethod == "POST")
            {
                // Iterate through that sorted list of POST parameters, and append the variable name and value (with no delimiters) to the end of the URL string
                var sortedKeys = context.Request.Form.AllKeys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                foreach (var key in sortedKeys)
                {
                    value.Append(key);
                    value.Append(context.Request.Form[key]);
                }
            }

            // Sign the resulting value with HMAC-SHA1 using your AuthToken as the key (remember, your AuthToken's case matters!).
            var sha1 = new HMACSHA1(Encoding.UTF8.GetBytes(authToken));
            var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(value.ToString()));

            // Base64 encode the hash
            var encoded = Convert.ToBase64String(hash);

            // Compare your hash to ours, submitted in the X-Twilio-Signature header. If they match, then you're good to go.
            var sig = context.Request.Headers["X-Twilio-Signature"];

            return sig == encoded;
        }
    }
}
