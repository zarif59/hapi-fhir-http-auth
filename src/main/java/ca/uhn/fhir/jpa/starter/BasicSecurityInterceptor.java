package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import org.apache.commons.codec.binary.Base64;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Interceptor
public class BasicSecurityInterceptor {

   /**
    * This interceptor implements HTTP Basic Auth, which specifies that
    * a username and password are provided in a header called Authorization.
    */
   @Hook(Pointcut.SERVER_INCOMING_REQUEST_POST_PROCESSED)
   public boolean incomingRequestPostProcessed(
         RequestDetails theRequestDetails, HttpServletRequest theRequest, HttpServletResponse theResponse)
         throws AuthenticationException {
      String authHeader = theRequest.getHeader("Authorization");

      // The format of the header must be:
      // Authorization: Basic [base64 of username:password]
      if (authHeader == null || authHeader.startsWith("Basic ") == false) {
         throw new AuthenticationException("Missing or invalid Authorization header");
      }

      String base64 = authHeader.substring("Basic ".length());
      String base64decoded = new String(Base64.decodeBase64(base64));
      String[] parts = base64decoded.split(":");

      String username = parts[0];
      String password = parts[1];

      /*
       * Here we test for a hardcoded username & password. This is
       * not typically how you would implement this in a production
       * system of course..
       */
      if (!username.equals("admin") || !password.equals("password")) {
         throw new AuthenticationException("Invalid username or password");
      }

      // Return true to allow the request to proceed
      return true;
   }
}
