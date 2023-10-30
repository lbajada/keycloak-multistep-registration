package org.lukebajada.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.storage.adapter.InMemoryUserAdapter;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.UUID;

import static org.lukebajada.keycloak.utils.OtpUtils.*;

public class EmailOtpAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    public static final String EMAIL_OTP_FORM = "email-otp-form.ftl";
    public static final String FORM_PARAM_OTP_CODE = "otp";

    private static final Logger logger = Logger.getLogger(EmailOtpAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String username = context.getAuthenticationSession().getAuthNote(ATTEMPTED_USERNAME);
        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

        Response response = context.form().createForm(EMAIL_OTP_FORM);

        // Do not send the verification email OTP if the user is already active!
        if (user == null) {
            user = new InMemoryUserAdapter(context.getSession(), context.getRealm(), UUID.randomUUID().toString());
            user.setEmail(username);
            sendOtp(context.getAuthenticationSession(), context.getSession(), user);
        } else {
            context.getEvent().error(Errors.EMAIL_IN_USE);
        }

        context.challenge(response);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("resend")) {
            context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
            authenticate(context);
            return;
        }

        String code = formData.getFirst(FORM_PARAM_OTP_CODE);
        logger.debugf("Got %s for OTP code in form", code);
        try {
            if (code != null && code.equals(context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_CODE))) {
                context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);

                context.getAuthenticationSession().setAuthNote(USER_AUTH_NOTE_OTP_VERIFIED, "true");

                context.success();
                return;
            }
        } catch (Exception e) {
            logger.warn("Error comparing OTP code to form", e);
        }

        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);

        Response challenge = context.form()
                .setError(Messages.INVALID_ACCESS_CODE)
                .createForm(EMAIL_OTP_FORM);
        context.challenge(challenge);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }


}
