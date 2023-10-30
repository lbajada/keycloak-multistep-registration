package org.lukebajada.keycloak.requiredactions;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.DisplayTypeRequiredActionFactory;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import static org.lukebajada.keycloak.utils.OtpUtils.USER_AUTH_NOTE_OTP_CODE;
import static org.lukebajada.keycloak.utils.OtpUtils.sendOtp;

public class EmailOtp implements RequiredActionProvider, RequiredActionFactory, DisplayTypeRequiredActionFactory {


    public static final String EMAIL_OTP_FORM = "email-otp-form.ftl";
    public static final String FORM_PARAM_OTP_CODE = "otp";
    public static final String PROVIDER_ID = "email-otp";
    public static final String DISPLAY_TEXT = "A One-Time password sent to the email provided for verification.";

    private static final Logger logger = Logger.getLogger(EmailOtp.class);

    @Override
    public String getDisplayText() {
        return DISPLAY_TEXT;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        sendOtp(context.getAuthenticationSession(), context.getSession(), context.getUser());

        Response response = context.form().createForm(EMAIL_OTP_FORM);
        context.challenge(response);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        logger.debug("EmailOtpAuthenticator.action");

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("resend")) {
            context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
            requiredActionChallenge(context);
            return;
        }

        String code = formData.getFirst(FORM_PARAM_OTP_CODE);
        logger.debugf("Got %s for OTP code in form", code);
        try {
            if (code != null
                    && code.equals(context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_CODE))) {
                context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_CODE);
                context.getAuthenticationSession().getAuthenticatedUser().setEmailVerified(true);
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
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    @Override
    public RequiredActionProvider createDisplay(KeycloakSession session, String displayType) {
        return this;
    }
}
