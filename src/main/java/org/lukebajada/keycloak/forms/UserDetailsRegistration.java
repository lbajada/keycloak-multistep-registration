package org.lukebajada.keycloak.forms;

import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.forms.RegistrationUserCreation;

import javax.ws.rs.core.MultivaluedMap;

import static org.lukebajada.keycloak.utils.OtpUtils.USER_AUTH_NOTE_OTP_VERIFIED;

public class UserDetailsRegistration extends RegistrationUserCreation {

    public static final String PROVIDER_ID = "user-details-registration";

    @Override
    public String getHelpText() {
        return "Should always be after Username Registration. This form prompts the user to fill in the rest of the details and shows the username in an uneditable field.";
    }

    @Override
    public String getDisplayType() {
        return "User details input with uneditable username";
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String username;
        if (context.getRealm().isRegistrationEmailAsUsername()) {
            username = formData.getFirst("email");
        } else {
            username = formData.getFirst("username");
        }

        if (!username.equals(context.getAuthenticationSession().getAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME))) {
            context.error("Malicious attempt at email address change!");
        }

        super.validate(context);
    }

    @Override
    public void success(FormContext context) {
        super.success(context);

        if (Boolean.parseBoolean(context.getAuthenticationSession().getAuthNote(USER_AUTH_NOTE_OTP_VERIFIED))) {
            context.getUser().setEmailVerified(true);
            context.getAuthenticationSession().removeAuthNote(USER_AUTH_NOTE_OTP_VERIFIED);
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
