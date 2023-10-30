package org.lukebajada.keycloak.forms;

import org.keycloak.Config;
import org.keycloak.authentication.FormAuthenticator;
import org.keycloak.authentication.FormAuthenticatorFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import javax.ws.rs.core.Response;
import java.util.List;

public class UsernameRegistrationPage implements FormAuthenticator, FormAuthenticatorFactory {
    public static final String PROVIDER_ID = "username-registration-page-form";
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public Response render(FormContext context, LoginFormsProvider form) {
        form.createRegistration();
        return form.createForm("register-username.ftl");
    }

    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Username Registration Page";
    }

    @Override
    public String getHelpText() {
        return "This is the controller for the username registration page";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public FormAuthenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
