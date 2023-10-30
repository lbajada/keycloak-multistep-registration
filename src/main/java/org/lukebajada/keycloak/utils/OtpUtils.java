package org.lukebajada.keycloak.utils;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

public final class OtpUtils {
    public static final String OTP_EMAIL = "otp-email.ftl";

    public static final String USER_AUTH_NOTE_OTP_CODE = "user-auth-note-otp-code";

    public static final String USER_AUTH_NOTE_OTP_VERIFIED = "user-auth-note-otp-verified";

    private static final Logger logger = Logger.getLogger(OtpUtils.class);

    public static void sendOtp(AuthenticationSessionModel authenticationSession, KeycloakSession session, UserModel user) {
        if (authenticationSession.getAuthNote(USER_AUTH_NOTE_OTP_CODE) != null) {
            logger.debugf(
                    "Skipping sending OTP email to %s because auth note isn't empty",
                    user.getEmail());
            return;
        }
        String code = String.format("%06d", ThreadLocalRandom.current().nextInt(999999));
        boolean sent = sendOtpEmail(session, user, code);
        if (sent) {
            logger.debugf("Sent OTP code %s to email %s", code, user.getEmail());
            authenticationSession.setAuthNote(USER_AUTH_NOTE_OTP_CODE, code);
        }
    }

    public static boolean sendOtpEmail(KeycloakSession session, UserModel user, String code) {
        RealmModel realm = session.getContext().getRealm();
        try {
            EmailTemplateProvider emailTemplateProvider =
                    session.getProvider(EmailTemplateProvider.class);
            String realmName = session.getContext().getRealm().getName();
            List<Object> subjAttr = ImmutableList.of(realmName);
            Map<String, Object> bodyAttr = Maps.newHashMap();
            bodyAttr.put("code", code);
            emailTemplateProvider
                    .setRealm(realm)
                    .setUser(user)
                    .setAttribute("realmName", realmName)
                    .send("otpSubject", subjAttr, OTP_EMAIL, bodyAttr);
            return true;
        } catch (EmailException e) {
            logger.error("Failed to send otp mail", e);
        }
        return false;
    }
}
