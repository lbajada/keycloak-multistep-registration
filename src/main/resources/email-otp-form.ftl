<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "form">
        <p>Enter access code</p>
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="otp" class="${properties.kcLabelClass!}">${msg("loginOtpOneTime")}</label>
                </div>

                <div class="${properties.kcInputWrapperClass!}">
                    <input id="otp" name="otp" autocomplete="off" type="text" class="${properties.kcInputClass!}"
                           autofocus aria-invalid="<#if messagesPerField.existsError('totp')>true</#if>"/>
                    <#if messagesPerField.existsError('totp')>
                        <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}"
                              aria-live="polite">${kcSanitize(messagesPerField.get('totp'))?no_esc}</span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                           name="submit" id="kc-submit" type="submit" value="${msg("doSubmit")}"/>
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                           name="resend" id="kc-resend" type="submit" value="${msg("doResend")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
