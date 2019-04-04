package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.SECURE_CODE;
import static com.symantec.tree.config.Constants.MOB_NUM;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;

import com.symantec.tree.nodes.VIPEnterOTP;

import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.util.i18n.PreferredLocales;
import org.testng.annotations.Test;

/**
 * 
 * @author Symantec
 * @category test
 * test class for "VIPEnterOTP"
 *
 */
@Test
public class VIPEnterOTPTest {

	@Test
    public void testProcessWithNoCallbacksReturnsASingleCallback() {
        // Given
		VIPEnterOTP node = new VIPEnterOTP();
        JsonValue sharedState = json(object(field(MOB_NUM, "9112345671")));
        PreferredLocales preferredLocales = mock(PreferredLocales.class);
        ResourceBundle resourceBundle = new MockResourceBundle("Enter Your Security Code/OTP");
        given(preferredLocales.getBundleInPreferredLocale(any(), any())).willReturn(resourceBundle);

        // When
        Action result = node.process(getContext(sharedState, preferredLocales, emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(null);
        assertThat(result.callbacks).hasSize(1);
        assertThat(result.callbacks.get(0)).isInstanceOf(TextInputCallback.class);
        assertThat(((TextInputCallback) result.callbacks.get(0)).getPrompt()).isEqualTo("Enter Your Security Code/OTP");
        assertThat((Object) result.sharedState).isNull();
        assertThat(sharedState).isObject().contains(entry(MOB_NUM, "9112345671"));
    }

    @Test
    public void testProcessWithCallbacksAddsToState() {
    	VIPEnterOTP node = new VIPEnterOTP();
        JsonValue sharedState = json(object(field(MOB_NUM, "9112345671")));
        TextInputCallback callback = new TextInputCallback("prompt");
        callback.setText("secret");
        
        //when
        Action result = node.process(getContext(sharedState, new PreferredLocales(), singletonList(callback)));
        
        //then
        assertThat(result.outcome).isEqualTo("outcome");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().contains(MOB_NUM, "9112345671");
        assertThat(result.sharedState).isObject().contains(SECURE_CODE, "secret");
    }

    private TreeContext getContext(JsonValue sharedState, PreferredLocales preferredLocales,
                                   List<? extends Callback> callbacks) {
        return new TreeContext(sharedState, new Builder().locales(preferredLocales).build(), callbacks);
    }

    static class MockResourceBundle extends ResourceBundle {
        private final String value;

        MockResourceBundle(String value) {
            this.value = value;
        }

        @Override
        protected Object handleGetObject(String key) {
            return value;
        }

        @Override
        public Enumeration<String> getKeys() {
            return null;
        }
    }
}
