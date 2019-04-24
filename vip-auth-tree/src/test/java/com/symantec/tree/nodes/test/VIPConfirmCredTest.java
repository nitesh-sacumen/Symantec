package com.symantec.tree.nodes.test;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.util.i18n.PreferredLocales;
import org.testng.annotations.Test;
import com.symantec.tree.nodes.VIPConfirmCredential;
import static com.symantec.tree.config.Constants.CONFIRM_CRED_CHOICE;

/**
 * 
 * @author Symantec
 * @category test test class for "VIPConfirmCredential"
 *
 */
@Test
public class VIPConfirmCredTest {

	@Test
	public void nodeProcessWithDefaultBehaviour() throws Exception {
		VIPConfirmCredential node = new VIPConfirmCredential();
		PreferredLocales preferredLocales = mock(PreferredLocales.class);
		ResourceBundle resourceBundle = new MockResourceBundle("Add More Credentials");
		given(preferredLocales.getBundleInPreferredLocale(any(), any())).willReturn(resourceBundle);
		JsonValue sharedState = json(object(1));
		
		// WHEN
		Action action = node.process(getContext(sharedState, new PreferredLocales(),emptyList()));
		
		//THEN
		assertThat(action.callbacks).hasSize(2);
		assertThat(action.outcome).isEqualTo(null);
		assertThat(action.callbacks.get(0)).isInstanceOf(TextOutputCallback.class);
		assertThat(action.callbacks.get(1)).isInstanceOf(ConfirmationCallback.class);
		assertThat(((ConfirmationCallback) action.callbacks.get(1)).getPrompt()).isEqualTo("Add More Credentials");

	}
	
	@Test
    public void nodeProcessWithYesOutcome() {
		VIPConfirmCredential node = new VIPConfirmCredential();
		JsonValue sharedState = json(object(1));
		ConfirmationCallback callback = new ConfirmationCallback("Add More Credentials", 0,
				new String[] { "YES", "NO" }, 0);
		callback.setSelectedIndex(0);
		
		//WHEN
        Action result = node.process(getContext(sharedState, new PreferredLocales(), singletonList(callback)));
        
        //THEN
        assertThat(result.outcome).isEqualTo("YES");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().contains(CONFIRM_CRED_CHOICE,"YES");
        assertThat(sharedState).isObject().containsExactly(entry(CONFIRM_CRED_CHOICE,"YES"));
    }
	
	@Test
    public void nodeProcessWithNoOutcome() {
		VIPConfirmCredential node = new VIPConfirmCredential();
		JsonValue sharedState = json(object(1));
		ConfirmationCallback callback = new ConfirmationCallback("Add More Credentials", 0,
				new String[] { "YES", "NO" }, 0);
		callback.setSelectedIndex(1);
		
		//WHEN
        Action result = node.process(getContext(sharedState, new PreferredLocales(), singletonList(callback)));
        
        //THEN
        assertThat(result.outcome).isEqualTo("NO");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().contains(CONFIRM_CRED_CHOICE,"NO");
        assertThat(sharedState).isObject().containsExactly(entry(CONFIRM_CRED_CHOICE,"NO"));
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
