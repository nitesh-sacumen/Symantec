package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.CRED_CHOICE;
import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;

import com.symantec.tree.nodes.VIPOTPAuth;
import com.symantec.tree.request.util.SmsDeviceRegister;
import com.symantec.tree.request.util.VoiceDeviceRegister;

import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * 
 * @author Symantec
 * @category test
 * test class for "VIPOTPAuth"
 *
 */
@Test
public class VIPOTPAuthTest {
	@Mock
	private VIPOTPAuth.Config config;
	
	@Mock
	private CoreWrapper coreWrapper;
	
	@Mock
	private VoiceDeviceRegister voiceDeviceRegister;
	
	@Mock
	private SmsDeviceRegister smsDeviceRegister;
	
	
	@InjectMocks
	private VIPOTPAuth node ;
	

	@BeforeMethod
	public void before() {

		node = null;
		initMocks(this);
		HashMap<Integer, String> creds = new HashMap<>();
		creds.put(0,"SMS");
		creds.put(1,"VOICE");
		when(config.referrerCredList()).thenReturn(creds);


	}
	@Test
	public void nodeProcessWithDefaultBehaviour() throws Exception {
		PreferredLocales preferredLocales = mock(PreferredLocales.class);
		ResourceBundle resourceBundle = new MockResourceBundle("Choose Your Cred Type");
		given(preferredLocales.getBundleInPreferredLocale(any(), any())).willReturn(resourceBundle);
		JsonValue sharedState = json(object(1));
		sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		sharedState.put(KEY_STORE_PASS,"WORK12345");
		
		// WHEN
		Action action = node.process(getContext(sharedState, new PreferredLocales(),emptyList()));
		
		//THEN
		assertThat(action.callbacks).hasSize(1);
		assertThat(action.outcome).isEqualTo(null);
		assertThat(action.callbacks.get(0)).isInstanceOf(ChoiceCallback.class);
		assertThat(((ChoiceCallback) action.callbacks.get(0)).getPrompt()).isEqualTo("Choose Your Cred Type");

	}
	
	@Test
    public void nodeProcessWithSMSOutcome() throws NodeProcessException {
		given(smsDeviceRegister.smsDeviceRegister(any(),any(),any(),any())).willReturn(true);
		JsonValue sharedState = json(object(1));
		sharedState.put(KEY_STORE_PATH,"C://Users");
		sharedState.put(KEY_STORE_PASS,"WORK12345");
		Collection<String> values = config.referrerCredList().values();
		String[] targetArray = values.toArray(new String[0]);
		ChoiceCallback callback = new ChoiceCallback("Choose Your Cred Type",targetArray,
				0,false);
		callback.setSelectedIndex(0);
		
		//WHEN
        Action result = node.process(getContext(sharedState, new PreferredLocales(), singletonList(callback)));
        
        //THEN
        assertThat(result.outcome).isEqualTo("SMS");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().contains(entry(CRED_CHOICE,"SMS"));
        assertThat(sharedState).isObject().contains(entry(CRED_CHOICE,"SMS"));
    }
	
	@Test
    public void nodeProcessWithVOICEOutcome() throws NodeProcessException {
		given(voiceDeviceRegister.voiceDeviceRegister(any(),any(),any(),any())).willReturn(true);
		JsonValue sharedState = json(object(1));
		sharedState.put(KEY_STORE_PATH,"C://Users");
		sharedState.put(KEY_STORE_PASS,"WORK12345");
		Collection<String> values = config.referrerCredList().values();
		String[] targetArray = values.toArray(new String[0]);
		ChoiceCallback callback = new ChoiceCallback("Choose Your Cred Type",targetArray,
				0,false);
		callback.setSelectedIndex(1);
        Action result = node.process(getContext(sharedState, new PreferredLocales(), singletonList(callback)));
        assertThat(result.outcome).isEqualTo("VOICE");
        assertThat(result.callbacks).isEmpty();
        assertThat(result.sharedState).isObject().contains(CRED_CHOICE,"VOICE");
        assertThat(sharedState).isObject().contains(entry(CRED_CHOICE,"VOICE"));
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
