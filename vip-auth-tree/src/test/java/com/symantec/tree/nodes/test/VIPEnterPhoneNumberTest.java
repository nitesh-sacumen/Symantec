package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.CRED_CHOICE;
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
import static org.mockito.MockitoAnnotations.initMocks;

import com.symantec.tree.nodes.VIPEnterPhoneNumber;
import com.symantec.tree.request.util.SMSVoiceRegister;

import java.util.Enumeration;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
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
 * test class for "VIPEnterPhoneNumber"
 *
 */
@Test
public class VIPEnterPhoneNumberTest {
	
	@Mock
	private CoreWrapper coreWrapper;
	
	@Mock
	private VIPEnterPhoneNumber.Config config;
	
	@Mock 
	private SMSVoiceRegister svRegister;
	
	
	@InjectMocks
	private VIPEnterPhoneNumber node ;
	
	@BeforeMethod
	public void setup() throws NodeProcessException {
		node = null;
		initMocks(this);
	}	

	@Test
    public void testProcessWithNoCallbacksReturnsASingleCallback() throws NodeProcessException {
        // Given
        JsonValue sharedState = json(object(field(CRED_CHOICE, "SMS")));
        PreferredLocales preferredLocales = mock(PreferredLocales.class);
        ResourceBundle resourceBundle = new MockResourceBundle("Enter Your Phone Number");
        given(preferredLocales.getBundleInPreferredLocale(any(), any())).willReturn(resourceBundle);

        // When
        Action result = node.process(getContext(sharedState, preferredLocales, emptyList()));

        // Then
        assertThat(result.outcome).isEqualTo(null);
        assertThat(result.callbacks).hasSize(1);
        assertThat(result.callbacks.get(0)).isInstanceOf(NameCallback.class);
        assertThat(((NameCallback) result.callbacks.get(0)).getPrompt()).isEqualTo("Enter Your Phone Number");
        assertThat((Object) result.sharedState).isNull();
        assertThat(sharedState).isObject().containsExactly((entry(CRED_CHOICE,"SMS")));
    }

    @Test
    public void testProcessWithCallbacksAddsToState() throws NodeProcessException {
    	//Given
		given(svRegister.smsRegister(any(),any(),any())).willReturn("0000");
    	JsonValue sharedState = json(object(field(CRED_CHOICE, "SMS")));
    	NameCallback callback = new NameCallback("prompt");
        callback.setName("918787878111");
        
        //when
        Action result = node.process(getContext(sharedState, new PreferredLocales(), singletonList(callback)));
        
        //then
        assertThat(result.outcome).isEqualTo("TRUE");
        assertThat(result.callbacks).isEmpty();
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
