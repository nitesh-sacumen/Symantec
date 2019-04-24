package com.symantec.tree.nodes.test;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.initMocks;

import java.util.ArrayList;
import java.util.List;
import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.util.i18n.PreferredLocales;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.nodes.VIPIADataCollector;

@Test
public class VIPAIDataCollectorTest {

	@Mock
	private VIPIADataCollector.Config config;

	@BeforeMethod
	public void before() {

		initMocks(this);

	}

	@Test
	public void testProcessWithNoCallbacksReturnsASingleCallback() {
		// Given
		VIPIADataCollector node = new VIPIADataCollector(config);
		JsonValue sharedState = json(object(1));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		// When
		Action result = node.process(getContext(sharedState, preferredLocales, emptyList()));

		// Then
		assertThat(result.outcome).isEqualTo(null);
		assertThat(result.callbacks).hasSize(4);
		assertThat(result.callbacks.get(1)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(0)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(2)).isInstanceOf(ScriptTextOutputCallback.class);
		assertThat(result.callbacks.get(3)).isInstanceOf(ScriptTextOutputCallback.class);

		assertThat((Object) result.sharedState).isNull();
	}
	
	@Test
    public void testProcessWithCallbacksInCaseOfMobile() {
		VIPIADataCollector node = new VIPIADataCollector(config);
        JsonValue sharedState = json(object(field(VIPIA.SCRIPT_URL, "test.js")));
        
		List<Callback> cbList = new ArrayList<>();

		HiddenValueCallback ncb = new HiddenValueCallback(VIPIA.MOBILE_AUTH_DATA);
		HiddenValueCallback hcb = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);
		
		ncb.setValue("==fjkhnmdiubhyd");
		hcb.setValue(VIPIA.DEVICE_FINGERPRINT);
		cbList.add(ncb);
		cbList.add(hcb);


        
        //WHEN
        Action result = node.process(getContext(sharedState, new PreferredLocales(),cbList));
        
        //THEN
        assertThat(result.outcome).isEqualTo("outcome");
        assertThat(result.callbacks.isEmpty());
        assertThat(sharedState).isObject().contains(entry(VIPIA.MOBILE_AUTH_DATA, "==fjkhnmdiubhyd"));
        assertThat(sharedState).isObject().contains(entry(VIPIA.AUTH_DATA, "==fjkhnmdiubhyd"));

    }
	
	@Test
    public void testProcessWithCallbacksInCaseOfWeb() {
		VIPIADataCollector node = new VIPIADataCollector(config);
        JsonValue sharedState = json(object(field(VIPIA.SCRIPT_URL, "test.js")));
        
		List<Callback> cbList = new ArrayList<>();

		HiddenValueCallback ncb = new HiddenValueCallback(VIPIA.MOBILE_AUTH_DATA);
		HiddenValueCallback hcb = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);
		
		hcb.setValue("==fjkhnmdiubhyd");
		ncb.setValue(VIPIA.MOBILE_AUTH_DATA);
		cbList.add(ncb);
		cbList.add(hcb);


        
        //WHEN
        Action result = node.process(getContext(sharedState, new PreferredLocales(),cbList));
        
        //THEN
        assertThat(result.outcome).isEqualTo("outcome");
        assertThat(result.callbacks.isEmpty());
        assertThat(sharedState).isObject().contains(entry(VIPIA.AUTH_DATA, "==fjkhnmdiubhyd"));
        assertThat(sharedState).isObject().contains(entry(VIPIA.DEVICE_FINGERPRINT,"==fjkhnmdiubhyd"));

    }

	private TreeContext getContext(JsonValue sharedState, PreferredLocales preferredLocales,
			List<? extends Callback> callbacks) {
		return new TreeContext(sharedState, new Builder().locales(preferredLocales).build(), callbacks);
	}

}
