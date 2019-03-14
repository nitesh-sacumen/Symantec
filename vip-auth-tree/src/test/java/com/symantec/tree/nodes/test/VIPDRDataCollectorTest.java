package com.symantec.tree.nodes.test;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
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
import com.symantec.tree.config.Constants.VIPDR;
import com.symantec.tree.nodes.VIPDRDataCollector;

@Test
public class VIPDRDataCollectorTest {

	@Mock
	private VIPDRDataCollector.Config config;
	
	@BeforeMethod
	public void before() {

		initMocks(this);

	}
	
	@Test
	public void testProcessWithNoCallbacksReturnsASingleCallback() {
		// Given
		VIPDRDataCollector node = new VIPDRDataCollector();
		JsonValue sharedState = json(object(1));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		// When
		Action result = node.process(getContext(sharedState, preferredLocales, emptyList()));

		// Then
		assertThat(result.outcome).isEqualTo(null);
		assertThat(result.callbacks).hasSize(3);
		assertThat(result.callbacks.get(1)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(0)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(2)).isInstanceOf(HiddenValueCallback.class);

		assertThat((Object) result.sharedState).isNull();
	}
	
	@Test
    public void testProcessWithCallbacksInCaseOfWeb() {
		VIPDRDataCollector node = new VIPDRDataCollector();
        JsonValue sharedState = json(object(1));
        
		List<Callback> cbList = new ArrayList<>();

		HiddenValueCallback pcb = new HiddenValueCallback(VIPDR.VIP_DR_DATA_PAYLOAD);
		HiddenValueCallback hcb = new HiddenValueCallback(VIPDR.VIP_DR_DATA_HEADER);
		HiddenValueCallback scb = new HiddenValueCallback(VIPDR.VIP_DR_DATA_SIGNATURE);

		/**
		 * DR Data Payload  : {
                     "RootDetected" : false
                     }
		 */
		
		pcb.setValue("ewoiUm9vdERldGVjdGVkIiA6IGZhbHNlCn0=");
		hcb.setValue("testHeader");
		scb.setValue("signatureHeader");

		cbList.add(pcb);
		cbList.add(hcb);
		cbList.add(scb);

       //WHEN
       Action result = node.process(getContext(sharedState, new PreferredLocales(),cbList));
        
        //THEN
        assertThat(result.outcome).isEqualTo("outcome");
        assertThat(result.callbacks.isEmpty());
        assertThat(sharedState).isObject().contains(entry("RootDetected", "false"));

    }
	
	private TreeContext getContext(JsonValue sharedState, PreferredLocales preferredLocales,
			List<? extends Callback> callbacks) {
		return new TreeContext(sharedState, new Builder().locales(preferredLocales).build(), callbacks);
	}
}
