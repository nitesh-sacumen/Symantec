package com.symantec.tree.nodes.test;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.initMocks;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.util.i18n.PreferredLocales;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.symantec.tree.config.Constants.VIPDR;
import com.symantec.tree.nodes.VIPDRDataCollector;
import com.symantec.tree.request.util.DeviceHygieneVerification;

@Test
public class VIPDRDataCollectorTest {

	@Mock
	private VIPDRDataCollector.Config config;
	
	@Mock
	private DeviceHygieneVerification deviceHygieneVerification;
	
	@InjectMocks
	VIPDRDataCollector node;

	
	@BeforeMethod
	public void before() {

		initMocks(this);

	}
	
	@Test
	public void testProcessWithNoCallbacksReturnsASingleCallback() throws NodeProcessException {
		// Given 
		
		JsonValue sharedState = json(object(1));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);
		
		String[] outcome = {VIPDR.DEVICE_HYGIENE_VERIFICATION_SUCCESS_MSG,VIPDR.DEVICE_HYGIENE_VERIFICATION_WITH_VIP_SUCCESS_MSG};
		given(deviceHygieneVerification.validateDHSignatureAndChain(any(),any(),any(),any())).willReturn(outcome);


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
    public void testProcessWithCallbacksInCaseOfWeb() throws NodeProcessException {
		
		String[] outcome = {VIPDR.DEVICE_HYGIENE_VERIFICATION_SUCCESS_MSG,VIPDR.DEVICE_HYGIENE_VERIFICATION_WITH_VIP_SUCCESS_MSG};
		given(deviceHygieneVerification.validateDHSignatureAndChain(any(),any(),any(),any())).willReturn(outcome);
		
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
        assertThat(result.outcome).isEqualTo("true");
        assertThat(result.callbacks.isEmpty());
        assertThat(sharedState).isObject().contains(entry("RootDetected", "false"));

    }
	
	private TreeContext getContext(JsonValue sharedState, PreferredLocales preferredLocales,
			List<? extends Callback> callbacks) {
		return new TreeContext(sharedState, new Builder().locales(preferredLocales).build(), callbacks);
	}
}
