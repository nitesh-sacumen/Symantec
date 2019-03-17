package com.symantec.tree.nodes.test;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.MockitoAnnotations.initMocks;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.util.i18n.PreferredLocales;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.nodes.VIPIARegistration;
import com.symantec.tree.request.util.DenyRisk;

@Test
public class VIPIARegistrationTest {

	@Mock
	private VIPIARegistration.Config config;

	@Mock
	private DenyRisk denyRisk;

	@InjectMocks
	VIPIARegistration node;

	@BeforeMethod
	public void before() {

		initMocks(this);

	}

	@Test
	public void testProcessWithNoCallbacksWithMobile() throws NodeProcessException {
		// Given
		JsonValue sharedState = json(object(field(VIPIA.MOBILE_AUTH_DATA, "==hnagbbbdjvbu")));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		// When
		Action result = node.process(getContext(sharedState, preferredLocales, emptyList()));

		// Then
		assertThat(result.outcome).isEqualTo(null);
		assertThat(result.callbacks).hasSize(4);
		assertThat(result.callbacks.get(3)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(2)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(0)).isInstanceOf(TextOutputCallback.class);
		assertThat(result.callbacks.get(1)).isInstanceOf(TextOutputCallback.class);

		assertThat((Object) result.sharedState).isNull();
	}

	@Test
	public void testProcessWithNoCallbacksWithWeb() throws NodeProcessException {
		// Given
		JsonValue sharedState = json(object(field(VIPIA.MOBILE_AUTH_DATA, null)));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		// When
		Action result = node.process(getContext(sharedState, preferredLocales, emptyList()));

		// Then
		assertThat(result.outcome).isEqualTo(null);
		assertThat(result.callbacks).hasSize(2);
		assertThat(result.callbacks.get(0)).isInstanceOf(HiddenValueCallback.class);
		assertThat(result.callbacks.get(1)).isInstanceOf(ScriptTextOutputCallback.class);

		assertThat((Object) result.sharedState).isNull();
	}

	@Test
	public void testProcessWithTrueOutcomeInCaseOfMobile() throws NodeProcessException {
		HiddenValueCallback enterEventId = new HiddenValueCallback(VIPIA.EVENT_ID);
		HiddenValueCallback enterAuthData = new HiddenValueCallback(VIPIA.AUTH_DATA);

		JsonValue sharedState = json(object(field(VIPIA.MOBILE_AUTH_DATA, "==hnagbbbdjvbu")));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		enterEventId.setValue("VIP@123");
		enterAuthData.setValue("==hzdjghdkbndufh");

		List<Callback> cbList = new ArrayList<>();

		cbList.add(enterEventId);
		cbList.add(enterAuthData);

		given(denyRisk.denyRisk(any(), any(), any(), any(), any(), any())).willReturn("0000");

		// WHEN
		Action action = node.process(getContext(sharedState, preferredLocales, cbList));

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");

	}
	
	@Test
	public void testProcessWithFalseOutcomeInCaseOfMobile() throws NodeProcessException {
		HiddenValueCallback enterEventId = new HiddenValueCallback(VIPIA.EVENT_ID);
		HiddenValueCallback enterAuthData = new HiddenValueCallback(VIPIA.AUTH_DATA);

		JsonValue sharedState = json(object(field(VIPIA.MOBILE_AUTH_DATA, "==hnagbbbdjvbu")));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		enterEventId.setValue("VIP@123");
		enterAuthData.setValue("==hzdjghdkbndufh");

		List<Callback> cbList = new ArrayList<>();

		cbList.add(enterEventId);
		cbList.add(enterAuthData);

		given(denyRisk.denyRisk(any(), any(), any(), any(), any(), any())).willReturn("6009");

		// WHEN
		Action action = node.process(getContext(sharedState, preferredLocales, cbList));

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("FALSE");

	}
	
	@Test
	public void testProcessWithTrueOutcomeInCaseOfWeb() throws NodeProcessException {
		HiddenValueCallback webAuthData = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);

		JsonValue sharedState = json(object(field(VIPIA.MOBILE_AUTH_DATA,null)));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		webAuthData.setValue("==hzdjghdkbndufh");

		List<Callback> cbList = new ArrayList<>();

		cbList.add(webAuthData);

		given(denyRisk.denyRisk(any(), any(), any(), any(), any(), any())).willReturn("0000");

		// WHEN
		Action action = node.process(getContext(sharedState, preferredLocales, cbList));

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");

	}
	
	@Test
	public void testProcessWithFalseOutcomeInCaseOfWeb() throws NodeProcessException {
		HiddenValueCallback webAuthData = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);

		JsonValue sharedState = json(object(field(VIPIA.MOBILE_AUTH_DATA,null)));
		PreferredLocales preferredLocales = mock(PreferredLocales.class);

		webAuthData.setValue("==hzdjghdkbndufh");

		List<Callback> cbList = new ArrayList<>();

		cbList.add(webAuthData);

		given(denyRisk.denyRisk(any(), any(), any(), any(), any(), any())).willReturn("6009");

		// WHEN
		Action action = node.process(getContext(sharedState, preferredLocales, cbList));

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("FALSE");

	}

	private TreeContext getContext(JsonValue sharedState, PreferredLocales preferredLocales,
			List<? extends Callback> callbacks) {
		return new TreeContext(sharedState, new Builder().locales(preferredLocales).build(), callbacks);
	}

}
