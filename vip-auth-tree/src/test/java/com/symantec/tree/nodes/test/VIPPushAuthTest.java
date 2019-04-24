package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import java.util.HashMap;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.ExternalRequestContext.Builder;
import org.forgerock.openam.core.CoreWrapper;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.symantec.tree.nodes.VIPPushAuth;
import com.symantec.tree.request.util.AuthenticateUser;
/**
 * 
 * @author Symantec
 * @category test
 * test class for "VIPPushAuth"
 *
 */
public class VIPPushAuthTest {
	@Mock
	private Map<String, String> vipPushCodeMap = new HashMap<>();;

	@Mock
	private CoreWrapper coreWrapper;
	
	@Mock
	private  AuthenticateUser pushAuthUser;
	
	@Mock
	private VIPPushAuth.Config config;
	
	@InjectMocks
	private VIPPushAuth node;
	
	@BeforeMethod
	public void before()throws Exception {
		node = null;
		initMocks(this);
		given(config.displayMsgText()).willReturn("Sacumen Push");
		given(config.displayMsgTitle()).willReturn("Sacumen Push");
		given(config.displayMsgTitle()).willReturn("www.sacumen.com");
}

	@Test
	public void testProcessWithTrueOutcome() throws NodeProcessException {
		given(pushAuthUser.authUser(any(), any(), any(),any(),any(),any())).willReturn("vip@123");
		JsonValue sharedState = json(object(field(USERNAME, "bob")));
		sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		sharedState.put(KEY_STORE_PASS,"WORK12345");
		JsonValue transientState = json(object(1));

		// WHEN
		Action action = node.process(getContext(sharedState,transientState));
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("true");
	}
	@Test
	public void testProcessWithFalseOutcome() throws NodeProcessException {
		given(pushAuthUser.authUser(any(), any(), any(),any(),any(),any())).willReturn("");
		JsonValue sharedState = json(object(field(USERNAME, "bob")));
		sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		sharedState.put(KEY_STORE_PASS,"WORK12345");
		JsonValue transientState = json(object(1));

		// WHEN
		Action action = node.process(getContext(sharedState,transientState));
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("false");
	}
	

	private TreeContext getContext(JsonValue sharedState, JsonValue transientState) {
        return new TreeContext(sharedState, transientState, new Builder().build(), emptyList());
    }
}
