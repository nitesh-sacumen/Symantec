package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.CRED_ID;
import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import java.util.HashMap;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.symantec.tree.nodes.VIPPollPushReg;
import com.symantec.tree.request.util.AuthPollPush;
/**
 * 
 * @author Symantec
 * @category test
 * test class for "VIPPollPushReg"
 *
 */
@Test
public class VIPPollPushRegTest {
	@Mock
	private VIPPollPushReg.Config config;
	
	@Mock
	private CoreWrapper coreWrapper;
	
	@Mock
	private  AuthPollPush pollPush;
	
	@InjectMocks
	private VIPPollPushReg node;
	
	
	
	@BeforeMethod
	public void before() {

		node = null;
		initMocks(this);

	}
	
	
	@Test
	public void testProcessWithTrueOutcome() throws NodeProcessException {
		given(pollPush.authPollPush(any(), any(), any())).willReturn("7000");
		TreeContext context = getTreeContext(new HashMap<>());
		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.sharedState.put(CRED_ID, "SYMC78695981");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");

		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");
	}
	
	@Test
	public void testProcessWithUnansweredOutcome() throws NodeProcessException {
		given(pollPush.authPollPush(any(), any(), any())).willReturn("7001");
		TreeContext context = getTreeContext(new HashMap<>());
		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.sharedState.put(CRED_ID, "SYMC78695981");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");

		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("UNANSWERED");
	}
	

	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
}
