package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static com.symantec.tree.config.Constants.SECURE_CODE;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;

import com.symantec.tree.nodes.VIPOTPCheck;
import com.symantec.tree.nodes.VIPOTPCheck.Symantec;
import com.symantec.tree.request.util.CheckVIPOtp;

import java.util.HashMap;
import java.util.Map;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.core.CoreWrapper;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * 
 * @author Symantec
 * @category test test class for "VIPOTPCheck"
 *
 */
@Test
public class VIPOtpCheckTest {
	@Mock
	private VIPOTPCheck.Config config;
	@Mock
	private CoreWrapper coreWrapper;
	@Mock
	private CheckVIPOtp checkOtp;
	@InjectMocks
	private VIPOTPCheck node;
	
	
	@BeforeMethod
	public void before() {

		initMocks(this);

	}

	@Test
	public void testProcessWithTrueOutcome() throws NodeProcessException {
		TreeContext context = getTreeContext(new HashMap<>());

		given(checkOtp.checkOtp(any(), any(), any(), any())).willReturn("0000");
		given(checkOtp.sendOutput(any(), any())).willReturn(goTo(Symantec.TRUE).build());

		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.sharedState.put(SECURE_CODE, "78695981");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");

		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");

	}
	
	@Test
	public void testProcessWithFalseOutcome() throws NodeProcessException {
		TreeContext context = getTreeContext(new HashMap<>());

		given(checkOtp.checkOtp(any(), any(), any(), any())).willReturn("6009");
		given(checkOtp.sendOutput(any(), any())).willReturn(goTo(Symantec.FALSE).build());

		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.sharedState.put(SECURE_CODE, "78695981");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");

		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.outcome).isEqualTo("FALSE");

	}

	

	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
	
	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}
}
