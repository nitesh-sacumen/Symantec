package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.*;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import com.symantec.tree.nodes.VIPVerifyCodeAddCredential;
import com.symantec.tree.request.util.AddCredential;

import java.util.HashMap;
import java.util.Map;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * 
 * @author Symantec
 * @category test test class for "VIPVerifyCodeAddCredential"
 *
 */
@Test
public class VIPVerifyCodeAddCredTest {

	@Mock
	private AddCredential addCredential;
	
	@InjectMocks
	 private VIPVerifyCodeAddCredential node;
	
	@BeforeMethod
	public void before() {
		node = null;
		initMocks(this);

	}

	@Test
	public void nodeProcessWithTrueOutcome() throws NodeProcessException {
		given(addCredential.addCredential(any(),any(),any(),any(),any(),any())).willReturn("0000");
		TreeContext context = getTreeContext(new HashMap<>());

		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.sharedState.put(CRED_ID, "SYMC87283752");
		context.sharedState.put(SECURE_CODE, "487385");
		context.sharedState.put(MOB_NUM, "918147119089");
		context.sharedState.put(CRED_CHOICE, "SMS");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");

		//WHEN
		Action action = node.process(context);

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");

	}
	
	@Test
	public void nodeProcessWithFalseOutcome() throws NodeProcessException {
		given(addCredential.addCredential(any(),any(),any(),any(),any(),any())).willReturn("6004");
		TreeContext context = getTreeContext(new HashMap<>());

		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.sharedState.put(CRED_ID, "SYMC87283752");
		context.sharedState.put(SECURE_CODE, "487385");
		context.sharedState.put(MOB_NUM, "918147119089");
		context.sharedState.put(CRED_CHOICE, "SMS");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");

		//WHEN
		Action action = node.process(context);

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("FALSE");

	}

	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
	
	class CustomAnswer implements Answer<Boolean> {
	    @Override
	    public Boolean answer(InvocationOnMock invocation) throws Throwable {
	        return true;
	    }
	}
}
