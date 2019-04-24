package com.symantec.tree.nodes.test;

import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.MockitoAnnotations.initMocks;


import java.util.HashMap;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import com.symantec.tree.nodes.VIPGenerateActivationCode;
import com.symantec.tree.request.util.GenerateActivationCode;

/**
 * 
 * @author Symantec
 * @category test test class for "VIPGenerateActivationCode"
 *
 */
@Test
public class VIPGenerateActivationCodeTest {
	@Mock
	private VIPGenerateActivationCode.Config config;
	
	@Mock
	private GenerateActivationCode generateActivationCode;
	
	@InjectMocks
	private VIPGenerateActivationCode node;

	@BeforeMethod
	public void before() {
		initMocks(this);

	}

	@Test
	public void nodeProcessWithTrueOutcome() throws NodeProcessException {
		//Given
		TreeContext context = getTreeContext(new HashMap<>());
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");
		when(generateActivationCode.generateCode(any(),any())).thenReturn("0000,vip@123");
	

		// WHEN
		Action action = node.process(context);
		
		//Then
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("true");

	}
	
	@Test
	public void nodeProcessWithFalseOutcome() throws NodeProcessException {
		//Given
		TreeContext context = getTreeContext(new HashMap<>());
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");
		when(generateActivationCode.generateCode(any(),any())).thenReturn("0780,vip@123");
	

		// WHEN
		Action action = node.process(context);
		
		//Then
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("false");

	}

	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
}
