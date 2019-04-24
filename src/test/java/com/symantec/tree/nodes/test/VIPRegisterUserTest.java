package com.symantec.tree.nodes.test;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static com.symantec.tree.config.Constants.NO_CREDENTIALS_REGISTERED;
import com.symantec.tree.nodes.VIPRegisterUser;
import com.symantec.tree.request.util.VIPCreateUser;

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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
/**
 * 
 * @author Symantec
 * @category test
 * test class for "VIPRegisterUser"
 *
 */
@Test
public class VIPRegisterUserTest {
	
	@Mock
	private VIPCreateUser vIPCreateUser;
	
	@InjectMocks
	private VIPRegisterUser node;
	
	
	@BeforeMethod
	public void before() {

		node=null;
		initMocks(this);
	}
	
	@Test
	public void testProcessWithTrueOutcome() throws NodeProcessException {
		given(vIPCreateUser.createVIPUser(any(), any(), any())).willReturn(true);
		TreeContext context = getTreeContext(new HashMap<>());
		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.transientState.put(NO_CREDENTIALS_REGISTERED, "false");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");


		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("true");
	}
	
	@Test
	public void testProcessWithFalseOutcome() throws NodeProcessException {
		given(vIPCreateUser.createVIPUser(any(), any(), any())).willReturn(false);
		TreeContext context = getTreeContext(new HashMap<>());
		context.sharedState.put(SharedStateConstants.USERNAME, "vip123");
		context.transientState.put(NO_CREDENTIALS_REGISTERED, "false");
		context.sharedState.put(KEY_STORE_PATH,"C://Users//keystore.ks");
		context.sharedState.put(KEY_STORE_PASS,"WORK12345");


		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("false");
	}
	

	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
}
