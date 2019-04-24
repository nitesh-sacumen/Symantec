package com.symantec.tree.nodes.test;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.object;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.MockitoAnnotations.initMocks;
import java.io.IOException;
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

import com.symantec.tree.nodes.VIPSearchUser;
import com.symantec.tree.request.util.VIPGetUser;

/**
 * 
 * @author Symantec
 * @category test test class for "VIPSearchUser"
 *
 */
@Test
public class VIPSearchUserTest {
	
	@Mock
	private CoreWrapper coreWrapper;
	
	@Mock
	private VIPSearchUser.Config config;
	
	@Mock 
	private VIPGetUser vipSearchUser;
	
	
	@InjectMocks
	private VIPSearchUser node ;

	@BeforeMethod
	public void setup() throws NodeProcessException {
		node = null;
		initMocks(this);
	}	

	@Test
	public void nodeProcessWithTrueOutcome() throws NodeProcessException, IOException {
		given(vipSearchUser.viewUserInfo(any(), any(),any())).willReturn("0000");
	    TreeContext context = getTreeContext(new HashMap<>());
	                    
		context.sharedState.put(SharedStateConstants.USERNAME, "vip");

		//WHEN
		Action action = node.process(context);

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");

	}
	
	@Test
	public void nodeProcessWithFalseOutcome() throws NodeProcessException, IOException {
		given(vipSearchUser.viewUserInfo(any(), any(), any())).willReturn("6003");
	    TreeContext context = getTreeContext(new HashMap<>());
	                    
		context.sharedState.put(SharedStateConstants.USERNAME, "vip");

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
}
