package com.symantec.tree.nodes.test;

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
import com.symantec.tree.nodes.VIPDRDataOSDecisionNode;

public class VIPDRDataOSDecisionNodeTest {
	@Mock
	private VIPDRDataOSDecisionNode.Config config;
	
	@InjectMocks
	VIPDRDataOSDecisionNode node;
	
	@BeforeMethod
	public void before() {
  		initMocks(this);
	}
	
	@Test
	public void testProcessWithiOSOutcome() throws NodeProcessException {
		
        TreeContext context = getTreeContext(new HashMap<>());

      
		context.sharedState.put("os","\"iOS\"");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(action.outcome).isEqualTo("iOS");
	}
	
	@Test
	public void testProcessWithAndroidOutcome() throws NodeProcessException {
		
        TreeContext context = getTreeContext(new HashMap<>());

      
		context.sharedState.put("os","\"android\"");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(action.outcome).isEqualTo("ANDROID");
	}
	
	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
	
}
