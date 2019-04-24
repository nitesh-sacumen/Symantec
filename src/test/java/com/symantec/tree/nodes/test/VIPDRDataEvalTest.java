package com.symantec.tree.nodes.test;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.json.test.assertj.AssertJJsonValueAssert.assertThat;
import static org.mockito.BDDMockito.given;
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

import com.symantec.tree.nodes.VIPDRDataEval;

@Test
public class VIPDRDataEvalTest {

	@Mock
	private VIPDRDataEval.Config config;
	
	@InjectMocks
	VIPDRDataEval node;
	
	@BeforeMethod
	public void before() {
  		initMocks(this);
	}
	
	@Test
	public void testProcessWithTrueOutcome() throws NodeProcessException {
		
		given(config.DRDataFields()).willReturn(VIPDRDataEval.DRDataFields.rootDetected);
        TreeContext context = getTreeContext(new HashMap<>());

      
		context.sharedState.put("rootDetected","\"true\"");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(context.sharedState).isObject().contains(entry("rootDetected","\"true\""));
	    assertThat(action.outcome).isEqualTo("true");
	}
	
	@Test
	public void testProcessWithFalseOutcome() throws NodeProcessException {
		
		given(config.DRDataFields()).willReturn(VIPDRDataEval.DRDataFields.rootDetected);
        TreeContext context = getTreeContext(new HashMap<>());

      
		context.sharedState.put("rootDetected","\"false\"");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(context.sharedState).isObject().contains(entry("rootDetected","\"false\""));
	    assertThat(action.outcome).isEqualTo("false");
	}
	
	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
	
}
