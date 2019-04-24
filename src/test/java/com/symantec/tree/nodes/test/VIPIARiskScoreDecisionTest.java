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

import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.nodes.VIPDRDataEval;
import com.symantec.tree.nodes.VIPIARiskScoreDecision;

@Test
public class VIPIARiskScoreDecisionTest {
	
	@Mock
	private VIPIARiskScoreDecision.Config config;
	
	@InjectMocks
	VIPIARiskScoreDecision node;
	
	@BeforeMethod
	public void before() {
  		initMocks(this);
	}
	
	@Test
	public void testProcessWithLOWOutcome() throws NodeProcessException {
		
		given(config.low_threshold()).willReturn(20);
		given(config.high_threshold()).willReturn(80);

        TreeContext context = getTreeContext(new HashMap<>());

      
		context.transientState.put(VIPIA.SCORE,"10");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(action.outcome).isEqualTo("LOW");
	}
	
	@Test
	public void testProcessWithMEDIUMOutcome() throws NodeProcessException {
		
		given(config.low_threshold()).willReturn(20);
		given(config.high_threshold()).willReturn(80);

        TreeContext context = getTreeContext(new HashMap<>());

      
		context.transientState.put(VIPIA.SCORE,"70");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(action.outcome).isEqualTo("MEDIUM");
	}
	
	@Test
	public void testProcessWithHIGHOutcome() throws NodeProcessException {
		
		given(config.low_threshold()).willReturn(20);
		given(config.high_threshold()).willReturn(80);

        TreeContext context = getTreeContext(new HashMap<>());

      
		context.transientState.put(VIPIA.SCORE,"100");
				
		// WHEN
		Action action = node.process(context);
		
		//THEN
		assertThat(action.callbacks).isEmpty();
	    assertThat(action.outcome).isEqualTo("HIGH");
	}
	
	private TreeContext getTreeContext(Map<String, String[]> parameters) {
		return new TreeContext(JsonValue.json(object(1)),
				new ExternalRequestContext.Builder().parameters(parameters).build(), emptyList());
	}
}
