package com.symantec.tree.nodes.test;

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
import org.forgerock.openam.auth.node.api.TreeContext;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.symantec.tree.nodes.VIPIADenyRisk;
import com.symantec.tree.request.util.DenyRisk;

@Test
public class VIPIADenyRiskTest {

	@Mock
	private VIPIADenyRisk.Config config;

	@Mock
	private DenyRisk denyRisk;

	@InjectMocks
	VIPIADenyRisk node;

	@BeforeMethod
	public void before() {
		initMocks(this);
	}

	@Test
	public void testProcessWithTrueOutcome() throws NodeProcessException {
		TreeContext context = getTreeContext(new HashMap<>());

		given(denyRisk.denyRisk(any(), any(), any(), any(), any(),any(),any())).willReturn("0000");

		// WHEN
		Action action = node.process(context);

		// THEN
		assertThat(action.callbacks).isEmpty();
		assertThat(action.outcome).isEqualTo("TRUE");
	}

	@Test
	public void testProcessWithFalseOutcome() throws NodeProcessException {
		TreeContext context = getTreeContext(new HashMap<>());

		given(denyRisk.denyRisk(any(), any(), any(), any(), any(),any(),any())).willReturn("6009");

		// WHEN
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
