package com.symantec.tree.nodes;

import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;


@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass =
VIPForceDRDataEval.Config.class)
public class VIPForceDRDataEval extends AbstractDecisionNode{
	
	private final Config config;
	private final Debug debug = Debug.getInstance("VIP");

	
	/**
	 * Configuration for the node.
	 */
	public interface Config {
		
		@Attribute(order = 100)
        default DRDataFields DRDataFields() {
            return DRDataFields.rootDetected;
        }
	}
	
	 public enum DRDataFields {
		 rootDetected,
		 passcodeDisabled,
		 affected,
		 os
	    }
	
	
	@Inject
	public VIPForceDRDataEval(@Assisted Config config) {
		this.config = config;
	}
	
	public Action process(TreeContext context) {

		debug.message("collecting DR Fields ........");
		return goTo(true).build();
		
	}
	

}
