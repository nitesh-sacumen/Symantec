package com.symantec.tree.nodes;

import javax.inject.Inject;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import com.google.inject.assistedinject.Assisted;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;


@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass =
VIPForceDRDataEval.Config.class)
public class VIPForceDRDataEval extends AbstractDecisionNode{
	
	private final Config config;
    private Logger logger = LoggerFactory.getLogger(VIPForceDRDataEval.class);

	
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

		logger.info("collecting DR Fields ........");
		return goTo(true).build();
		
	}
	

}
