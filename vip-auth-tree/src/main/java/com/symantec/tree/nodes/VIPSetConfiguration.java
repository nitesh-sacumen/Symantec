package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.AUTHENTICATION_SERVICE_URL;
import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static com.symantec.tree.config.Constants.MANAGEMENT_SERVICE_URL;
import static com.symantec.tree.config.Constants.QUERY_SERVICE_URL;
import static com.symantec.tree.config.Constants.SDK_SERVICE_URL;


import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;

import com.google.inject.assistedinject.Assisted;
import com.symantec.tree.request.util.GetVIPServiceURL;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * 
 * Setting and adding all the VIP Service URLs to the shared state.
 * 
 *
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = VIPSetConfiguration.Config.class)
public class VIPSetConfiguration extends SingleOutcomeNode {
	
	private final Config config;
 
	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100, requiredValue = true)
		String Key_Store_Path();

		@Attribute(order = 200, requiredValue = true)
		String Key_Store_Password();

		@Attribute(order = 300, requiredValue = true)
		String Authentication_Service_URL();

		@Attribute(order = 400, requiredValue = true)
		String Query_Service_URL();

		@Attribute(order = 500, requiredValue = true)
		String Management_Service_URL();

		@Attribute(order = 600, requiredValue = true)
		String SDK_Service_URL();
	}

	    /**
		 * Create the node.
		 *
		 */
		@Inject
		public VIPSetConfiguration(@Assisted Config config) {
			this.config = config;
		}
		
		@Override
		public Action process(TreeContext context) throws NodeProcessException{
			context.sharedState.put(KEY_STORE_PATH,config.Key_Store_Path());
			context.sharedState.put(KEY_STORE_PASS,config.Key_Store_Password());
			
			GetVIPServiceURL vip = GetVIPServiceURL.getInstance();
			vip.setServiceURL(config.Management_Service_URL(), config.Authentication_Service_URL(),
					config.Query_Service_URL(),config.SDK_Service_URL());
			
			vip.setKeyStorePasswod(config.Key_Store_Password());
			vip.setKeyStorePath(config.Key_Store_Path());
			vip.setUserName(context.sharedState.get(SharedStateConstants.USERNAME).asString());

            return goToNext().build();
		}

}
