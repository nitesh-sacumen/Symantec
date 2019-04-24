package com.symantec.tree.nodes;
import static com.symantec.tree.config.Constants.NO_CREDENTIALS_REGISTERED;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.request.util.GetVIPServiceURL;
import com.symantec.tree.request.util.VIPCreateUser;
import javax.inject.Inject;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Register User" node with TRUE,FALSE outcome. If TRUE, it will go to "VIP Display Creds". If False, go to
 *             "Failure".
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPRegisterUser.Config.class)
public class VIPRegisterUser extends AbstractDecisionNode {

    private Logger logger = LoggerFactory.getLogger(VIPRegisterUser.class);

	private VIPCreateUser vIPCreateUser;


	/**
	 * Configuration for the node.
	 */
	public interface Config {

	}

	/**
	 * Create the node.
	 *
	 */
	@Inject
	public VIPRegisterUser(VIPCreateUser vIPCreateUser) {
		this.vIPCreateUser = vIPCreateUser;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.info("VIP Register User...");
		
		String credRegistrationStatus = context.transientState.get(NO_CREDENTIALS_REGISTERED).toString();
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		boolean isVIPProfileRegistered;

		logger.debug("credRegistrationStatus:" + credRegistrationStatus);

		if (credRegistrationStatus != null && credRegistrationStatus.equalsIgnoreCase("true")) {
			logger.info("User already registered and hence not making user registration call");
			return goTo(true).build();
		} else {
			logger.info("User not registered and hence making user registration call");
			isVIPProfileRegistered = vIPCreateUser.createVIPUser(vip.getUserName(),vip.getKeyStorePath(),vip.getKeyStorePasswod());
			return goTo(isVIPProfileRegistered).build();
		}
	}
}