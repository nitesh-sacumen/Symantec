package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.DISPLAY_ERROR;
import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static com.symantec.tree.config.Constants.MOB_NUM;
import static com.symantec.tree.config.Constants.NO_CREDENTIALS_REGISTERED;
import static com.symantec.tree.config.Constants.NO_CRED_REGISTERED;
import static com.symantec.tree.config.Constants.SUCCESS_CODE;
import static com.symantec.tree.config.Constants.USER_DOES_NOT_EXIST;
import static com.symantec.tree.config.Constants.VIP_CRED_REGISTERED;

<<<<<<< HEAD
import java.util.List;
import java.util.ResourceBundle;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.request.util.VIPGetUser;
import javax.inject.Inject;
import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
=======
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
>>>>>>> remotes/origin/no_sdk_frank_changes
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;
import com.symantec.tree.request.util.VIPGetUser;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Search User" node with TRUE,FALSE and ERROR outcome. If TRUE, it will go to "VIP Push Auth User". If False, go to
 *             "VIP Register User" and if ERROR, It will go to "VIP Display Error" Page.
 *
 */
@Node.Metadata(outcomeProvider = VIPSearchUser.SymantecOutcomeProvider.class, configClass = VIPSearchUser.Config.class)
public class VIPSearchUser implements Node {
	private final Debug debug = Debug.getInstance("VIP");
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPSearchUser";

	/**
	 * Configuration for the node.
	 */
	 public interface Config {

	}
	 
	private VIPGetUser vipSearchUser;

	/**
	 * Create the node.
	 *
	 */
	@Inject
	public VIPSearchUser(VIPGetUser vipSearchUser) {
		this.vipSearchUser = vipSearchUser;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		//TODO This duplicated code should be pulled out in a helper method that all nodes use
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		
		String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();
		
		String statusCode = vipSearchUser.viewUserInfo(userName,key_store,key_store_pass);
        debug.message("status code in VIP Search User"+statusCode);
		String mobNum;

			if (statusCode.equalsIgnoreCase(SUCCESS_CODE)) {
				mobNum = vipSearchUser.getMobInfo(userName,key_store,key_store_pass);
				debug.message("Phone Number in VIP Search User" + mobNum);

				if (mobNum != null && mobNum.equalsIgnoreCase(NO_CRED_REGISTERED)) {
					debug.message("No Credential Registered in VIP Search User");
					context.transientState.put(NO_CREDENTIALS_REGISTERED, true);
					return goTo(Symantec.FALSE).build();
				} else if (mobNum != null && mobNum.equalsIgnoreCase(VIP_CRED_REGISTERED)) {
					debug.message("VIP Credential Registered in VIP Search User");
					return goTo(Symantec.TRUE).build();
				} else {
					debug.message("Fall back options in VIP Search User");

					context.sharedState.put(MOB_NUM, mobNum);
					return goTo(Symantec.TRUE).build();
				}
			} else if(statusCode.equalsIgnoreCase(USER_DOES_NOT_EXIST)) {
				return goTo(Symantec.FALSE).build();
			}else {
				context.sharedState.put(DISPLAY_ERROR,"User is locked, Please contact to administrator");
				return goTo(Symantec.ERROR).build();
			}
	}
	
	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}
	
	/**
	 * The possible outcomes for the SymantecVerifyAuth.
	 */
	public enum Symantec {
		/**
		 * Successful.
		 */
		TRUE,
		/**
		 * failed.
		 */
		FALSE,
		/**
		 * Locked.
		 */
		ERROR

	}
	
	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPSearchUser.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")));
		}
	}

}