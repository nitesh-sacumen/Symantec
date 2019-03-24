package com.symantec.tree.nodes;


import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;
import static com.symantec.tree.config.Constants.*;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.request.util.AddCredential;
import com.symantec.tree.request.util.GetVIPServiceURL;
import com.symantec.tree.request.util.VIPGetUser;
import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * 
 * @Descrition "VIP Add Credential" node with true, error and false outcome, If true, go
 *             to "VIP Authenticate Push Credentials", if error go to "Display Error" else false, go to "VIP Display Creds".
 *
 */
@Node.Metadata(outcomeProvider = VIPAddCredential.SymantecOutcomeProvider.class, configClass = VIPAddCredential.Config.class)
public class VIPAddCredential implements Node {

	private static final String BUNDLE = "com/symantec/tree/nodes/VIPAddCredential";
	private Logger logger = LoggerFactory.getLogger(VIPAddCredential.class);

	private AddCredential addCred;
	private VIPGetUser vipSearchUser;

	/**
	 * Configuration for the node.
	 */
	public interface Config {

	}

	/**
	 * Create the node.
	 */
	@Inject
	public VIPAddCredential(AddCredential addCred,VIPGetUser vipSearchUser) {
		this.addCred = addCred;
		this.vipSearchUser = vipSearchUser;
	}

	/**
	 * Main logic of the node
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
        logger.info("Adding Credentials");
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();
		String credValue = context.sharedState.get(CRED_ID).asString();
		
		
		//Searching User in VIP data base, If it exist and register with Credential ID then it will throw error for already registered Credential ID.
		HashMap<String, String> credentialDetail = vipSearchUser.getCredentialBindingDetail(vip.getUserName(),vip.getKeyStorePath(),vip.getKeyStorePasswod(), context);
		if(credentialDetail!=null && credentialDetail.containsKey("OATH_TIME")&& credentialDetail.get("OATH_TIME").equalsIgnoreCase(credValue)) {
			logger.info("Entered Credential ID is already registered, Please enter valid Credential ID or choose other option.");
			context.sharedState.put(CREDENTIAL_ID_ERROR, "Entered Credential ID is already registered, Please enter valid Credential ID or choose other option.");
			return goTo(Symantec.FALSE).build();
		}
		
		// Adding Credential to the VIP Database
		String statusCode = addCred.addCredential(vip.getUserName(), credValue,STANDARD_OTP,vip.getKeyStorePath(),vip.getKeyStorePasswod());
		logger.debug("isCredAdded: "+statusCode);
		
		// Making decision based on AddCredential request response
		if(statusCode.equalsIgnoreCase(SUCCESS_CODE)) {
			logger.info("Crdentials is added successfully");
			return goTo(Symantec.TRUE).build();
		}
		else if(statusCode.equalsIgnoreCase(INVALID_CREDENIALS)||statusCode.equalsIgnoreCase(SCHEMA_INVALID)){
			logger.info("Entered Credential ID is Invalid");
			context.sharedState.put(CREDENTIAL_ID_ERROR, "Entered Credential ID is Invalid,Please enter valid Credential ID or choose other option.");
			return goTo(Symantec.FALSE).build();
		}
		else {
			logger.info("There is some error with entered Credential ID");
			context.sharedState.put(DISPLAY_ERROR, "Your Credential ID is disabled, Please contact to administrator");
			return goTo(Symantec.ERROR).build();
		}
		
	}
	
	/**
	 * The possible outcomes for the SymantecVerifyAuth.
	 */
	private enum Symantec {
		/**
		 * Successful.
		 */
		TRUE,
		/**
		 * failed.
		 */
		FALSE,
		/**
		 * Disabled.
		 */
		ERROR

	}
	
	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}
	
	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPAddCredential.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")));
		}
	}

}
