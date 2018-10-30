/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static com.symantec.tree.config.Constants.MOBNUM;

/** 
 * A node that checks to see if zero-page login headers have specified username and shared key 
 * for this request. 
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = VIPSearchUser.Config.class)
public class VIPSearchUser extends AbstractDecisionNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "SymantecSearchUser";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    
    private com.symantec.tree.request.util.VIPSearchUser vipSearchUser=null;

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100,requiredValue = true)
        default String vipuserservice_url() {
            return "";
        }

    }
    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public VIPSearchUser(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
        try {
        vipSearchUser = new com.symantec.tree.request.util.VIPSearchUser();
        }catch (Exception e) {
			System.out.println("error when instansiating searchuser......."+e.getMessage());
		}
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
    	boolean isVIPProfileExisted = vipSearchUser.viewUserInfo(userName);
    	String mobNum = null;
    	
    	try {
    	
    	if(isVIPProfileExisted) {
    		mobNum = vipSearchUser.getMobInfo(userName);
	    	System.out.println("PHone Number"+mobNum);

	    	if(mobNum != null && mobNum.equalsIgnoreCase("NOCREDREGISTERED")){
	    		System.out.println("NOCREDREGISTERED");
	    		context.transientState.put("NoCredentialRegistered", true);
	    		return goTo(false).build();
	    	}
	    	else if(mobNum != null && mobNum.equalsIgnoreCase("VIPCREDREGISTERED")){
	    		System.out.println("VIPCREDREGISTERED");
	    		//context.transientState.put("VIPCREDREGISTERED", "VIPCREDREGISTERED");
	    		return goTo(isVIPProfileExisted).build();
	    	}
	    	else{
	    		
	    		context.sharedState.put(MOBNUM,mobNum);    	
	    		return goTo(isVIPProfileExisted).build();
	    	}
    	}
    	
    	}catch(NullPointerException ne){
    		System.out.println("Phone Number not available for user");
    	}
    	
        return goTo(isVIPProfileExisted).build();
    }
}