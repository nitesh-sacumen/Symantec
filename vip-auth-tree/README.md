<!--
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
 * Copyright ${data.get('yyyy')} ForgeRock AS.
-->
# VipAuthTreeNode
A simple authentication node for ForgeRock's Access Manager 6.0 and above.

## Information

VIP Forgerock offers secondary authentication along with the authentication offered by the openam. Following are the authentication mechanisms available: 1) Push 2) OTP

## Installation

The VIP OpenAM tree nodes will be packaged as a jar file using the maven build tool and will be deployed in to the ForgeRock Access Management (AM)6 application WEB-INF/lib folder which is running on tomcat server.

## Steps

1) Configure Maven to be able to access the OpenAM repositories

2) Setup a Maven Project for building the Custom Authentication Node I.e. vip-auth-tree

3) Write the custom logic inside tree nodes to communicate with vip services

4) Change to the root directory of the Maven project of the vip Tree Node Run the mvn package command.

5) The project will generate a .jar file containing our custom nodes I.e . VIP OpenAM Tree Nodes, In the form of vip-auth-tree-1.0.jar.

6) Copy the vip-auth-tree-1.0.jar file to the WEB-INF/lib/ folder where AM is deployed

7) Restart the AM for the new plug-in to become available.

The vip tree nodes are now available in the tree designer to add to authentication trees

Following are the nodes that will be available after deploying the jar file:

![p_1](https://user-images.githubusercontent.com/20396535/54488323-77137880-48c6-11e9-9985-6fe6024e7a55.PNG)

![p_2](https://user-images.githubusercontent.com/20396535/54488325-809ce080-48c6-11e9-9503-21e10cb3e8fe.PNG)

![p_3](https://user-images.githubusercontent.com/20396535/54488327-8abedf00-48c6-11e9-9935-677255b5ce33.PNG)


* VIP DISPLAY ERROR
```js
This node will display error assiciated with exceed attempts of invalid otp. There are no configurable attributes to it.
```

* VIP Add Credential
```js
This node will add credentials as credential id associtaed with user in VIP Database. There are no configurable attributes to it.
```

* VIP Add More Credentials
```js
This node gives you a screen where you can choose yes/no for add more credentilas in VIP. There are no configurable attributes to it.
```

* VIP AddCred with VerifyCode
```js
This node will add credentials as credential id and OTP  or phone number and OTP associtaed with user in VIP Database. There are no configurable attributes to it.
```

* VIP Authenticate Push Credentals
```js
This node will authenticate push credentials during registration.
Attributes to be configured are:
 * Push Display Message Text: The message which should be display on push event. Ex. VIP Push Cred
 * Push Display Message Title: The message title which should be display on push event. Ex. VIP Push
 * Push Display Message Profile. The message profile. Ex www.vip.com
```
![auth-push](https://user-images.githubusercontent.com/20396535/48187242-7c811500-e360-11e8-8bee-a7d7668aed8c.PNG)

* VIP Check Symantec OTP
```js
This node will verify OTP with username. There are no configurable attributes to it.
```

* VIP Display Creds
```js
This node gives you a screen where you need choose your credential type. Where you can choose VIP/SMS/VOICE.
Attributes to be configured are:
 * List of Creds : You need to configure key-value pair as
    0 - VIP
    1 - SMS
    2 - VOICE
```
![display](https://user-images.githubusercontent.com/20396535/48187643-b0106f00-e361-11e8-9d25-e6a6b0b38f49.PNG)


* VIP Enter CredentialID
```js
This node gives you a screen where you need to enter credential id generated on vip app. There are no configurable attributes to it.
```

* VIP Enter Phone Number
```js
This node gives you a screen where you need to enter phone number. There are no configurable attributes to it.
```

* VIP Enter SecurityCode/OTP
```js
This node gives you a screen where you need to enter OTP, which appears on given phone number . There are no configurable attributes to it.
```

* VIP OTPAuth Creds
```js
This node gives you a screen where you need choose your authentication credential type. Where you can choose SMS/VOICE.
Attributes to be configured are:
 * List of Creds : You need to configure key-value pair as
    0 - SMS
    1 - VOICE
    2 - TOKEN
```
![otp-auth](https://user-images.githubusercontent.com/20396535/48188130-f914f300-e362-11e8-8a38-61f611ad8450.PNG)


* VIP Poll Push Auth
```js
This node get poll push request status during authentication. There are no configurable attributes to it.
```

* VIP Poll Push Reg
```js
This node get poll push request status during registraton. There are no configurable attributes to it.
```

* VIP Push Auth User
```js
This node will authenticate push credentials during authentication.
Attributes to be configured are:
 * Push Display Message Text: The message which should be display on push event. Ex. VIP Push Cred
 * Push Display Message Title: The message title which should be display on push event. Ex. VIP Push
 * Push Display Message Profile. The message profile. Ex www.vip.com
```
![auth-push-1](https://user-images.githubusercontent.com/20396535/48188528-f8c92780-e363-11e8-95c9-480ee7f63aca.PNG)


* VIP Register User
```js
This node register user in VIP, If user dont exist. There are no configurable attributes to it.
```

* VIP Search User
```js
This node search user in VIP and get user info, if user exits. There are no configurable attributes to it.
```

* VIP Set Configuration
```js
This node set all the sevice urls which will be used to access Symantec APIs.
Attributes to be configured are:
 * Keystore Path: Path for keystore file.
 * Keystore Password: Password of keystore file.
 * Authentication Service URL: VIP Authentication Service URL
 * Query Service URL: VIP Query Service URL
 * Management Service URL: VIP Management Service URL
 * SDK Service URL : Service url to get Activation Code
```

![url_conf](https://user-images.githubusercontent.com/20396535/48860971-68212b80-ede8-11e8-9953-646b9625bb70.PNG)

* VIP DR Data Collector
```js
This node collects DR data(payload, signature, header) in encoded form. There are no configurable attributes to it.
```

* VIP DR Data Eval
```js
This node takes decesion according to json which are coming from from DR Data Collector node. If attribute value in json true then it goes to another node for further verification and if it is false then it goes to success node. 

Attributes to be configured are:
* DR Data Fields : You need to choose field from DR Data JSON, Which you want to evaluate.
```
![p_4](https://user-images.githubusercontent.com/20396535/54487945-edfa4280-48c1-11e9-941b-6faf14cd6bc5.PNG)

* VIP DR OS Decesion Node
```js
This node just verify forDR Data coming from android device or ios device. There are no configurable attributes to it.
```

* VIP IA Authentication
```js
This node execute Evalate Risk request after Deny Risk. There are no configurable attributes to it.
```

* VIP IA Confirm Risk
```js
This node execute Confirm Risk request. There are no configurable attributes to it.
```

* VIP IA Data Collector Node
```js
This node collects Auth Data using HiddenValueCallBack and ScriptTextOutputCallback.

Attributes to be configured are:
* Script : Script URL which will collect Auth Data.
* Is Page Node : If it false then user will not able to see login button on web page, it will be clicked by script and if it is true then login button will appear on web page and user need to click it to navigate next page.
```

![p_5](https://user-images.githubusercontent.com/20396535/54488211-37985c80-48c5-11e9-9e29-40071c1387b1.PNG)

* VIP IA Deny Risk
```js
This node execute Deny Risk request. There are no configurable attributes to it.
```

* VIP IA Evaluate Risk
```js
This node execute Evaluate Risk request. There are no configurable attributes to it.
```

* VIP IA Registration
```js
This node execute Deny Risk request to register new device. There are no configurable attributes to it.
```

* VIP IA Risk Score Decision Node
```js
This node makes decision based on score fetch by evaluate risk api.

Attributes to be configured are:
* low_threshold : Low range of score. By default it is 20.
* high_threshold : High range of score. By default it is 80.
```

![p_6](https://user-images.githubusercontent.com/20396535/54488293-2734b180-48c6-11e9-84b2-34e5b8c78732.PNG)

* VIP SDK Enter CredentialID
```js
This node gives you a screen where you need to enter credential id generated on vip app. There are no configurable attributes to it.
```

* Set Session Properties
```js
This node sets session properties, which needs to white list in Session Property Whitelist Service under Global_Services.

Attributes to be configured are:
* Properties : Add key value pair as key-LIMITED_ACCESS value-Rooted_Device(As your convenince)
```

![p_15](https://user-images.githubusercontent.com/20396535/54489198-e9d52180-48cf-11e9-8cd9-65b32fd0e339.PNG)

![p_16](https://user-images.githubusercontent.com/20396535/54489202-ee013f00-48cf-11e9-8f05-8d1f1eb5cb6e.png)



## Set Logging Level

* User can set log level in forgerock instance, To set user need to follow this path:
```js
DEPLOYMENT-->SERVERS-->LocalInstance-->Debugging
```

![set_logging](https://user-images.githubusercontent.com/20396535/48692807-621b2700-ebfd-11e8-993b-d9f0da2f9191.PNG)

## Configure the trees as follows

 * Navigate to **Realm** > **Authentication** > **Trees** > **Create Tree**
 
 ![tree](https://user-images.githubusercontent.com/20396535/48189113-66c21e80-e365-11e8-8045-326786a41aca.PNG)


## Configuring VIP Auth Tre
```js
this section depicts configuration of VIP Auth Tree
```
* Configure VIP Auth Tree as shown below

![sdk_7](https://user-images.githubusercontent.com/20396535/49303025-a5737080-f4ee-11e8-9f8f-e439b4472729.PNG)


```js
 Nodes To be Configured:
    * VIP Display Creds
    * VIP OTPAuth Creds
    * VIP Authenticate Push Credentials
    * VIP Push Auth User
    * VIP Set Configuration
```

* Now access the protected site by OpenAM

![login](https://user-images.githubusercontent.com/20396535/48189557-7c841380-e366-11e8-8050-f1b54e3d8e1c.PNG)


# VIP SDK Flow

* Configure Vip-Sdk-Registeration Tree as shown below:
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
```
![p_7](https://user-images.githubusercontent.com/20396535/54488586-6dd7db00-48c9-11e9-9186-e310bc6de2a6.PNG)



* Configure Vip-Sdk-VerifyOTP Tree as shown below:
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
```
![p_8](https://user-images.githubusercontent.com/20396535/54488616-d1fa9f00-48c9-11e9-8e30-ff1bde338fb3.PNG)



* Configure VIP_DR Tree as shown below:
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
    * VIP DR Data Eval : Need to choose field from drop down to evaluate device hygenie.
    * Set Session Properties : Add key value pair as key-LIMITED_ACCESS value-Rooted_Device
```
![p_9](https://user-images.githubusercontent.com/20396535/54488650-6bc24c00-48ca-11e9-8e75-e05f4b750291.PNG)



* Configure VIP_IA Tree as shown below: 
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
    * VIP IA Data Collector Node : Enter Script url to get auth data and select true/false to enable/disable login button respectively.
        * Set Session Properties : Add key value pair as key-LIMITED_ACCESS value-Risk_Score
```
![p_10](https://user-images.githubusercontent.com/20396535/54488770-e93a8c00-48cb-11e9-9366-41b70ad265a7.PNG)



* Configure VIP_DR_TXN Tree as shown below:
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
    * VIP DR Data Eval : Need to choose field from drop down to evaluate device hygenie.
    * Set Session Properties : Add key value pair as key-LIMITED_ACCESS_TXN value-Rooted_Device
```
![p_9](https://user-images.githubusercontent.com/20396535/54488650-6bc24c00-48ca-11e9-8e75-e05f4b750291.PNG)



* Configure VIP_IA_TXN Tree as shown below: 
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
    * VIP IA Data Collector Node : Enter Script url to get auth data and select true/false to enable/disable login button respectively.
    * Set Session Properties : Add key value pair as key-LIMITED_ACCESS_TXN value-Risk_Score
```
![p_10](https://user-images.githubusercontent.com/20396535/54488770-e93a8c00-48cb-11e9-9366-41b70ad265a7.PNG)



* Configure VIP_WITHOUT_DR Tree as shown below: 
```js
 Nodes To be Configured:
    * VIP Set Configuration : Need to mention all the VIP Service URLs
    * Set Session Properties : Add key value pair as key-LIMITED_ACCESS_TXN value-Rooted_Device
```
![p_11](https://user-images.githubusercontent.com/20396535/54488834-65cd6a80-48cc-11e9-9638-2e34d6c75b63.PNG)




* Configure VIP Transaction With DR Policy Set as shown below:
![p_12](https://user-images.githubusercontent.com/20396535/54488914-366b2d80-48cd-11e9-9775-825b76f88308.PNG)


* Configure VIP Transaction With IA Policy Set as shown below:
![p_13](https://user-images.githubusercontent.com/20396535/54488924-3cf9a500-48cd-11e9-92e8-15bb0f61479a.PNG)


* Configure VIP Transaction Without DR Policy Set as shown below:
![p_14](https://user-images.githubusercontent.com/20396535/54488926-4420b300-48cd-11e9-8ebb-7b1465de99ac.PNG)







        






 




