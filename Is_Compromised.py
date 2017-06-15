# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
#

from org.jboss.seam.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.oxauth.service import UserService, AuthenticationService, SessionStateService
from org.xdi.util import StringHelper
import javax.crypto.spec.SecretKeySpec as SecretKeySpec
import javax.crypto.spec.IvParameterSpec as IvParameterSpec
import javax.crypto.Cipher
from javax.crypto import *

import urllib, urllib2, json
import java

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "checkPwdCompromised. Initialization"
        print "checkPwdCompromised. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "checkPwdCompromised. Destroy"
        print "checkPwdCompromised. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Basic. Authenticate for step 1"
            credentials = Identity.instance().getCredentials()
            user_name = credentials.getUsername()
            user_password = credentials.getPassword()
            userService = UserService.instance()
            find_user_by_uid = userService.getUser(user_name)
            status_attribute_value = userService.getCustomAttribute(find_user_by_uid, "mail")
            print status_attribute_value
            if status_attribute_value != None:
                user_mail = status_attribute_value.getValue()
                isCompromised = self.is_compromised(user_mail,user_password,configurationAttributes)
                if (isCompromised ):
                    print user_mail+" password has been compromised."            
                    return False
            if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
                #userService = UserService.instance()
                logged_in = userService. authenticate(user_name, user_password)

            if (not logged_in):
                return False

            return True
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if (step == 1):
            print "Basic. Prepare for Step 1"
            return True
        else:
            return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return None

    def getCountAuthenticationSteps(self, configurationAttributes):
        return 1

    def getPageForStep(self, configurationAttributes, step):
        return ""

    def logout(self, configurationAttributes, requestParameters):
        return True

    def is_compromised(self, userid, password,configurationAttributes):
        print "Vericloud APIs Initialization"
        if not configurationAttributes.containsKey("credentials_file"):
            print "credentials_file property not defined"
            return False

        vericloud_gluu_creds_file = configurationAttributes.get("credentials_file").getValue2()
        # Load credentials from file
        f = open(vericloud_gluu_creds_file, 'r')
        try:
            creds = json.loads(f.read())
        except:
            print "Vericloud API. Initialize notification services. Failed to load credentials from file:", vericloud_gluu_creds_file
            return False
        finally:
            f.close()
        
        try:
            url = str(creds["api_url"])
            api_key=str(creds["api_key"])
            api_secret= str(creds["api_secret"])
        except:
            print "Vericloud API. Initialize notification services. Invalid credentials file '%s' format:" % super_gluu_creds_file
            return False
        

	reqdata = {"mode":"search_leaked_password_with_userid", "api_key": api_key, "api_secret": api_secret, "userid": userid}
	reqdata = urllib.urlencode(reqdata)
	resp = urllib2.urlopen(urllib2.Request(url, reqdata)).read()
	resp = json.loads(resp)
	if resp['result'] != 'succeeded':
	    return None
	for pass_enc in resp['passwords_encrypted']:
	    plaintext = self.AESCipherdecrypt(api_secret, pass_enc)
	    if (len(password), password[0], password[-1]) == (len(plaintext), plaintext[0], plaintext[-1]) :
	        return True
	return False

    def AESCipherdecrypt(self, key, enc ):
        enc, iv = enc.split(':')
	cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
	cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key.decode("hex"), "AES"),IvParameterSpec(iv.decode("hex")))
	decrypted_password = cipher.doFinal(enc.decode("hex"))
	return decrypted_password.tostring()