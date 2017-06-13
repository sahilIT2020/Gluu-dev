package org.xdi.oxauth.service;

import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.log.Log;
import org.xdi.ldap.model.SearchScope;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.json.*;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.*;
import org.slf4j.Logger;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.xdi.oxauth.audit.ApplicationAuditLogger;
import org.xdi.oxauth.model.config.StaticConf;
import org.xdi.oxauth.model.configuration.AppConfiguration;
import org.xdi.oxauth.model.jwk.JSONWebKeySet;
import org.xdi.oxauth.service.EncryptionService;
//import org.codehaus.jettison.json.JSONArray;
//import org.codehaus.jettison.json.JSONException;
//import org.codehaus.jettison.json.JSONObject;
import org.xdi.oxauth.service.external.ExternalAuthenticationService;

//https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
//Please goto above url if you got "Illegal key size" exception.
@Scope(ScopeType.STATELESS)
@Name("VeriCloudCompromise")
@AutoCreate
public class VeriCloudCompromise {

    @In
    private AuthenticationService authenticationService;
    
    @In
    private ExternalAuthenticationService externalAuthenticationService;

    @In
    private ApplicationAuditLogger applicationAuditLogger;

    @In
    private AppConfiguration appConfiguration;

    @In
    private StaticConf staticConfiguration;

    @In
    private JSONWebKeySet webKeysConfiguration;

    @In(required = false)
    private FacesContext facesContext;

    @In(value = "#{facesContext.externalContext}", required = false)
    private ExternalContext externalContext;

	private String url = "https://api.vericlouds.com/index.php";
	private String reqdata = "mode=search_leaked_password_with_userid&api_key=%s&api_secret=%s&userid=%s";
	private String api_key = "Gluu";
	private String api_secret = "4f6a078ac577e6616dd0ad0914433901d744dfa3ad974b92f448038e676d3fb0";
	private byte[] key = hexToByteArray(api_secret);

	public byte[] hexToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public String decrypt(String encrypted) {
		String[] strs = encrypted.split(":");
		try {
			IvParameterSpec iv = new IvParameterSpec(hexToByteArray(strs[1]));
			Cipher cipher = Cipher.getInstance( "AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), iv);
			return new String(cipher.doFinal(hexToByteArray(strs[0])));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	public JSONObject makeRequest(String userid) {
		try {
			HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
			conn.setDoOutput(true);
			OutputStream os = conn.getOutputStream();
			os.write(String.format(reqdata, api_key, api_secret, URLEncoder.encode(userid, "utf-8")).getBytes());

			JSONObject obj = new JSONObject(new JSONTokener(conn.getInputStream()));
			os.close();
			return obj;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public boolean is_compromised(String userid, String password) {
			JSONObject js = makeRequest(userid);

		if (js != null && js.getString("result").equals("succeeded")) {
			JSONArray pwdJSONArray  = js.getJSONArray("passwords_encrypted");

			for (int i = 0; i < pwdJSONArray.length(); i++) {
				String tmp = decrypt(pwdJSONArray.getString(i));
				int tlen = tmp.length();
				if (tlen == password.length() && tmp.charAt(0) == password.charAt(0)
						&& tmp.charAt(tlen - 1) == password.charAt(tlen - 1))
					return true;

            }

		}
		return false;
	}
    public static VeriCloudCompromise instance() {
        return (VeriCloudCompromise) Component.getInstance(UserService.class);
    }

}
