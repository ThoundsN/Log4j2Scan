package burp.utils;

import burp.BurpExtender;
import burp.IRequestInfo;
import burp.ui.tabs.CacheUIHandler;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Arrays;


public  class Cache {
    private BurpExtender parent;

    public static HashSet<String> PARAMNAME_WHITELIST = new HashSet<>();
    public static HashSet<String> HEADER_WHITELIST = new HashSet<>(Arrays.asList(
            "content-length",
            "cookie",
            "host",
            "content-type"));
    public static HashSet<String> HOST_WHITELIST = new HashSet<>(Arrays.asList(
            "alipay",
            "google-analytics",
            "recaptcha",
            "intercom",
            ".gov"));

    public static HashMap<String,Boolean> KEY_OF_REQUESTS = new HashMap<String, Boolean>();


    public Cache(BurpExtender parent){
        this.parent = parent;
    }

    public  void addRequestKey(IRequestInfo request){
        String keyOfRequest = Utils.getKeyOfRequest(request);
        KEY_OF_REQUESTS.put(keyOfRequest,false);
        parent.uiHandler.cui.model.addRow(keyOfRequest);

    }

    public  void updateRequestKey(IRequestInfo request){
        String keyOfRequest = Utils.getKeyOfRequest(request);
        KEY_OF_REQUESTS.put(keyOfRequest,true);
        parent.uiHandler.cui.model.updateBooleanRow(keyOfRequest);

    }


    public static void addWhiteList(String paramNameText){
        if (paramNameText.contains("\r")) {
            String[] paramNameArray = paramNameText.split("\\R");
            for(String paramName : paramNameArray){
                PARAMNAME_WHITELIST.add(paramName.trim());
            }
            return;
        }

        PARAMNAME_WHITELIST.add(paramNameText.trim());
    }

    public static boolean inWhiteList(String paramName){
        return PARAMNAME_WHITELIST.contains(paramName);
    }

}
