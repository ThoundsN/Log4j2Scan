package burp.utils;

import java.util.HashSet;
import java.util.Arrays;


public class Cache {

    public static HashSet<String> PARAMNAME_WHITELIST = new HashSet<>();
    public static HashSet<String> HEADER_WHITELIST = new HashSet<>(Arrays.asList(
            "content-length",
            "cookie",
            "host",
            "content-type"));
    



    public static void addWhiteList(String paramNameText){
        if (paramNameText.contains("\r")) {
            String[] paramNameArray = paramNameText.split("\\R");
            for(String paramName : paramNameArray){
                PARAMNAME_WHITELIST.add(paramName.trim());
                HEADER_WHITELIST.add(paramName.trim());
            }
            return;
        }

        PARAMNAME_WHITELIST.add(paramNameText.trim());
        HEADER_WHITELIST.add(paramNameText.trim());
    }

    public static boolean inWhiteList(String paramName){
        return PARAMNAME_WHITELIST.contains(paramName);
    }

}
