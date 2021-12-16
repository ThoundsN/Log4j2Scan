package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;

public class ScanItem {
    public ScanItem(IParameter param, IHttpRequestResponse tmpreq) {
        this.Param = param;
        this.TmpRequest = tmpreq;
    }

    public ScanItem(String headerName, IHttpRequestResponse tmpreq) {
        this.IsHeader = true;
        this.HeaderName = headerName;
        this.TmpRequest = tmpreq;
    }


    public ScanItem( IHttpRequestResponse tmpreq,String explantion) {
        this.TmpRequest = tmpreq;
        this.explanation = explantion;
        this.HasExplantion = true;
    }

    public String HeaderName;
    public String explanation;
    public boolean IsHeader;
    public boolean HasExplantion;
    public IParameter Param;
    public IHttpRequestResponse TmpRequest;
}
