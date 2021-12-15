package burp.scanner;

import burp.*;
import burp.backend.IBackend;
import burp.backend.platform.*;
import burp.poc.IPOC;
import burp.poc.impl.*;
import burp.ui.tabs.BackendUIHandler;
import burp.utils.*;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import static burp.ui.tabs.POCUIHandler.defaultEnabledPocIds;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    public IBackend backend;
    private HashSet<String> scanned_Urls;

    private final String[] HEADER_BLACKLIST = new String[]{
            "content-length",
            "cookie",
            "host",
            "content-type"
    };
    private final String[] HEADER_GUESS = new String[]{
            "User-Agent",
            "Referer",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Originating-IP",
            "Originating-IP",
            "CF-Connecting_IP",
            "True-Client-IP",
            "Originating-IP",
            "X-Real-IP",
            "Forwarded",
            "X-Api-Version",
            "X-Wap-Profile",
            "Contact"
    };

    private final String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "gif",
            "pdf",
            "bmp",
            "js",
            "css",
            "ico",
            "woff",
            "woff2",
            "ttf",
            "otf",
            "ttc",
            "svg",
            "psd",
            "exe",
            "zip",
            "rar",
            "7z",
            "msi",
            "tar",
            "gz",
            "mp3",
            "mp4",
            "mkv",
            "swf",
            "xls",
            "xlsx",
            "doc",
            "docx",
            "ppt",
            "pptx",
            "iso"
    };

    private IPOC[] pocs;

    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
        this.pocs = new IPOC[]{new POC1(), new POC2(), new POC3(), new POC4(), new POC11()};
//        this.backend = new DnslogCN();
        this.loadConfig();

        this.scanned_Urls = new HashSet<>();
        if (this.backend.getState()) {
            parent.stdout.println("Log4j2Scan loaded successfully!\r\n");
        } else {
            parent.stdout.println("Backend init failed!\r\n");
        }
    }

    public String urlencodeForTomcat(String exp) {
        exp = exp.replace("{", "%7b");
        exp = exp.replace("}", "%7d");
        return exp;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        String key = Utils.getKeyOfRequest(req);
        List<IScanIssue> issues = new ArrayList<>();

        if (scanned_Urls.contains(key)){
            return issues;
        }
        this.scanned_Urls.add(key);
        if (isStaticFile(req.getUrl().toString())){
            return issues;
        }

        parent.stdout.println(String.format("Scanning: %s", req.getUrl().toString()));
        Map<String, ScanItem> domainMap = new HashMap<>();
        domainMap.putAll(paramsFuzz(baseRequestResponse, req));
        domainMap.putAll(headerFuzz(baseRequestResponse, req));

        try {
            Thread.sleep(10000); //sleep 10s, wait for network delay.
        } catch (InterruptedException e) {
            parent.stdout.println(e);
        }
        issues.addAll(finalCheck(baseRequestResponse, req, domainMap));
        parent.stdout.println(String.format("Scan complete: %s", req.getUrl()));
        return issues;
    }

    private boolean isStaticFile(String url) {
        return Arrays.stream(STATIC_FILE_EXT).anyMatch(s -> s.equalsIgnoreCase(HttpUtils.getUrlFileExt(url)));
    }

    private Collection<IPOC> getSupportedPOCs() {
        return Arrays.stream(pocs).filter(p -> Arrays.stream(backend.getSupportedPOCTypes()).anyMatch(c -> c == p.getType())).collect(Collectors.toList());
    }

//    private Map<String, ScanItem> pathFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
//
//    }


    private Map<String, ScanItem> existingHeaderFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        // Fuzzing already existed headers
        // one temp domain :  one existing header   ->   all pocs

        List<String> headers = req.getHeaders();
        List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
        byte[] rawRequest = baseRequestResponse.getRequest();
        Map<String, ScanItem> domainMap = new HashMap<>();

        for (int i = 1; i < headers.size(); i++) {
            HttpHeader header = new HttpHeader(headers.get(i));
            if (Arrays.stream(HEADER_BLACKLIST).noneMatch(h -> h.equalsIgnoreCase(header.Name))) {
                //header is not cookie, host
                List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.Name)).collect(Collectors.toList());
                needSkipheader.forEach(guessHeaders::remove);
                // remove alreay existed header from guess headers
                String tmpDomain = backend.getNewPayload();
                String payloadDomain = Utils.addPrefixTempDomain(header.Name,tmpDomain);
                for (IPOC poc : getSupportedPOCs()) {
                    List<String> tmpHeaders = new ArrayList<>(headers);

                    header.Value = poc.generate(payloadDomain);
                    tmpHeaders.set(i, header.toString());
                    byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                    IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                    domainMap.put(payloadDomain, new ScanItem(header.Name, tmpReq));
                }
            }
        }
        return domainMap;
    }

    private Map<String, ScanItem> guessHeaderFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        List<String> headers = req.getHeaders();
        List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
        byte[] rawRequest = baseRequestResponse.getRequest();
        Map<String, ScanItem> domainMap = new HashMap<>();
        List<String> tmpHeaders = new ArrayList<>(headers);
        String tmpDomain = backend.getNewPayload();

        for (IPOC poc : getSupportedPOCs()) {
            Map<String, String> domainHeaderMap = new HashMap<>();
            for (String headerName : guessHeaders) {
                String payloadDomain = Utils.addPrefixTempDomain(headerName,tmpDomain);

                tmpHeaders.add(String.format("%s: %s", headerName, poc.generate(tmpDomain)));
                domainHeaderMap.put(headerName, tmpDomain);
            }
            byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
            IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
            for (Map.Entry<String, String> domainHeader : domainHeaderMap.entrySet()) {
                domainMap.put(domainHeader.getValue(), new ScanItem(domainHeader.getKey(), tmpReq));
            }
        }
        return domainMap;
    }

        private Map<String, ScanItem> headerFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> domainMap = new HashMap<>();
        try {
            domainMap.putAll(existingHeaderFuzz(baseRequestResponse,req));
            domainMap.putAll(guessHeaderFuzz(baseRequestResponse,req));

        } catch (Exception ex) {
            parent.stdout.println(ex);
        }
        return domainMap;
    }

    //only Scanned cookie
// when iterating Iparamter there seems to be only PARAM_COOKIE and PARAM_JSON
    private Map<String, ScanItem> paramsFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> domainMap = new HashMap<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        for (IParameter param : req.getParameters()) {
            for (IPOC poc : getSupportedPOCs()) {
                try {
                    String tmpDomain = backend.getNewPayload();
                    byte[] tmpRawRequest = rawRequest;
                    String exp = poc.generate(tmpDomain);
                    boolean hasModify = false;
                    switch (param.getType()) {
                        case IParameter.PARAM_URL:
                        case IParameter.PARAM_BODY:
                        case IParameter.PARAM_COOKIE:
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            IParameter newParam = helper.buildParameter(param.getName(), exp, param.getType());
                            tmpRawRequest = helper.updateParameter(rawRequest, newParam);
                            hasModify = true;
                            break;
                        case IParameter.PARAM_JSON:
                        case IParameter.PARAM_XML:
                        case IParameter.PARAM_MULTIPART_ATTR:
                        case IParameter.PARAM_XML_ATTR:
                            //unsupported.
                    }
                    if (hasModify) {
                        IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                        tmpReq.getResponse();
                        domainMap.put(tmpDomain, new ScanItem(param, tmpReq));

                    }
                } catch (Exception ex) {
                    parent.stdout.println(ex);
                }
            }
        }
        return domainMap;
    }

    private List<IScanIssue> finalCheck(IHttpRequestResponse baseRequestResponse, IRequestInfo req, Map<String, ScanItem> domainMap) {
        List<IScanIssue> issues = new ArrayList<>();
        if (backend.flushCache(domainMap.size())) {
            for (Map.Entry<String, ScanItem> domainItem :
                    domainMap.entrySet()) {
                ScanItem item = domainItem.getValue();
                boolean hasIssue = backend.CheckResult(domainItem.getKey());
                if (hasIssue) {
                    issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                            req.getUrl(),
                            new IHttpRequestResponse[]{baseRequestResponse, item.TmpRequest},
                            "Log4j2 RCE Detected",
                            String.format("Vulnerable param is \"%s\" in %s.", item.IsHeader ? item.HeaderName : item.Param.getName(), item.IsHeader ? "Header" : getTypeName(item.Param.getType())),
                            "High"));
                }
            }
        } else {
            parent.stdout.println("get backend result failed!\r\n");
        }
        return issues;
    }

    private String getTypeName(int typeId) {
        switch (typeId) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_JSON:
                return "Body-json";
            case IParameter.PARAM_XML:
                return "Body-xml";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Body-multipart";
            case IParameter.PARAM_XML_ATTR:
                return "Body-xml-attr";
            default:
                return "unknown";
        }
    }

    public void close() {
        if (this.backend != null) {
            this.backend.close();
        }
    }

    public boolean getState() {
        try {
            return this.backend.getState() && getSupportedPOCs().size() > 0;
        } catch (Exception ex) {
            return false;
        }
    }

    private void loadConfig() {
        BackendUIHandler.Backends currentBackend = BackendUIHandler.Backends.valueOf(Config.get(Config.CURRENT_BACKEND, BackendUIHandler.Backends.BurpCollaborator.name()));
        JSONArray enabled_poc_ids = JSONArray.parseArray(Config.get(Config.ENABLED_POC_IDS, JSONObject.toJSONString(defaultEnabledPocIds)));

        try {
            switch (currentBackend) {
                case Ceye:
                    this.backend = new Ceye();
                    break;
                case DnslogCN:
                    this.backend = new DnslogCN();
                    break;
                case RevSuitDNS:
                    this.backend = new RevSuitDNS();
                    break;
                case RevSuitRMI:
                    this.backend = new RevSuitRMI();
                    break;
                case GoDnslog:
                    this.backend = new GoDnslog();
                    break;
                case BurpCollaborator:
                    this.backend = new BurpCollaborator();
                    break;
            }
            List<Integer> enabled_poc_ids_list = new ArrayList<>();
            enabled_poc_ids.forEach(e -> enabled_poc_ids_list.add((int) e));
            this.pocs = Utils.getPOCs(Arrays.asList(enabled_poc_ids.toArray()).toArray(new Integer[0])).values().toArray(new IPOC[0]);
        } catch (Exception ex) {
            parent.stdout.println(ex);
        } finally {
            if (this.backend == null || !this.backend.getState()) {
                parent.stdout.println("Load backend from config failed! fallback to dnslog.cn....");
                this.backend = new DnslogCN();
            }
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
