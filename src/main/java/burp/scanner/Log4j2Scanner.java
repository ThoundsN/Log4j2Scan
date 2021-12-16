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

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    public IBackend backend;
    private Config.FuzzMode fuzzMode;

    private HashSet<String> scannedUrls;
    private HashSet<String> scannedCookies;

    private final String[] HEADER_BLACKLIST = new String[]{
            "content-length",
            "cookie",
            "host",
            "content-type"
    };
    private final String[] HEADER_GUESS = new String[]{
            "User-Agent",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Forwarded-For",
            "X-Originating-IP",
            "CF-Connecting_IP",
            "True-Client-IP",
            "Originating-IP",
            "X-Real-IP",
            "Client-IP",
            "X-Wap-Profile",
            "X-Api-Version",
            "Sec-Ch-Ua",
            "Sec-Ch-Ua-Platform",
            "Upgrade-Insecure-Requests",
            "Accept",
            "Sec-Fetch-Site",
            "Sec-Fetch-Mode",
            "Sec-Fetch-User",
            "Sec-Fetch-Dest",
            "Accept-Encoding",
            "Accept-Language",
            "Referer",
            "Forwarded",
            "Contact",
            "If-Mondified-Since",
            "X-Custom-IP-Authorization",
            "X-Forwarded-Host",
            "X-Forwarded-Server",
            "X-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "Connection"

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

        this.scannedUrls = new HashSet<>();
        this.scannedCookies = new HashSet<>();
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
        this.fuzzMode = Config.FuzzMode.valueOf(Config.get(Config.FUZZ_MODE, Config.FuzzMode.EachFuzz.name()));
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        String key = Utils.getKeyOfRequest(req);
        List<IScanIssue> issues = new ArrayList<>();

        if (scannedUrls.contains(key)){
            return issues;
        }
        this.scannedUrls.add(key);
        if (isStaticFile(req.getUrl().toString())){
            return issues;
        }

        parent.stdout.println(String.format("Scanning: %s", req.getUrl().toString()));
        Map<String, ScanItem> resultMap = new HashMap<>();


        if (this.fuzzMode == Config.FuzzMode.EachFuzz) {
            resultMap.putAll(IParameterFuzz(baseRequestResponse, req));
            if (Config.getBoolean(Config.ENABLED_FUZZ_HEADER, true)) {
                resultMap.putAll(headersFuzz(baseRequestResponse, req));
            }
            resultMap.putAll(pathFuzz(baseRequestResponse,req));
            resultMap.putAll(paramNameFuzz(baseRequestResponse,req));
        }


        if (this.fuzzMode == Config.FuzzMode.Crazy) {
            resultMap.putAll(crazyFuzz(baseRequestResponse, req));
            resultMap.putAll(pathFuzz(baseRequestResponse,req));
            resultMap.putAll(paramNameFuzz(baseRequestResponse,req));


        }


        try {
            Thread.sleep(10000); //sleep 10s, wait for network delay.
        } catch (InterruptedException e) {
            parent.stdout.println(e);
        }
        issues.addAll(finalCheck(baseRequestResponse, req, resultMap));
        parent.stdout.println(String.format("Scan complete: %s", req.getUrl()));
        return issues;
    }

    private boolean isStaticFile(String url) {
        return Arrays.stream(STATIC_FILE_EXT).anyMatch(s -> s.equalsIgnoreCase(HttpUtils.getUrlFileExt(url)));
    }

    private Collection<IPOC> getSupportedPOCs() {
        return Arrays.stream(pocs).filter(p -> Arrays.stream(backend.getSupportedPOCTypes()).anyMatch(c -> c == p.getType())).collect(Collectors.toList());
    }

    private Map<String, ScanItem> pathFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();

        String tmpDomain = backend.getNewPayload();


            for (IPOC poc : getSupportedPOCs()) {
                try {
                //backfixpath
                String payloadDomain = Utils.addPrefixTempDomain("path" + poc.getIndex(), tmpDomain);
                String exp = poc.generate(payloadDomain);
                exp = helper.urlEncode(exp);
                exp = urlencodeForTomcat(exp);
                String path = req.getUrl().getPath();
                byte[] rawpayloadReq = helper.stringToBytes(helper.bytesToString(baseRequestResponse.getRequest()).replace(path, path + '/' + exp));
                IHttpRequestResponse requestResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), rawpayloadReq);
                resultMap.put(payloadDomain, new ScanItem(requestResponse, "backfix path "));
                } catch (Exception ex) {
                    parent.stderr.println(ex);
            }

        }
        return resultMap;

    }

    private Map<String, ScanItem> paramNameFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();

        String tmpDomain = backend.getNewPayload();
        HashSet<Byte> paramType_set = new HashSet();
        for (IParameter param : req.getParameters()){
            paramType_set.add(param.getType());
        }

        for (IPOC poc : getSupportedPOCs()){

                for (Byte paramtype : paramType_set) {
                    try {
                    String typename = this.getTypeName(paramtype);
                    String payloadDomain = Utils.addPrefixTempDomain(typename + poc.getIndex(), tmpDomain);
                    String exp = poc.generate(payloadDomain);
                    Boolean useIparam = false;
                    byte[] rawRequest = baseRequestResponse.getRequest();

                    switch (paramtype) {
                        case IParameter.PARAM_URL:
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            useIparam = true;
                            break;
                        case IParameter.PARAM_BODY:
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            useIparam = true;
                            break;
                        case IParameter.PARAM_COOKIE:
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            useIparam = true;
                            break;
                        case IParameter.PARAM_JSON:
                        case IParameter.PARAM_XML:
                            continue;
                        case IParameter.PARAM_MULTIPART_ATTR:
                            continue;
                        case IParameter.PARAM_XML_ATTR:
                            continue;

                    }
                    if (useIparam) {
                        IParameter newParam = helper.buildParameter(exp, Utils.GetRandomString(4), paramtype);
                        byte[] tmpRawRequest = helper.addParameter(rawRequest, newParam);
                        IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                        tmpReq.getResponse();
                        resultMap.put(payloadDomain, new ScanItem(tmpReq, String.format("%s parameter name: %s", typename, exp)));
                    } else {
                        byte[] body = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
                        String jsonStr = helper.bytesToString(body);
                        JSONObject jsonObject = JSONObject.parseObject(jsonStr);
                        jsonObject.put(exp, Utils.GetRandomString(4));
                        String newJsonStr = JSONObject.toJSONString(jsonObject);
                        byte[] newBody = helper.stringToBytes(newJsonStr);
                        byte[] tmpRawRequest = helper.buildHttpMessage(req.getHeaders(), newBody);
                        IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                        tmpReq.getResponse();
                        resultMap.put(payloadDomain, new ScanItem(tmpReq, String.format("Json parameter name: %s", exp)));
                    }
                    } catch (Exception ex) {
                        parent.stderr.println(ex);


                    }



            }

        }
        return resultMap;
    }


    private Map<String, ScanItem> crazyFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        List<String> headers = req.getHeaders();
        Map<String, ScanItem> resultMap = new HashMap<>();
        for (IPOC poc : getSupportedPOCs()) {
            try {
                byte[] rawRequest = baseRequestResponse.getRequest();
                byte[] tmpRawRequest = rawRequest;
                byte[] rawBody = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
                List<String> tmpHeaders = new ArrayList<>(headers);
                Map<String, String> domainHeaderMap = new HashMap<>();
                if (Config.getBoolean(Config.ENABLED_FUZZ_HEADER, true)) {
                    List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
                    for (int i = 1; i < headers.size(); i++) {
                        HttpHeader header = new HttpHeader(headers.get(i));
                        if (Arrays.stream(HEADER_BLACKLIST).noneMatch(h -> h.equalsIgnoreCase(header.Name))) {
                            List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.Name)).collect(Collectors.toList());
                            needSkipheader.forEach(guessHeaders::remove);
                            String tmpDomain = backend.getNewPayload();
                            header.Value = poc.generate(tmpDomain);
                            if (header.Name.equalsIgnoreCase("accept")) {
                                header.Value = "*/*;" + header.Value;
                            }
                            tmpHeaders.set(i, header.toString());
                            domainHeaderMap.put(header.Name, tmpDomain);
                        }
                    }
                    for (String headerName : guessHeaders) {
                        String tmpDomain = backend.getNewPayload();
                        tmpHeaders.add(String.format("%s: %s", headerName, poc.generate(tmpDomain)));
                        domainHeaderMap.put(headerName, tmpDomain);
                    }
                }
                int skipLength = 0;
                int paramsIndex = 0;
                Map<Integer, ParamReplace> paramMap = new HashMap<>();
                Map<String, IParameter> domainParamMap = new HashMap<>();
                tmpRawRequest = parent.helpers.buildHttpMessage(tmpHeaders, rawBody);
                IRequestInfo tmpReqInfo = parent.helpers.analyzeRequest(tmpRawRequest);
                for (IParameter param : tmpReqInfo.getParameters()) {
                    String tmpDomain = backend.getNewPayload();
                    String exp = poc.generate(tmpDomain);
                    boolean UseIparam = false;
                    switch (param.getType()) {
                        case IParameter.PARAM_URL:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_URL, true))
                                continue;
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            UseIparam = true;
                            break;
                        case IParameter.PARAM_COOKIE:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_COOKIE, true))
                                continue;
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            UseIparam = true;
                            break;
                        case IParameter.PARAM_BODY:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_FORM, true))
                                continue;
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            break;
                        case IParameter.PARAM_JSON:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_JSON, true))
                                continue;
                            break;
                        case IParameter.PARAM_MULTIPART_ATTR:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_MULTIPART, true))
                                continue;
                            break;
                        case IParameter.PARAM_XML:
                        case IParameter.PARAM_XML_ATTR:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_XML, true))
                                continue;
                            break;
                    }
                    if (UseIparam) {
                        IParameter newParam = helper.buildParameter(param.getName(), exp, param.getType());
                        tmpRawRequest = helper.updateParameter(tmpRawRequest, newParam);
                    } else {
                        paramMap.put(paramsIndex++, new ParamReplace(
                                param.getValueStart() - tmpReqInfo.getBodyOffset() + skipLength,
                                param.getValueEnd() - tmpReqInfo.getBodyOffset() + skipLength,
                                exp));
                        skipLength += exp.length() - (param.getValueEnd() - param.getValueStart());
                    }
                    domainParamMap.put(tmpDomain, param);
                }
                tmpRawRequest = helper.buildHttpMessage(helper.analyzeRequest(tmpRawRequest).getHeaders(), updateParams(rawBody, paramMap));
                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                for (Map.Entry<String, String> domainHeader : domainHeaderMap.entrySet()) {
                    resultMap.put(domainHeader.getValue(), new ScanItem(domainHeader.getKey(), tmpReq));
                }
                for (Map.Entry<String, IParameter> domainParam : domainParamMap.entrySet()) {
                    resultMap.put(domainParam.getKey(), new ScanItem(domainParam.getValue(), tmpReq));
                }
            } catch (Exception ex) {
                parent.stderr.println(ex);
            }
        }


        return resultMap;
    }

    private byte[] updateParams(byte[] rawBody, Map<Integer, ParamReplace> paramMap) {
        byte[] body = rawBody;
        for (int i = 0; i < paramMap.size(); i++) {
            ParamReplace paramReplace = paramMap.get(i);
            body = Utils.Replace(body, new int[]{paramReplace.Start, paramReplace.End}, paramReplace.Payload.getBytes(StandardCharsets.UTF_8));
            parent.stdout.println(paramReplace);
        }
        return body;
    }


    private Map<String, ScanItem> existingheadersFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        // Fuzzing already existed headers
        // one temp domain :  one existing header   ->   all pocs

        List<String> headers = req.getHeaders();
        List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
        byte[] rawRequest = baseRequestResponse.getRequest();
        Map<String, ScanItem> resultMap = new HashMap<>();

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

                    header.Value = poc.generate(payloadDomain);  //exp

                    tmpHeaders.set(i, header.toString());
                    byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                    IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                    resultMap.put(payloadDomain, new ScanItem(header.Name, tmpReq));
                }
            }
        }
        return resultMap;
    }

    private Map<String, ScanItem> guessheadersFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        // For guessing headers , should use the same
        List<String> headers = req.getHeaders();
        List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
        byte[] rawRequest = baseRequestResponse.getRequest();
        Map<String, ScanItem> resultMap = new HashMap<>();
        List<String> tmpHeaders = new ArrayList<>(headers);
        String tmpDomain = backend.getNewPayload();

        for (IPOC poc : getSupportedPOCs()) {
            try {
            Map<String, String> domainHeaderMap = new HashMap<>();
            for (String headerName : guessHeaders) {
                String payloadDomain = Utils.addPrefixTempDomain(headerName+poc.getIndex(),tmpDomain);

                tmpHeaders.add(String.format("%s: %s", headerName, poc.generate(payloadDomain)));
                domainHeaderMap.put(headerName, payloadDomain);
            }
            byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
            IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
            for (Map.Entry<String, String> domainHeader : domainHeaderMap.entrySet()) {
                resultMap.put(domainHeader.getValue(), new ScanItem(domainHeader.getKey(), tmpReq));
            }
            } catch (Exception ex) {
                parent.stdout.println(ex);
            }
        }
        return resultMap;
    }

        private Map<String, ScanItem> headersFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();

        resultMap.putAll(existingheadersFuzz(baseRequestResponse,req));
        resultMap.putAll(guessheadersFuzz(baseRequestResponse,req));


        return resultMap;
    }

// when iterating Iparamter there seems to be only PARAM_COOKIE and PARAM_JSON
    private Map<String, ScanItem> IParameterFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        String tmpDomain = backend.getNewPayload();
        HashSet<String> paramSet = new HashSet<>();


        for (IParameter param : req.getParameters()) {

                byte[] tmpRawRequest = rawRequest;
                String paramName = param.getName();
                String prefix;
                if (paramSet.contains(paramName)){
                     prefix =  paramName +Utils.GetRandomString(2) ;
                }
                else{
                     prefix = paramName;
                }
                boolean UseIparam = false;
//                boolean skip  = false;
                paramSet.add(paramName);

                for (IPOC poc : getSupportedPOCs()) {

                try {
                    prefix = prefix + poc.getIndex();
                    String payloadDomain = Utils.addPrefixTempDomain(prefix, tmpDomain);

                    String exp = poc.generate(payloadDomain);

                    switch (param.getType()) {
                        case IParameter.PARAM_URL:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_URL, true))
                                continue;
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            UseIparam =true;
                            break;
                        case IParameter.PARAM_COOKIE:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_COOKIE, true))
                                continue;
                            if (this.scannedCookies.contains(param.getName())){
                                continue;
                            }
                            this.scannedCookies.add(param.getName());
                            UseIparam =true;
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            break;
                        case IParameter.PARAM_BODY:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_FORM, true))
                                continue;
                            exp = helper.urlEncode(exp);
                            exp = urlencodeForTomcat(exp);
                            break;
                        case IParameter.PARAM_JSON:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_JSON, true))
                                continue;
                            break;
                        case IParameter.PARAM_XML:
                        case IParameter.PARAM_MULTIPART_ATTR:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_MULTIPART, true))
                                continue;
                            break;
                        case IParameter.PARAM_XML_ATTR:
                            if (!Config.getBoolean(Config.ENABLED_FUZZ_BODY_XML, true))
                                continue;
                            break;
                    }


                    if (UseIparam) {
                        IParameter newParam = helper.buildParameter(param.getName(), exp, param.getType());
                        tmpRawRequest = helper.updateParameter(rawRequest, newParam);
                    } else {
                        byte[] body = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
                        byte[] newBody = Utils.Replace(body, new int[]{param.getValueStart() - req.getBodyOffset(), param.getValueEnd() - req.getBodyOffset()}, exp.getBytes(StandardCharsets.UTF_8));
                        tmpRawRequest = helper.buildHttpMessage(req.getHeaders(), newBody);
                    }

                    IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                    tmpReq.getResponse();
                    resultMap.put(tmpDomain, new ScanItem(param, tmpReq));
                }catch(Exception ex){
                    parent.stdout.println(ex);
                }

            }

        }
        return resultMap;
    }


    private List<IScanIssue> finalCheck(IHttpRequestResponse baseRequestResponse, IRequestInfo req, Map<String, ScanItem> resultMap) {
        List<IScanIssue> issues = new ArrayList<>();
        if (backend.flushCache(resultMap.size())) {
            for (Map.Entry<String, ScanItem> tmpdomainItem :
                    resultMap.entrySet()) {
                ScanItem item = tmpdomainItem.getValue();
                boolean hasIssue = backend.CheckResult(tmpdomainItem.getKey());
                if (hasIssue) {
                    String desciption;
                    if (item.HasExplantion){
                        desciption =  String.format("Vulnerable point is in path with payload %s \r\n Explanation: %s", tmpdomainItem.getKey(),tmpdomainItem.getValue().explanation);
                    }else {
                        desciption =String.format("Vulnerable param is \"%s\" in %s.", item.IsHeader ? item.HeaderName : item.Param.getName(), item.IsHeader ? "Header" : getTypeName(item.Param.getType()));
                    }


                    issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                            req.getUrl(),
                            new IHttpRequestResponse[]{baseRequestResponse, item.TmpRequest},
                            "Log4j2 RCE Detected",
                            desciption,
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
