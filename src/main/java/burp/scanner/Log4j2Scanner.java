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

import burp.utils.TreeUtils.*;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    public IBackend backend;
    private Config.FuzzMode fuzzMode;

    private HashSet<String> scannedCookies;

//    private final String[] HEADER_WHITELIST = new String[]{
//            "content-length",
//            "cookie",
//            "host",
//            "content-type"
//    };
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
            "iso",
            "webm",
            "webm2"
    };


    private final String[] STATIC_FILE_TYPE = new String[]{
            "image",
            "gif",
            "css",
            "video",
            "jpeg",
            "script"
    };


    private IPOC[] pocs;

    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
        this.pocs = new IPOC[]{new POC1(), new POC2(), new POC3(), new POC4(), new POC11()};
        this.loadConfig();

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
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) {
        this.fuzzMode = Config.FuzzMode.valueOf(Config.get(Config.FUZZ_MODE, Config.FuzzMode.EachFuzz.name()));
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        URL url = req.getUrl();
        boolean isWafHost = false;
//        parent.stdout.println("do active scan: " +  req.getUrl().toString());

        for(String whitelistHost : Cache.HOST_WHITELIST){
            if (req.getUrl().getHost().contains(whitelistHost)){
                return issues;
            }
        }

        if (isStaticFile(url.toString(),baseRequestResponse)){
            return issues;
        }

        for(String wafHost : Cache.WAFHOST_WHITELIST){
            if (req.getUrl().getHost().equalsIgnoreCase(wafHost)){
                if (req.getContentType() != IRequestInfo.CONTENT_TYPE_JSON){
                    parent.stdout.println("Skiped waf host: "+ url.toString());
                    return issues;
                }
                isWafHost = true;
            }
        }

        String key = Utils.getKeyOfRequest(req);
        if (Cache.KEY_OF_REQUESTS.keySet().contains(key)){
            return issues;
        }

        try {
            if (!TreeUtils.isUrlHostInTree(Cache.rootNode, url)) {
                TreeUtils.addUrlToTree(Cache.rootNode, url);
                parent.stdout.println(TreeUtils.parseUrl(url).toString() + "   not in tree, adding it  ");
            } else {
                TreeNode<String> ptrNode = TreeUtils.searchUrlSegmentInTree(Cache.rootNode, url);
                if (ptrNode == null) {
                    parent.stdout.println(TreeUtils.parseUrl(url).toString() + " already in tree ");
                    return issues;
                } else {
                    ArrayList<String> urlList = TreeUtils.parseUrl(url);
                    if (TreeUtils.isSubPathInteresting(urlList, ptrNode, ptrNode.depth)) {
                        TreeUtils.addUrlToTree(Cache.rootNode, url);
                        parent.stdout.println(TreeUtils.parseUrl(url).toString() + " is interesting  , added to tree");
                    } else {
                        parent.stdout.println(TreeUtils.parseUrl(url).toString() + " isn't interesting  ");
                        return issues;
                    }
                }
            }
        }catch (Exception ex){
            parent.stdout.println(ex.getStackTrace());
        }

        //Started scanning
        parent.cache.addRequestKey(req);

        parent.stdout.println(String.format("Scanning: %s", url.toString()));
        Map<String, ScanItem> resultMap = new HashMap<>();

        if(isWafHost){
            resultMap.putAll(crazyFuzzJson(baseRequestResponse,req));
        }
        else if (this.fuzzMode == Config.FuzzMode.EachFuzz) {
            resultMap.putAll(IParameterFuzz(baseRequestResponse, req));
            if (Config.getBoolean(Config.ENABLED_FUZZ_HEADER, true)) {
                resultMap.putAll(headersFuzz(baseRequestResponse, req));
            }
            resultMap.putAll(pathFuzz(baseRequestResponse,req));
            resultMap.putAll(paramNameFuzz(baseRequestResponse,req));
            Utils.checkWAF(resultMap,helper);

        }
        else if (this.fuzzMode == Config.FuzzMode.Crazy) {
            resultMap.putAll(crazyFuzzIParam(baseRequestResponse, req));
            resultMap.putAll(crazyFuzzHeader(baseRequestResponse, req));
            resultMap.putAll(crazyFuzzCookie(baseRequestResponse, req));
            resultMap.putAll(pathFuzz(baseRequestResponse,req));
            resultMap.putAll(paramNameFuzz(baseRequestResponse,req));
            Utils.checkWAF(resultMap,helper);

            resultMap.putAll(badJsonFuzz(baseRequestResponse,req));
            resultMap.putAll(crazyFuzzJson(baseRequestResponse,req));
        }


        try {
            Thread.sleep(3333); //sleep 3s, wait for network delay.
        } catch (InterruptedException e) {
            parent.stdout.println(e);
        }
        issues.addAll(finalCheck(baseRequestResponse, req, resultMap));
        parent.stdout.println(String.format("Scan complete: %s", url));
        return issues;
    }

    private boolean isStaticFile(String url,IHttpRequestResponse baseRequestResponse) {
        IResponseInfo resposne = this.parent.helpers.analyzeResponse(baseRequestResponse.getResponse());
        String mimeType = resposne.getStatedMimeType();
        Boolean b = Arrays.stream(STATIC_FILE_TYPE).anyMatch(s -> s.equalsIgnoreCase(mimeType));

        Boolean a = Arrays.stream(STATIC_FILE_EXT).anyMatch(s -> s.equalsIgnoreCase(HttpUtils.getUrlFileExt(url)));

        return a||b ;

    }


    private Collection<IPOC> getSupportedPOCs() {
        return Arrays.stream(pocs).filter(p -> Arrays.stream(backend.getSupportedPOCTypes()).anyMatch(c -> c == p.getType())).collect(Collectors.toList());
    }


    private Map<String, ScanItem> badJsonFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> domainMap = new HashMap<>();
        boolean canFuzz = false;
        List<String> rawHeaders = req.getHeaders();
        List<String> tmpHeaders = new ArrayList<>(rawHeaders);
        for (int i = 1; i < rawHeaders.size(); i++) {
            HttpHeader header = new HttpHeader(rawHeaders.get(i));
            if (header.Name.equalsIgnoreCase("content-type")) {  //has content-type header, maybe accept application/json?
                header.Value = "application/json;charset=UTF-8";
                tmpHeaders.set(i, header.toString());
                canFuzz = true;
            }
        }
        if (canFuzz) {
            for (IPOC poc : getSupportedPOCs()) {
                String tmpDomain = backend.getNewPayload();
                String exp = poc.generate(tmpDomain);
                String finalPaylad = String.format("{\"%s\":%d%s%d}",   //try to create a bad-json.
                        Utils.GetRandomString(Utils.GetRandomNumber(3, 10)),
                        Utils.GetRandomNumber(100, Integer.MAX_VALUE),
                        exp,
                        Utils.GetRandomNumber(100, Integer.MAX_VALUE));
                IParameter fakeParam = helper.buildParameter("Bad-json Fuzz", exp, IParameter.PARAM_JSON);
                byte[] newRequest = helper.buildHttpMessage(tmpHeaders, finalPaylad.getBytes(StandardCharsets.UTF_8));
                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                domainMap.put(tmpDomain, new ScanItem(fakeParam, tmpReq));
            }
        }
        return domainMap;
    }

    private Map<String, ScanItem> pathFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();

        String tmpDomain = backend.getNewPayload();
        String payload = "";

            for (IPOC poc : getSupportedPOCs()) {
                try {
                //backfixpath
                String payloadDomain = Utils.addPrefixTempDomain("path" + poc.getIndex(), tmpDomain);
                String exp = poc.generate(payloadDomain);
                if(poc.getType() == IPOC.UNICODE){
                    exp = Utils.unicodeReplace(exp);
                }
                exp = helper.urlEncode(exp);
                exp = urlencodeForTomcat(exp);
                payload = "/"+exp+ payload;

                } catch (Exception ex) {
                    parent.stdout.println(ex.getStackTrace());
            }

        }
        String path = req.getUrl().getPath();
        byte[] rawpayloadReq = helper.stringToBytes(helper.bytesToString(baseRequestResponse.getRequest()).replace(path, path + payload));
        rawpayloadReq = Utils.unicodeRestore(rawpayloadReq);
        IHttpRequestResponse requestResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), rawpayloadReq);
        resultMap.put(tmpDomain, new ScanItem(requestResponse, "backfix path fuzz"));
        return resultMap;

    }

    private Map<String, ScanItem> paramNameFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();
        

        String tmpDomain = backend.getNewPayload();
        HashSet<Byte> paramType_set = new HashSet();
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] tmpRawRequest = rawRequest;
        byte[] body = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
        ArrayList<IParameter> paramList =  new ArrayList<>();
        HashMap<String,String> jsonMap = new HashMap<>();
        HashMap<String,String> paramTypeMap = new HashMap<>();


        for (IParameter param : req.getParameters()){
            paramType_set.add(param.getType());
        }

                for (Byte paramtype : paramType_set) {
                        Boolean useIparam = false;
                        Boolean IsJson = false;
                        String typename = this.getTypeName(paramtype);


                        switch (paramtype) {
                            case IParameter.PARAM_URL:
                                useIparam = true;
                                break;
                            case IParameter.PARAM_BODY:

                                useIparam = true;
                                break;
                            case IParameter.PARAM_COOKIE:
                                useIparam = true;
                                break;
                            case IParameter.PARAM_JSON:
                                IsJson = true;
                                break;
                            case IParameter.PARAM_XML:
                                continue;
                            case IParameter.PARAM_MULTIPART_ATTR:
                                continue;
                            case IParameter.PARAM_XML_ATTR:
                                continue;

                        }
                    for (IPOC poc : getSupportedPOCs()) {

                            String payloadDomain = Utils.addPrefixTempDomain(typename + poc.getIndex(), tmpDomain);
                            String exp = poc.generate(payloadDomain);

                        if(poc.getType() == IPOC.UNICODE){
                            exp = Utils.unicodeReplace(exp);
                        }

                            if (useIparam) {
                                exp = helper.urlEncode(exp);
                                exp = urlencodeForTomcat(exp);
                                IParameter newParam = helper.buildParameter(exp, Utils.GetRandomString(4), paramtype);
                                paramList.add(newParam);
                                paramTypeMap.put(payloadDomain, typename);

                            } else if (IsJson) {

                                jsonMap.put(exp, Utils.GetRandomString(4));

                            }
                        }
                        if (IsJson) {
                            try {
                                String jsonStr = helper.bytesToString(body);
                                JSONObject jsonObject = JSONObject.parseObject(jsonStr);
                                jsonObject.putAll(jsonMap);
                                String newJsonStr = JSONObject.toJSONString(jsonObject);
                                byte[] newBody = helper.stringToBytes(newJsonStr);
                                tmpRawRequest = helper.buildHttpMessage(req.getHeaders(), newBody);
                            }catch (Exception  ex ){
                                parent.stdout.println("body:  "+  helper.bytesToString(body));
                                parent.stdout.println(ex.getStackTrace());;
                                continue;
                        }
                        for (IParameter param : paramList) {
                            tmpRawRequest = helper.addParameter(tmpRawRequest, param);

                        }

                        tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
                        IHttpRequestResponse tmpReqRes = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                        tmpReqRes.getResponse();


                        for (Map.Entry<String, String> entry : paramTypeMap.entrySet()) {
                            resultMap.put(entry.getKey(), new ScanItem(tmpReqRes, String.format("%s parameter name: %s", entry.getValue(), entry.getKey())));
                        }
                    }
                    }
        return resultMap;

        }


    private Map<String, ScanItem> crazyFuzzHeader(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
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
                        if (!Cache.HEADER_WHITELIST.stream().anyMatch(header.Name::equalsIgnoreCase) && !Cache.PARAMNAME_WHITELIST.stream().anyMatch(header.Name::equalsIgnoreCase)) {
                            List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.Name)).collect(Collectors.toList());     //remove guessheader from existing headers
                            needSkipheader.forEach(guessHeaders::remove);
                            String tmpDomain = backend.getNewPayload();
                            if (poc.getType() == IPOC.UNICODE){
                                header.Value = Utils.unicodeReplace(poc.generate(tmpDomain));
                            }else{
                                header.Value = poc.generate(tmpDomain);
                            }
                            if (header.Name.equalsIgnoreCase("accept")) {
                                header.Value = "*/*;" + header.Value;
                            }
                            tmpHeaders.set(i, header.toString());
                            domainHeaderMap.put(header.Name, tmpDomain);
                        }
                    }
                    for (String headerName : guessHeaders) {
                        String tmpDomain = backend.getNewPayload();
                        String exp = poc.generate(tmpDomain);
                        if (poc.getType() == IPOC.UNICODE){
                            exp = Utils.unicodeReplace(poc.generate(tmpDomain));
                        }
                        tmpHeaders.add(String.format("%s: %s", headerName, exp));
                        domainHeaderMap.put(headerName, tmpDomain);
                    }
                }
                tmpRawRequest = parent.helpers.buildHttpMessage(tmpHeaders, rawBody);

                if(poc.getType() == IPOC.UNICODE){
                    tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
                }
                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);


                for (Map.Entry<String, String> domainHeader : domainHeaderMap.entrySet()) {
                    resultMap.put(domainHeader.getValue(), new ScanItem(domainHeader.getKey(), tmpReq));
                }
            }catch (Exception ex ){
                parent.stdout.println(ex.getStackTrace());;
            }
        }

        return resultMap;
    }
    private Map<String, ScanItem> crazyFuzzCookie(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();
        for (IPOC poc : getSupportedPOCs()) {
            try{
                Map<String, IParameter> domainParamMap = new HashMap<>();
                byte[] rawRequest = baseRequestResponse.getRequest();
                byte[] tmpRawRequest = rawRequest;

                for (IParameter param : req.getParameters()) {
                    if (Cache.inWhiteList(param.getName())) {
                        continue;
                    }
                    String tmpDomain = backend.getNewPayload();
                    String exp = poc.generate(tmpDomain);
                    if (poc.getType() == IPOC.UNICODE){
                        exp = Utils.unicodeReplace(exp);
                    }
                    if (param.getType() == IParameter.PARAM_COOKIE){
                        exp = helper.urlEncode(exp);
                        exp = urlencodeForTomcat(exp);
                        IParameter newParam = helper.buildParameter(param.getName(), exp, param.getType());
                        tmpRawRequest = helper.updateParameter(tmpRawRequest, newParam);
                        domainParamMap.put(tmpDomain, param);

                    }
                }
                if(poc.getType() == IPOC.UNICODE){
                    tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
                }


                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                for (Map.Entry<String, IParameter> domainParam : domainParamMap.entrySet()) {
                    resultMap.put(domainParam.getKey(), new ScanItem(domainParam.getValue(), tmpReq));
                }

                }catch (Exception ex){
                parent.stdout.println(ex.getStackTrace());
            }
        }


            return resultMap;
    }


    private Map<String, ScanItem> crazyFuzzJson(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();
        if(helper.analyzeRequest(baseRequestResponse).getContentType() !=  IRequestInfo.CONTENT_TYPE_JSON){
            return resultMap;
        }
        String tmpDomain = backend.getNewPayload();
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] tmpRawRequest = rawRequest;
        byte[] rawBody = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
        int skipLength = 0;
        int paramsIndex = 0;
        Map<Integer, ParamReplace> paramMap = new HashMap<>();
        Map<String, IParameter> domainParamMap = new HashMap<>();
        for (IParameter param : req.getParameters()) {
            if (Cache.inWhiteList(param.getName()) ||param.getType() != IParameter.PARAM_JSON) {
                continue;
            }
            try{
                String expDomain = Utils.addPrefixTempDomain(param.getName()+"0",tmpDomain);
                String exp = POC0.generate(expDomain);
                paramMap.put(paramsIndex++, new ParamReplace(
                        param.getValueStart() - req.getBodyOffset() + skipLength,
                        param.getValueEnd() - req.getBodyOffset() + skipLength,
                        exp));
                skipLength += exp.length() - (param.getValueEnd() - param.getValueStart());
                domainParamMap.put(expDomain, param);
            }catch (Exception ex){
                parent.stdout.println(ex);
            }

        }
        tmpRawRequest = helper.buildHttpMessage(helper.analyzeRequest(tmpRawRequest).getHeaders(), updateParams(rawBody, paramMap));
        IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
        for (Map.Entry<String, IParameter> domainParam : domainParamMap.entrySet()) {
            resultMap.put(domainParam.getKey(), new ScanItem(domainParam.getValue(), tmpReq));
        }

        return resultMap;
    }


    private Map<String, ScanItem> crazyFuzzIParam(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        Map<String, ScanItem> resultMap = new HashMap<>();

        for (IPOC poc : getSupportedPOCs()) {
            try {
                byte[] rawRequest = baseRequestResponse.getRequest();
                byte[] tmpRawRequest = rawRequest;
                byte[] rawBody = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
                int skipLength = 0;
                int paramsIndex = 0;
                Map<Integer, ParamReplace> paramMap = new HashMap<>();
                Map<String, IParameter> domainParamMap = new HashMap<>();
                IRequestInfo tmpReqInfo = parent.helpers.analyzeRequest(tmpRawRequest);
                for (IParameter param : tmpReqInfo.getParameters()) {
                    if (Cache.inWhiteList(param.getName())) {
                        continue;
                    }
                    String tmpDomain = backend.getNewPayload();
                    String exp = poc.generate(tmpDomain);

                    if(poc.getType() == IPOC.UNICODE){
                        exp = Utils.unicodeReplace(exp);
                    }
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
//                            exp = helper.urlEncode(exp);
//                            exp = urlencodeForTomcat(exp);
//                            UseIparam = true;
//                            break;
                            continue;
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
                if(poc.getType() == IPOC.UNICODE){
                    tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
                }
                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                for (Map.Entry<String, IParameter> domainParam : domainParamMap.entrySet()) {
                    resultMap.put(domainParam.getKey(), new ScanItem(domainParam.getValue(), tmpReq));
                }
            } catch (Exception ex) {
                parent.stdout.println(ex);
            }
        }
        return resultMap;
    }




    private byte[] updateParams(byte[] rawBody, Map<Integer, ParamReplace> paramMap) {
        byte[] body = rawBody;
        for (int i = 0; i < paramMap.size(); i++) {
            ParamReplace paramReplace = paramMap.get(i);
            body = Utils.Replace(body, new int[]{paramReplace.Start, paramReplace.End}, paramReplace.Payload.getBytes(StandardCharsets.UTF_8));
//            parent.stdout.println(paramReplace);
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
            if (!Cache.HEADER_WHITELIST.stream().anyMatch(header.Name::equalsIgnoreCase) && !Cache.PARAMNAME_WHITELIST.stream().anyMatch(header.Name::equalsIgnoreCase)) {
                //header is not cookie, host
                List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.Name)).collect(Collectors.toList());
                needSkipheader.forEach(guessHeaders::remove);
                // remove alreay existed header from guess headers
                String tmpDomain = backend.getNewPayload();
                String payloadDomain = Utils.addPrefixTempDomain(header.Name,tmpDomain);
                for (IPOC poc : getSupportedPOCs()) {

                    List<String> tmpHeaders = new ArrayList<>(headers);

                    header.Value = poc.generate(payloadDomain);  //exp
                    if(poc.getType() == IPOC.UNICODE){
                        header.Value = Utils.unicodeReplace(header.Value);
                    }

                    tmpHeaders.set(i, header.toString());
                    byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                    if(poc.getType() == IPOC.UNICODE){
                        tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
                    }
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
                if(poc.getType() == IPOC.UNICODE){
                    payloadDomain = Utils.unicodeReplace(payloadDomain);
                }

                tmpHeaders.add(String.format("%s: %s", headerName, poc.generate(payloadDomain)));
                domainHeaderMap.put(headerName, payloadDomain);
            }
            byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
            if(poc.getType() == IPOC.UNICODE){
                tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
            }
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
            if (Cache.inWhiteList(param.getName())){
                continue;
            }

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

                    if(poc.getType() == IPOC.UNICODE){
                        exp = Utils.unicodeReplace(exp);
                    }

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
                    if(poc.getType() == IPOC.UNICODE){
                        tmpRawRequest = Utils.unicodeRestore(tmpRawRequest);
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
        parent.cache.updateRequestKey(req);
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
        BackendUIHandler.Backends currentBackend = BackendUIHandler.Backends.valueOf(Config.get(Config.CURRENT_BACKEND, BackendUIHandler.Backends.GoDnslog.name()));
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
                    this.backend = new GoDnslog(parent);
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
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
