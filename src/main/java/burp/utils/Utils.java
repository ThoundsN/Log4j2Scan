package burp.utils;


import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import burp.poc.IPOC;

import java.lang.reflect.Field;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class Utils {
    public static IBurpExtenderCallbacks Callback;
    private static MessageDigest md;
    private static Random rand = new Random();

    public static int GetRandomNumber(int min, int max) {
        return rand.nextInt(max - min + 1) + min;
    }

    public static Boolean GetRandomBoolean() {
        return rand.nextInt(100) > 50;
    }

    public static String GetRandomString(int length) {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = rand.nextInt(str.length() - 1);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    public static int[] getRandomIndex(int size, int max) {
        if (size > max) size = max;
        return ThreadLocalRandom.current().ints(0, max).distinct().limit(size).toArray();
    }

    public static long getRandomLong() {
        return rand.nextLong();
    }

    public static Map<Integer, IPOC> getPOCs(Integer[] pocRange) {
        Map<Integer, IPOC> pocs = new HashMap();
        for (int pocId : pocRange) {
            try {
                pocs.put(pocId, (IPOC) Class.forName("burp.poc.impl.POC" + pocId).getConstructor().newInstance());
            } catch (Exception ex) {
                Utils.Callback.printOutput(ex.toString());
            }
        }
        return pocs;
    }

    public static String confusionChars(String[] _chars) {
        StringBuilder result = new StringBuilder();
        int confusionCount = Utils.GetRandomNumber(1, _chars.length);
        int[] confustionCharIndexs = Utils.getRandomIndex(confusionCount, _chars.length);
        for (int i = 0; i < _chars.length; i++) {
            int finalI = i;
            if (Arrays.stream(confustionCharIndexs).anyMatch(c -> c == finalI)) {
                result.append(confusionChar(_chars[i]));
            } else {
                result.append(_chars[i]);
            }
        }
        return result.toString();
    }

    public static String confusionChar(String _char) {
        int garbageCount = Utils.GetRandomNumber(2, 5);
        StringBuilder garbage = new StringBuilder();
        for (int i = 0; i < garbageCount; i++) {
            int garbageLength = Utils.GetRandomNumber(3, 6);
            String garbageWord = Utils.GetRandomString(garbageLength);
            garbage.append(garbageWord).append(":");
        }
        return String.format("${%s-%s}", garbage, _char);
    }

    public static byte[] byteMerger(byte[] bt1, byte[] bt2) {
        byte[] bt3 = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }

    public static String getCurrentTimeMillis() {
        return String.valueOf(System.currentTimeMillis());
    }

    public static byte[] MD5(byte[] src) {
        if (md == null) {
            try {
                md = MessageDigest.getInstance("md5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("MD5 not found!");
            }
        }
        byte[] secretBytes = null;
        secretBytes = md.digest(src);
        return secretBytes;
    }


    public static byte[] Replace(byte[] request, int[] selectedIndexRange, byte[] targetBytes) {
        byte[] result = new byte[request.length - (selectedIndexRange[1] - selectedIndexRange[0]) + targetBytes.length];
        System.arraycopy(request, 0, result, 0, selectedIndexRange[0]);
        System.arraycopy(targetBytes, 0, result, selectedIndexRange[0], targetBytes.length);
        System.arraycopy(request, selectedIndexRange[1], result, selectedIndexRange[0] + targetBytes.length, request.length - selectedIndexRange[1]);
        return result;
    }



    public static String addPrefixTempDomain(String prefix,String tmpdomain){
        String replaced = prefix.replaceAll("[_'-/?!.=+;:&%#~]","");
         replaced =replaced.toLowerCase();

        return replaced + "." + tmpdomain;

    }

    public static String getKeyOfRequest(IRequestInfo request){
        String method = request.getMethod();
        String url = request.getUrl().toString();
        String host = request.getUrl().getHost();
        String path = request.getUrl().getPath();
        List<IParameter> params =  request.getParameters();
        StringBuilder paramNameStr = new StringBuilder();
        for (IParameter param : params){
            if( param.getType() == IParameter.PARAM_URL){
                paramNameStr.append('_' + param.getName());
            }
        }
//        return method+":"+ host + paramNameStr.toString();
        return method+":"+ host + path +  paramNameStr.toString();
    }

    public static Boolean checkWAF(Map<String,ScanItem> resultMap, IExtensionHelpers helpers){
        Boolean hasWaf = true;
        for (ScanItem item : resultMap.values()){
            if (helpers.analyzeResponse(item.TmpRequest.getResponse()).getStatusCode() != 403 ){
                hasWaf = false;
            }

        }
        return hasWaf;

    }

    //burp are unable to process dot less i with its api
    public static String unicodeReplace(String poc){
        return poc.replace("??","@@@@");
    }

    public static String unicodeRestore(String reqString){
        reqString = reqString.replace("%40%40%40%40","??");
        return reqString.replace("@@@@","??");

    }

    public static byte[] unicodeRestore(byte[] tmpRawRequest){
        String bytesAsString = new String(tmpRawRequest, StandardCharsets.UTF_8);
        bytesAsString = Utils.unicodeRestore(bytesAsString);
        tmpRawRequest = bytesAsString.getBytes(StandardCharsets.UTF_8);
        return tmpRawRequest;
    }
}
