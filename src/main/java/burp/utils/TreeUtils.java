package burp.utils;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class TreeUtils {

    public static ArrayList<String> parseUrl(URL url){
        ArrayList<String> urlParsedList = new ArrayList<>();
        urlParsedList.add(url.getHost());
        urlParsedList.addAll(Arrays.asList(url.getPath().split("/")));
        urlParsedList.removeAll(Arrays.asList("", null));
        return urlParsedList;

    }

    public static TreeNode<String> addUrlToTree(TreeNode<String> root,URL url ) {
        ArrayList<String> urlParsedList = parseUrl(url);
        TreeNode<String> curNode = root;
        for (String element :urlParsedList){
            curNode = curNode.addChild(element);
        }
        return root;
    }

    public static Boolean isUrlHostInTree(TreeNode<String> root, URL url){
        ArrayList<String> urlParsedList = parseUrl(url);
        if (root.children.stream().noneMatch(s->s.data.equalsIgnoreCase(urlParsedList.get(0)))){
            return false;
            // Case3 : url totally not in tree

        }
        return true;
    }

    public static TreeNode<String> searchUrlSegmentInTree(TreeNode<String> root, URL url){
        ArrayList<String> urlParsedList = parseUrl(url);
        TreeNode<String> parentNode = root;
        boolean urlInTree = true;
        for (String curStr : urlParsedList) {
            if(parentNode.children.stream().noneMatch(s->s.data.equalsIgnoreCase(curStr))){
                urlInTree = false;
            }
            for (TreeNode<String> curNode : parentNode.children) {
                if (curNode.data.equals(curStr)) {
                    parentNode = curNode;
                    break;
                }
            }
        }
        if(urlInTree){
            return null;
            //case1: url in tree
        }
        return parentNode;
        //case2 prefix of url in tree
    }



    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            char cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    public static Boolean isHighEntropy(String str){
        if(getShannonEntropy(str) > 3.65){
            return true;
        }
        return false;

    }

    //    /aaa/123/ccc    /aaa/456/bbb
    public static Boolean isNounceSubPathInteresting(ArrayList<String> urlList,TreeNode<String> parent, int index) {
        String pathSegment = urlList.get(index);
        if(mightBeNounce(pathSegment)){
            return false;
        }
        for (TreeNode<String> child : parent.children) {
            if (child.data.equalsIgnoreCase(pathSegment)) {
                if (urlList.size() == index + 1) {
                    return false;
                }
                if (!child.children.isEmpty()) {
                    return isNounceSubPathInteresting(urlList, child, index + 1);
                }
            }

        }
        return true;

    }

    // high entrophy, numeric, most are random numbers

    public static Boolean mostlyNumeric(String str){
        int count = 0;
        for(int i =0; i < str.length(); i++){
            char c = str.charAt(i);
            if(Character.isDigit(c)){
                count++;
            }
        }
        double ratio = (double) count/str.length();
        return ratio > 0.75;

    }

    public static Boolean mightBeNounce(String str){
        return isHighEntropy(str) || str.chars().allMatch(Character::isDigit) || str.length() > 25 || mostlyNumeric(str);
    }

    public static Boolean isSubPathInteresting(ArrayList<String> urlList,TreeNode<String> parent, int index  ){
        String pathSegment = urlList.get(index);
        if (mightBeNounce(pathSegment)){

            for (TreeNode<String> child : parent.children){
                if (mightBeNounce(child.data)){
                    //  Check whether the number is the last segment of path   /123

                    if (urlList.size() == index +1 ){
                        return  false;
                    }
                    if(!child.children.isEmpty() ){
                        return isNounceSubPathInteresting(urlList, child, index + 1);
                    }else{
                        return true;
                        // urlList is bigger than current url in tree,  like   /123/aaa  compared to /123
                    }
                }
            }
        }
        for (TreeNode<String> child : parent.children) {

            if(child.data.equalsIgnoreCase(pathSegment)){
//                System.out.println("called");
                return isSubPathInteresting(urlList,child,index+1);
            }
        }
        return true;
    }
}
