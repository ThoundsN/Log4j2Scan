package burp;

import burp.scanner.Log4j2Scanner;
import burp.utils.Utils;

import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, ITab {

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public String version = "0.6";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Utils.Callback = this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerScannerCheck(new Log4j2Scanner(this));
        callbacks.setExtensionName("Log4j2Scan v" + version);

    }

    @Override
    public String getTabCaption() {
        return null;
    }

    @Override
    public Component getUiComponent() {
        return null;
    }
}


//add json request and x-www-url-formed support
//
//
//add parameter in url
//use one single random domain for one request
//backfix in path
//
//
//
//tmpdomain: original requerst
//tmpdomain: scanitem  ->  (request, iparameter)  ,(request, headername)
//
//
//
//pattern of log4j usage in opensource project and other cms


//add key cache to remove duplicate , host url parameter   done
