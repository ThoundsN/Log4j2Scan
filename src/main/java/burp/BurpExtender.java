package burp;

import burp.scanner.Log4j2Scanner;
import burp.utils.Utils;
import burp.ui.Log4j2ScanUIHandler;


import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, ITab {

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Log4j2ScanUIHandler uiHandler;
    public Log4j2Scanner scanner;
    public String version = "0.8";


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Utils.Callback = this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerScannerCheck(new Log4j2Scanner(this));
        callbacks.setExtensionName("Log4j2Scan v" + version);
        callbacks.setExtensionName("Log4j2Scan");
        this.stdout.println("Log4j2Scan v" + version);
        this.uiHandler = new Log4j2ScanUIHandler(this);
        callbacks.addSuiteTab(this.uiHandler);
        this.reloadScanner();

    }

    @Override
    public String getTabCaption() {
        return null;
    }

    @Override
    public Component getUiComponent() {
        return null;
    }

    public void reloadScanner() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
        scanner = new Log4j2Scanner(this);
        callbacks.registerScannerCheck(scanner);
    }
}


//add json request and x-www-url-formed support
//
//
//add parameter in url
//use one single random domain for one request
//backfix in path
//improve check logic

//
//subdomain of hashed domain
//
//tmpdomain: original requerst
//tmpdomain: scanitem  ->  (request, iparameter)  ,(request, headername)
//
//



//add key cache to remove duplicate , host url parameter   done
