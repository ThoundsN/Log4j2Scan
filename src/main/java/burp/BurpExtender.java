package burp;

import burp.scanner.Log4j2Scanner;
import burp.utils.Cache;
import burp.utils.Utils;
import burp.ui.Log4j2ScanUIHandler;


import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender,IExtensionStateListener  {

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Log4j2ScanUIHandler uiHandler;
    public Log4j2Scanner scanner;
    public Cache cache;
    public String version = "1.2";


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Utils.Callback = this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.registerScannerCheck(new Log4j2Scanner(this));
        callbacks.setExtensionName("Log4j2Scan");
        this.stdout.println("Log4j2Scan v" + version);
        this.uiHandler = new Log4j2ScanUIHandler(this);
        callbacks.addSuiteTab(this.uiHandler);
        this.cache = new Cache(this);
        this.reloadScanner();

    }


    public void reloadScanner() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
        scanner = new Log4j2Scanner(this);
        callbacks.registerScannerCheck(scanner);
    }

    public void extensionUnloaded() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
    }
}


//improve check logic



//delete  scannedurls cache , only key url
//check crazy fuzz to bypass wlist parameter





//subdomain of hashed domain  done
//add key cache to remove duplicate , host url parameter   done
//backfix in path  done
//param whilte list  done
//use one single random domain for one request     done  not very useful
//host whilelist  done



