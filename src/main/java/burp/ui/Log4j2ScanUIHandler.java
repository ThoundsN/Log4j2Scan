package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtender;
import burp.ITab;
import burp.ui.tabs.BackendUIHandler;
import burp.ui.tabs.CacheUIHandler;
import burp.ui.tabs.FuzzUIHandler;
import burp.ui.tabs.POCUIHandler;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;

public class Log4j2ScanUIHandler implements ITab {
    public JTabbedPane mainPanel;
    public BurpExtender parent;
    public BackendUIHandler bui;
    public POCUIHandler pui;
    public FuzzUIHandler fui;
    public CacheUIHandler cui;

    public Log4j2ScanUIHandler(BurpExtender parent) {
        this.parent = parent;
        this.initUI();
    }

    private void initUI() {
        this.mainPanel = new JTabbedPane();
        bui = new BackendUIHandler(parent);
        pui = new POCUIHandler(parent);
        fui = new FuzzUIHandler(parent);
        cui = new CacheUIHandler(parent);
        this.mainPanel.addTab("Backend", bui.getPanel());
        this.mainPanel.addTab("POC", pui.getPanel());
        this.mainPanel.addTab("Fuzz", fui.getPanel());
        this.mainPanel.addTab("Cache", cui.getPanel());

    }

    @Override
    public String getTabCaption() {
        return "Log4j2Scan";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}