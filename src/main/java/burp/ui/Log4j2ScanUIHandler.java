package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtender;
import burp.ITab;
import burp.ui.tabs.BackendUIHandler;
import burp.ui.tabs.POCUIHandler;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;

public class Log4j2ScanUIHandler implements ITab {
    public JTabbedPane mainPanel;
    public BurpExtender parent;

    public Log4j2ScanUIHandler(BurpExtender parent) {
        this.parent = parent;
        this.initUI();
    }

    private void initUI() {
        this.mainPanel = new JTabbedPane();
        BackendUIHandler bui = new BackendUIHandler(parent);
        POCUIHandler pui = new POCUIHandler(parent);
        this.mainPanel.addTab("Backend", bui.getPanel());
        this.mainPanel.addTab("POC", pui.getPanel());
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