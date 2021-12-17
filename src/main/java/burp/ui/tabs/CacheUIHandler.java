package burp.ui.tabs;

import burp.BurpExtender;
import burp.utils.Cache;
import burp.utils.Config;
import burp.utils.UIUtil;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;


public class CacheUIHandler {
    private  BurpExtender parent;
    private JPanel mainPanel;
    private JTextArea wlistParamInput;
    private JTextArea wlistParamDisplay;
    private JScrollPane wlistParamDisplayscroll;
    private Insets buttonMargin = new Insets(0, 3, 0, 3);


    public CacheUIHandler(BurpExtender parent) {
        this.parent = parent;
    }


    public JPanel getPanel() {
        mainPanel = new JPanel();
        mainPanel.setAlignmentX(0.0f);
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setLayout(new BoxLayout(mainPanel, 1));
        JPanel panel1 = UIUtil.GetXJPanel();
        JTabbedPane cachePanel = new JTabbedPane();
        cachePanel.add("WhiteList ParamName ",getWhilelistPanel());
        panel1.add(cachePanel);
        mainPanel.add(panel1);

        return mainPanel;
    }

    private JPanel getWhilelistPanel(){
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        JPanel subPanel1 = UIUtil.GetXJPanel();
        this.wlistParamInput = new JTextArea(5,20);
        wlistParamInput.setMaximumSize(wlistParamInput.getPreferredSize());
        wlistParamInput.setLineWrap(true);
        subPanel1.add(new JLabel("Whitelist param name to add: "));
        subPanel1.add(wlistParamInput);


        JPanel subPanel2 = UIUtil.GetYJPanel();
        wlistParamDisplay = new JTextArea(5,20);
        wlistParamDisplay.setMaximumSize(wlistParamDisplay.getPreferredSize());
        wlistParamDisplay.setLineWrap(true);
        wlistParamDisplay.setEditable(false);
        wlistParamDisplayscroll= new JScrollPane(wlistParamDisplay);
        subPanel2.add(new JLabel("Current whitelist param names: "));
        subPanel2.add(wlistParamDisplayscroll);

        JPanel subPanel3 = UIUtil.GetXJPanel();
        JButton addBtn = new JButton("Add");
        addBtn.addActionListener(e -> {
            burp.utils.Cache.addWhiteList( wlistParamInput.getText());
            wlistParamInput.setText("");
        });
        addBtn.setMargin(buttonMargin);
        JButton displayBtn = new JButton("Display");
        displayBtn.addActionListener(e -> {
            String text = String.join(System.lineSeparator(),Cache.PARAMNAME_WHITELIST);
            wlistParamDisplay.setText(text);
        });
        displayBtn.setMargin(buttonMargin);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            Cache.PARAMNAME_WHITELIST.clear();
            wlistParamDisplay.setText("");
        });
        displayBtn.setMargin(buttonMargin);
        subPanel3.add(addBtn);
        subPanel3.add(displayBtn);
        subPanel3.add(clearBtn);


        panel1.add(subPanel1);
        panel1.add(subPanel2);
        panel1.add(subPanel3);
        return panel1;
    }

}
