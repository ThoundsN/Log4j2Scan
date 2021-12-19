package burp.ui.tabs;

import burp.BurpExtender;
import burp.ui.models.RequestKeyModel;
import burp.utils.Cache;
import burp.utils.UIUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class CacheUIHandler {
    private  BurpExtender parent;
    private JPanel mainPanel;
    private JTextArea wlistParamInput;
    private JTextArea wlistParamDisplay;
    private JScrollPane wlistParamDisplayscroll;
    public RequestKeyModel model;
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
        cachePanel.add("Scanned Requests ",getScannedRequestsPanel());
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


        JPanel subPanel2 = UIUtil.GetXJPanel();
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

    private JPanel getScannedRequestsPanel(){
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        this.model = new RequestKeyModel(Cache.KEY_OF_REQUESTS);
        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);

        JScrollPane tableScrollPane = new JScrollPane(table);
        tableScrollPane.setPreferredSize(new Dimension(250, 200));


        JButton button = new JButton("delete");
        button.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                // check for selected row first
                if (table.getSelectedRow() != -1) {
                    // remove selected row from the model
                    model.deleteRow(table.convertRowIndexToModel(table.getSelectedRow()));
                }
                System.out.println("keys:  " +Cache.KEY_OF_REQUESTS.toString());
            }
        });

        panel1.add(tableScrollPane);
        panel1.add(button);



        return panel1;
    }

}


