package burp.ui.tabs;

import burp.BurpExtender;
import burp.poc.IPOC;
import burp.utils.CheckBoxListItem;
import burp.utils.Config;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.intellij.lang.annotations.JdkConstants;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class POCUIHandler {

    private BurpExtender parent;
    private JPanel mainPanel;
    private Integer[] pocRange = new Integer[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,14, 15,16, 17};
//    public static final Integer[] defaultEnabledPocIds = new Integer[]{1, 3,  17};
    public static final Integer[] defaultEnabledPocIds = new Integer[]{17};
    private JList pocList;
    Map<Integer, IPOC> allPocs;

    public POCUIHandler(BurpExtender parent) {
        this.parent = parent;
    }

    public JPanel getPanel() {
        mainPanel = new JPanel();
        mainPanel.setAlignmentX(0.0f);
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setLayout(new BoxLayout(mainPanel, 1));

        allPocs = Utils.getPOCs(pocRange);
        JScrollPane scrollPane = new JScrollPane();
        mainPanel.add(scrollPane);

        pocList = new JList(){

            private boolean processEvent(MouseEvent e) {
                int index = pocList.locationToIndex(e.getPoint());
                return index > -1 && pocList.getCellBounds(index, index).contains(e.getPoint());
            }

            @Override
            protected void processMouseEvent(MouseEvent e) {
                if (processEvent(e)) {
                    super.processMouseEvent(e);
                }
            }

            @Override
            protected void processMouseMotionEvent(MouseEvent e) {
                if (processEvent(e)) {
                    super.processMouseMotionEvent(e);
                }
            }
        };
        scrollPane.setViewportView(pocList);
        pocList.setSelectionModel(new DefaultListSelectionModel() {
            @Override
            public void setSelectionInterval(int index0, int index1) {
                if (super.isSelectedIndex(index0)) {
                    super.removeSelectionInterval(index0, index1);
                } else {
                    super.addSelectionInterval(index0, index1);
                }
            }
        });
        pocList.setListData(allPocs.entrySet().toArray());
        CheckBoxListItem cboxItem = new CheckBoxListItem();
        pocList.setCellRenderer(cboxItem);

        JPanel panel1 = new JPanel();
        JButton applyBtn = new JButton("Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.setBackground(Color.cyan);
        applyBtn.addActionListener(e -> {
            List<Map.Entry<Integer, IPOC>> ava_pocs = (List<Map.Entry<Integer, IPOC>>) pocList.getSelectedValuesList();
            JSONArray pocIds = new JSONArray();
            for (Map.Entry<Integer, IPOC> poc : ava_pocs) {
                pocIds.add(poc.getKey());
                parent.stdout.println("Enabled poc id: " + poc.getKey());
            }
            Config.set(Config.ENABLED_POC_IDS, pocIds.toJSONString());
            this.loadConfig();
            this.apply();
        });
        panel1.add(applyBtn);
        panel1.setMaximumSize(panel1.getPreferredSize());
        mainPanel.add(panel1);
        this.loadConfig();
        return mainPanel;
    }

    private void apply() {
        parent.reloadScanner();
        if (parent.scanner.getState()) {
            JOptionPane.showMessageDialog(mainPanel, "Apply success!");
        } else {
            JOptionPane.showMessageDialog(mainPanel, "Apply failed, please go to plug-in log see detail!");
        }
    }

    private void loadConfig() {
        JSONArray enabled_poc_ids = JSONArray.parseArray(Config.get(Config.ENABLED_POC_IDS, JSONObject.toJSONString(defaultEnabledPocIds)));
        pocList.setListData(allPocs.entrySet().toArray());
        for (Object id : enabled_poc_ids) {
            pocList.setSelectedIndex((int) id - 1);
        }
    }
}