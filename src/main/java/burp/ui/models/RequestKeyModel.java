package burp.ui.models;

import burp.utils.Cache;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class RequestKeyModel extends AbstractTableModel {

    private ArrayList<String> keys;
    private ArrayList<Boolean> bools;


    public RequestKeyModel(HashMap<String, Boolean> data) {
        this.keys = new ArrayList<String>();
        this.bools = new ArrayList<Boolean>();
        int i = 0;
        for (Map.Entry<String, Boolean> entry : data.entrySet()) {
            this.keys.add(entry.getKey());
            this.bools.add(entry.getValue());
        }
    }

    @Override
    public String getColumnName(int col) {
        if (col == 0) {
            return "KeyofRequest";
        } else {
            return "Finished";
        }
    }


    @Override
    public int getColumnCount() {
        return 2;
    }


    @Override
    public int getRowCount() {
        return keys.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        if (col == 0) {
            return keys.get(row);
        } else {
            return bools.get(row);
        }
    }

    @Override
    public void setValueAt(Object aValue, int row, int col) {
        if (col == 0) {
            keys.set(row, (String) aValue);
        } else {
            bools.set(row, (Boolean) aValue);

        }
    }

    public void addRow(String keyOfRequest) {
        if ( !keys.contains(keyOfRequest)){
            keys.add(keyOfRequest);
            bools.add(false);
            fireTableRowsInserted(this.getRowCount() - 1, this.getRowCount() - 1);

        }
    }


    public void deleteRow(int row) {
        String keyToDelete = (String) this.getValueAt(row, 0);
        keys.remove(row);
        bools.remove(row);
        Cache.KEY_OF_REQUESTS.remove(keyToDelete);
        fireTableRowsDeleted(row, row);
    }

    public void updateBooleanRow(String key) {
        int row = keys.indexOf(key);
        bools.set(row, true);
        fireTableCellUpdated(row, 1);
    }

}
