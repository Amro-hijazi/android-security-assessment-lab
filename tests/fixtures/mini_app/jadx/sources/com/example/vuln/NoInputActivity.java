package com.example.vuln;

public class NoInputActivity extends Activity {
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.d("Admin", "token=" + this.token);
    }
}
