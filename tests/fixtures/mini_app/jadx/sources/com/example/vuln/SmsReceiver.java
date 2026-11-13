package com.example.vuln;

public class SmsReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        String phone = intent.getStringExtra("phone");
        Log.i("Sms", "sending pin to " + phone + " pin=" + this.pin);
        SmsManager.getDefault().sendTextMessage(phone, null, "x", null, null);
    }
}
