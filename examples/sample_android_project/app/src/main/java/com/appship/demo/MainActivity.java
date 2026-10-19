package com.appship.demo;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView message = new TextView(this);
        message.setText(AppMessage.welcome());
        message.setTextSize(22);
        message.setGravity(Gravity.CENTER);
        message.setPadding(24, 24, 24, 24);
        setContentView(message);
    }
}
