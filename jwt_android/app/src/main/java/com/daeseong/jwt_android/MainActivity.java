package com.daeseong.jwt_android;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import java.security.NoSuchAlgorithmException;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private Button button1, button2;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        button1 = findViewById(R.id.button1);
        button1.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                //token create
                HS256 obj = new HS256();
                String token = obj.createToken("daeseong.com", Long.parseLong("14852700000"), true, "userId1234567890", "daeseong");
                Log.e(TAG, "createToken token:" + token);

                //token read
                obj.readToken(token);

                //verify token
                String Algorithm = obj.getAlgorithm(token);
                String Header = obj.getHeader(token);
                String Payload = obj.getPayload(token);
                String Signature = obj.getSignature(token);
                Log.e(TAG, "Algorithm:" + Algorithm);
                Log.e(TAG, "Header:" + Header);
                Log.e(TAG, "Payload:" + Payload);
                Log.e(TAG, "Signature:" + Signature);

            }
        });

        button2 = findViewById(R.id.button2);
        button2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                //token create
                RSA obj = new RSA();
                String token = obj.createToken("daeseong.com", 148527, true, "userId1234567890", "daeseong");
                Log.e(TAG, "createToken token:" + token);



            }
        });

    }
}
