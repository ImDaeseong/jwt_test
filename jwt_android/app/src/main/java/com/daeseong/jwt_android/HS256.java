package com.daeseong.jwt_android;

import android.util.Base64;
import android.util.Log;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.util.HashMap;
import java.util.Map;

public class HS256 {

    private static final String TAG = HS256.class.getSimpleName();

    private String sPWD = "password1234567890";

    public String createToken(String iss, Long exp, Boolean http, String userId, String userName) {

        String token = "";

        try {
            Map<String, Object> header = new HashMap<String, Object>();
            header.put("alg", "HS256");
            header.put("typ", "JWT");

            token = JWT.create().withHeader(header)
                    .withClaim("iss", iss)
                    .withClaim("exp", exp)
                    .withClaim("https://daeseong.com/jwt", http)
                    .withClaim("userId", userId)
                    .withClaim("userName", userName)
                    .sign(Algorithm.HMAC256(sPWD));
        }catch (Exception ex){
            ex.getMessage().toString();
        }
        return token;
    }

    private String[] split(String sToken) {
        String[] result = new String[3];
        String[] split = sToken.split("\\.");
        result[0] = split[0];
        result[1] = split[1];
        result[2] = split[2];
        return result;
    }

    public void readToken(String sToken) {

        try {

            DecodedJWT jwt = JWT.decode(sToken);

            Log.e(TAG, "jwt.getToken():" + jwt.getToken());
            Log.e(TAG, "jwt.getHeader():" + jwt.getHeader());
            Log.e(TAG, "jwt.getAlgorithm():" + jwt.getAlgorithm());
            Log.e(TAG, "jwt.getPayload():" + jwt.getPayload());
            Log.e(TAG, "jwt.getSignature():" + jwt.getSignature());

            String[] split = split(jwt.getToken());
            Log.e(TAG, "split1:" + split[0]);
            Log.e(TAG, "split2:" + split[1]);
            Log.e(TAG, "split3:" + split[2]);

            Claim claim1 = jwt.getClaim("iss");
            Claim claim2 = jwt.getClaim("exp");
            Claim claim3 = jwt.getClaim("https://daeseong.com/jwt");
            Claim claim4 = jwt.getClaim("userId");
            Claim claim5 = jwt.getClaim("userName");
            Log.e(TAG, "iss:" + claim1.asString());
            Log.e(TAG, "exp:" + claim2.asLong());
            Log.e(TAG, "https://daeseong.com/jwt:" + claim3.asBoolean());
            Log.e(TAG, "userId:" + claim4.asString());
            Log.e(TAG, "userName:" + claim5.asString());

        }catch (Exception e){
            e.getMessage().toString();
        }
    }

    public String getAlgorithm(String sToken) {

        String Algorithm = "";
        try {
            DecodedJWT jwt=JWT.decode(sToken);
            Algorithm = jwt.getAlgorithm();
        }catch (Exception e){
            e.getMessage().toString();
        }
        return Algorithm;
    }

    public String getHeader(String sToken) {

        String Header = "";
        try {
            DecodedJWT jwt=JWT.decode(sToken);
            Header = new String(Base64.decode(jwt.getHeader(), Base64.URL_SAFE));
        }catch (Exception e){
            e.getMessage().toString();
        }
        return Header;
    }

    public String getPayload(String sToken) {

        String payload = "";
        try {
            DecodedJWT jwt = JWT.decode(sToken);
            payload = new String(Base64.decode(jwt.getPayload(), Base64.URL_SAFE));
        }catch (Exception e){
            e.getMessage().toString();
        }
        return payload;
    }

    public String getSignature(String sToken) {

        String signature = "";
        try {
            DecodedJWT jwt = JWT.decode(sToken);
            signature = jwt.getSignature();
        }catch (Exception e){
            e.getMessage().toString();
        }
        return signature;
    }
}
