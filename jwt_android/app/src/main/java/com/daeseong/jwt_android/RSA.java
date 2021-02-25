package com.daeseong.jwt_android;

import android.os.Build;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSA {

    private static final String TAG = RSA.class.getSimpleName();

    private String sPWD = "password1234567890";

    public String createToken(String iss, Integer exp, Boolean http, String userId, String userName) {

        String token = "";

        try {
            Map<String, Object> header = new HashMap<String, Object>();
            header.put("alg", "RS256");
            header.put("typ", "JWT");

            String sPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDhoSEmtkEwSte0\n" +
                    "anFLDG/dM3i1MCSVtzJJTIgcfuOCB75pme/WOnDvDZkBkdoSclgpSPuDdH2EPVb4\n" +
                    "NKpDsIDBhu8rMt8RqR+TMITYmsxMO+IAo/pmDFA7SQ1VQNiAQhJAqTB667lpfqcn\n" +
                    "XvHbukYPrZWnNEn3l1WUdcCSYwJqIlAZfHNZnvBTpHrG8Y1bjv65kkVLIrzPhgl6\n" +
                    "piLzgOvmL5bTcXWZ2KtjCoRZfKhCbv4OVCWmUFfM+Zk9oe3DD8GXUKOIUQX2LD4l\n" +
                    "wp0gXj7+UUVnWkKaoMzUHRA060kNMO5ijS45XJuR6iHEXCcgF616oXm88WbLvBla\n" +
                    "oAdJ07hlAgMBAAECggEBAIWsO4K+2XIt9QuLQGGxFZkchHf79MDKTz2D3OPc/Rat\n" +
                    "Vc8khyYJa50FFlAKxALHwZl8Bp6D5lTxLlRQh0shB7cgJRQXyHajFvTR+vKFC2Ji\n" +
                    "2+t7Or84rlPhXMfUai/adQvf8Lvyad+pTIiTxIBkJFvngFEWNng8LVSOSq+vft+3\n" +
                    "Jaqf/HEfz9hw8MDXYDW94JS+fhRVbgbBBEUBjK0F45WSO0e6cNcuCmDm7kr73v6W\n" +
                    "ZORVda/sHPVaD5VPze5mhk/qNs4H2q3+qqsIULp+Ffx4MEi8xj+qp24PQfGrv/k+\n" +
                    "Pg3YPpCRpe6YD/zhKuCPjXtwoTj6FQpSFoM27oKPYSECgYEA8kmUNPlygT7e0zDR\n" +
                    "SqeNYN8dvxQ7mp03yI/gUlRDo8RYTWNNXnwl1OovVYnVmiBQp+CpYSPNvqWWm6Y1\n" +
                    "/6LmKuliVVVHchi2nhCMSY7fK93U2Kas4ISuA5xoG0LM6fNgqbSdR5L9cwb488oO\n" +
                    "xIwYBlOexcRcXkRz6ClsE8oCLWkCgYEA7mYyxJHEXwtgwwyWf68sPZEJqRFsQ53y\n" +
                    "zAy/20yqyWX8BPdkZ5jRJnuXI2D7atHPFocpsjDiw1d1a1/5vrR1AwZpAMJEWkXt\n" +
                    "xzW0UFGv6kOlsAgb94cXReFFJZJ77vfAOYXeCyHS/l69hgGFXu1csQC99NUYQQmS\n" +
                    "hSSxQnVAB50CgYBSw4WoDunpcoOFWvCzcsbdp3mu0weFSl1K2rMDDJvKboDHdrtw\n" +
                    "IjJ+J70hmCLqMk26+wiBEUzv6fqnksBxYcEEOZMImUf9lqmTFw4E9pQPlQhnNZBq\n" +
                    "ZYhX3W7GmSwMYsHLVtI/J9wCFgimpogi5cQzLQ9YeTogTXvWe4favq+9uQKBgASV\n" +
                    "WmyFEO1y3o1hdJNH3uXgH/tsJlS2eLCLnjStKKtuloXR69BCE+NVhPZdKvhGyGB6\n" +
                    "gMa4QePXjp5d3gNYnNdODD7DfWTu6z9lPO4+Y89xNYJI5aDArCXfyuCKDG/vu3Zf\n" +
                    "qIE2SUQythoZdWL51Uph5UULw8ecU4DTz8SjVHPRAoGBAKxI4ngJwybnLVgK7eKs\n" +
                    "DDptIfIuvstZi2Ji+S/dEJPGqAJrfpNmkVIumDJcgQzRo3sFH0NwG0HftPQh43xA\n" +
                    "zbT8ck23rwZmLxsgC+Xw22j8WNmBFDSmkW6ymkdu1zqneV1IVfkPhHtw/i2Sa77P\n" +
                    "Q6M3HKUQantoFFRXXECVH4Up\n" +
                    "-----END PRIVATE KEY-----";
            sPrivateKey = sPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "");
            sPrivateKey = sPrivateKey.replace("-----END PRIVATE KEY-----", "");
            sPrivateKey = sPrivateKey.replaceAll("\\s+", "");
            //Log.e(TAG, "sPrivateKey:" + sPrivateKey);

            PrivateKey PrivKey = null;
            PublicKey publicKey = null;

            Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) PrivKey);
            //Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);

            token = JWT.create()
                    .withHeader(header)
                    .withClaim("iss", iss)
                    .withClaim("exp", exp)
                    .withClaim("https://daeseong.com/jwt", http)
                    .withClaim("userId", userId)
                    .withClaim("userName", userName)
                    .sign(algorithm);

        }catch (Exception ex){
            ex.getMessage().toString();
        }
        return token;
    }



}
