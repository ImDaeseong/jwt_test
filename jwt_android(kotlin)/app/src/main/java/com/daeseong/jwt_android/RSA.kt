package com.daeseong.jwt_android

import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec


@RequiresApi(api = Build.VERSION_CODES.O)
class RSA {

    private val tag = RSA::class.java.simpleName

    private val sPWD = "password1234567890"

    fun createToken(iss: String?, exp: Long?, http: Boolean?, userId: String?, userName: String?): String {

        var token = ""

        try {

            val header: MutableMap<String, Any> = HashMap()
            header["alg"] = "RS256"
            header["typ"] = "JWT"

            val privKey  = rsaPrivateKey()
            //val publicKey = rsaPublicKey()

            token = JWT.create()
                .withHeader(header)
                .withClaim("iss", iss)
                .withClaim("exp", exp)
                .withClaim("https://daeseong.com/jwt", http)
                .withClaim("userId", userId)
                .withClaim("userName", userName)
                .sign(Algorithm.RSA256(privKey))

        } catch (ex: Exception) {
            ex.message.toString()
        }
        return token
    }

    @Throws(InvalidKeySpecException::class, NoSuchAlgorithmException::class)
    fun verifyToken(token: String?): Boolean {

        try {

            val publicKey = rsaPublicKey()
            val algorithm = Algorithm.RSA256(publicKey, null)
            val verifier = JWT.require(algorithm).build()
            val jwt = verifier.verify(token)

            val iss = jwt.getClaim("iss").asString()
            val exp = jwt.getClaim("exp").asLong()
            val bsite = jwt.getClaim("https://daeseong.com/jwt").asBoolean()
            val userId = jwt.getClaim("userId").asString()
            val userName = jwt.getClaim("userName").asString()

            Log.e(tag, "iss:$iss")
            Log.e(tag, "exp:$exp")
            Log.e(tag, "https://daeseong.com/jwt:$bsite")
            Log.e(tag, "userId:$userId")
            Log.e(tag, "userName:$userName")

        } catch (exception: JWTVerificationException) {
            return false
        }
        return true
    }

    @Throws(InvalidKeySpecException::class, NoSuchAlgorithmException::class)
    fun getHeader(sToken: String?): String {

        var header = ""

        try {

            val publicKey = rsaPublicKey()
            val algorithm = Algorithm.RSA256(publicKey, null)
            val verifier = JWT.require(algorithm).build()
            val jwt = verifier.verify(sToken)
            header = String(Base64.decode(jwt.header, Base64.URL_SAFE))

        } catch (exception: JWTVerificationException) {
            Log.e(tag, "Error getting header", exception)
        }
        return header
    }

    @Throws(InvalidKeySpecException::class, NoSuchAlgorithmException::class)
    fun getPayload(sToken: String?): String {

        var payload = ""

        try {

            val publicKey = rsaPublicKey()
            val algorithm = Algorithm.RSA256(publicKey, null)
            val verifier = JWT.require(algorithm).build()
            val jwt = verifier.verify(sToken)

            payload = String(Base64.decode(jwt.payload, Base64.URL_SAFE))

        } catch (exception: JWTVerificationException) {
            Log.e(tag, "Error getting payload", exception)
        }
        return payload
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun rsaPublicKey(): RSAPublicKey {

        val keyString =  //"-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4aEhJrZBMErXtGpxSwxv" +
                    "3TN4tTAklbcySUyIHH7jgge+aZnv1jpw7w2ZAZHaEnJYKUj7g3R9hD1W+DSqQ7CA" +
                    "wYbvKzLfEakfkzCE2JrMTDviAKP6ZgxQO0kNVUDYgEISQKkweuu5aX6nJ17x27pG" +
                    "D62VpzRJ95dVlHXAkmMCaiJQGXxzWZ7wU6R6xvGNW47+uZJFSyK8z4YJeqYi84Dr" +
                    "5i+W03F1mdirYwqEWXyoQm7+DlQlplBXzPmZPaHtww/Bl1CjiFEF9iw+JcKdIF4+" +
                    "/lFFZ1pCmqDM1B0QNOtJDTDuYo0uOVybkeohxFwnIBeteqF5vPFmy7wZWqAHSdO4" +
                    "ZQIDAQAB"
        //"-----END PUBLIC KEY-----";

        val decodedKey = Base64.decode(keyString, Base64.DEFAULT)
        val ks = X509EncodedKeySpec(decodedKey)//decoder.decode(keyString))
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(ks) as RSAPublicKey
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun rsaPrivateKey(): RSAPrivateKey {

        val keyString =  //"-----BEGIN PRIVATE KEY-----\n" +
            ("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDhoSEmtkEwSte0" +
                    "anFLDG/dM3i1MCSVtzJJTIgcfuOCB75pme/WOnDvDZkBkdoSclgpSPuDdH2EPVb4" +
                    "NKpDsIDBhu8rMt8RqR+TMITYmsxMO+IAo/pmDFA7SQ1VQNiAQhJAqTB667lpfqcn" +
                    "XvHbukYPrZWnNEn3l1WUdcCSYwJqIlAZfHNZnvBTpHrG8Y1bjv65kkVLIrzPhgl6" +
                    "piLzgOvmL5bTcXWZ2KtjCoRZfKhCbv4OVCWmUFfM+Zk9oe3DD8GXUKOIUQX2LD4l" +
                    "wp0gXj7+UUVnWkKaoMzUHRA060kNMO5ijS45XJuR6iHEXCcgF616oXm88WbLvBla" +
                    "oAdJ07hlAgMBAAECggEBAIWsO4K+2XIt9QuLQGGxFZkchHf79MDKTz2D3OPc/Rat" +
                    "Vc8khyYJa50FFlAKxALHwZl8Bp6D5lTxLlRQh0shB7cgJRQXyHajFvTR+vKFC2Ji" +
                    "2+t7Or84rlPhXMfUai/adQvf8Lvyad+pTIiTxIBkJFvngFEWNng8LVSOSq+vft+3" +
                    "Jaqf/HEfz9hw8MDXYDW94JS+fhRVbgbBBEUBjK0F45WSO0e6cNcuCmDm7kr73v6W" +
                    "ZORVda/sHPVaD5VPze5mhk/qNs4H2q3+qqsIULp+Ffx4MEi8xj+qp24PQfGrv/k+" +
                    "Pg3YPpCRpe6YD/zhKuCPjXtwoTj6FQpSFoM27oKPYSECgYEA8kmUNPlygT7e0zDR" +
                    "SqeNYN8dvxQ7mp03yI/gUlRDo8RYTWNNXnwl1OovVYnVmiBQp+CpYSPNvqWWm6Y1" +
                    "/6LmKuliVVVHchi2nhCMSY7fK93U2Kas4ISuA5xoG0LM6fNgqbSdR5L9cwb488oO" +
                    "xIwYBlOexcRcXkRz6ClsE8oCLWkCgYEA7mYyxJHEXwtgwwyWf68sPZEJqRFsQ53y" +
                    "zAy/20yqyWX8BPdkZ5jRJnuXI2D7atHPFocpsjDiw1d1a1/5vrR1AwZpAMJEWkXt" +
                    "xzW0UFGv6kOlsAgb94cXReFFJZJ77vfAOYXeCyHS/l69hgGFXu1csQC99NUYQQmS" +
                    "hSSxQnVAB50CgYBSw4WoDunpcoOFWvCzcsbdp3mu0weFSl1K2rMDDJvKboDHdrtw" +
                    "IjJ+J70hmCLqMk26+wiBEUzv6fqnksBxYcEEOZMImUf9lqmTFw4E9pQPlQhnNZBq" +
                    "ZYhX3W7GmSwMYsHLVtI/J9wCFgimpogi5cQzLQ9YeTogTXvWe4favq+9uQKBgASV" +
                    "WmyFEO1y3o1hdJNH3uXgH/tsJlS2eLCLnjStKKtuloXR69BCE+NVhPZdKvhGyGB6" +
                    "gMa4QePXjp5d3gNYnNdODD7DfWTu6z9lPO4+Y89xNYJI5aDArCXfyuCKDG/vu3Zf" +
                    "qIE2SUQythoZdWL51Uph5UULw8ecU4DTz8SjVHPRAoGBAKxI4ngJwybnLVgK7eKs" +
                    "DDptIfIuvstZi2Ji+S/dEJPGqAJrfpNmkVIumDJcgQzRo3sFH0NwG0HftPQh43xA" +
                    "zbT8ck23rwZmLxsgC+Xw22j8WNmBFDSmkW6ymkdu1zqneV1IVfkPhHtw/i2Sa77P" +
                    "Q6M3HKUQantoFFRXXECVH4Up")
        //"-----END PRIVATE KEY-----\n";

        val decodedKey = Base64.decode(keyString, Base64.DEFAULT)
        val ks = PKCS8EncodedKeySpec(decodedKey)//decoder.decode(keyString))
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(ks) as RSAPrivateKey
    }

}