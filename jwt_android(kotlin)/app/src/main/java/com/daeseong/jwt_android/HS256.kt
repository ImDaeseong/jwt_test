package com.daeseong.jwt_android

import android.util.Base64
import android.util.Log
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm

class HS256 {

    private val tag = HS256::class.java.simpleName
    private val sPWD = "password1234567890"

    fun createToken(iss: String?, exp: Long?, http: Boolean?, userId: String?, userName: String?): String {
        return try {
            val header: Map<String, Any> = mapOf("alg" to "HS256", "typ" to "JWT")
            JWT.create().withHeader(header)
                .withClaim("iss", iss)
                .withClaim("exp", exp)
                .withClaim("https://daeseong.com/jwt", http)
                .withClaim("userId", userId)
                .withClaim("userName", userName)
                .sign(Algorithm.HMAC256(sPWD))
        } catch (ex: Exception) {
            Log.e(tag, ex.message.toString())
            ""
        }
    }

    private fun split(sToken: String): Array<String?> {
        return sToken.split("\\.").toTypedArray()
    }

    fun readToken(sToken: String?) {
        try {
            val jwt = JWT.decode(sToken)
            Log.e(tag, "jwt.getToken(): ${jwt.token}")
            Log.e(tag, "jwt.getHeader(): ${jwt.header}")
            Log.e(tag, "jwt.getAlgorithm(): ${jwt.algorithm}")
            Log.e(tag, "jwt.getPayload(): ${jwt.payload}")
            Log.e(tag, "jwt.getSignature(): ${jwt.signature}")

            val split = split(jwt.token)
            Log.e(tag, "split1: ${split[0]}")
            Log.e(tag, "split2: ${split[1]}")
            Log.e(tag, "split3: ${split[2]}")

            val claim1 = jwt.getClaim("iss")
            val claim2 = jwt.getClaim("exp")
            val claim3 = jwt.getClaim("https://daeseong.com/jwt")
            val claim4 = jwt.getClaim("userId")
            val claim5 = jwt.getClaim("userName")

            Log.e(tag, "iss: ${claim1.asString()}")
            Log.e(tag, "exp: ${claim2.asLong()}")
            Log.e(tag, "https://daeseong.com/jwt: ${claim3.asBoolean()}")
            Log.e(tag, "userId: ${claim4.asString()}")
            Log.e(tag, "userName: ${claim5.asString()}")

        } catch (e: Exception) {
            Log.e(tag, e.message.toString())
        }
    }

    fun getAlgorithm(sToken: String?): String {
        return try {
            val jwt = JWT.decode(sToken)
            jwt.algorithm
        } catch (e: Exception) {
            Log.e(tag, e.message.toString())
            ""
        }
    }

    fun getHeader(sToken: String?): String {
        return try {
            val jwt = JWT.decode(sToken)
            String(Base64.decode(jwt.header, Base64.URL_SAFE))
        } catch (e: Exception) {
            Log.e(tag, e.message.toString())
            ""
        }
    }

    fun getPayload(sToken: String?): String {
        return try {
            val jwt = JWT.decode(sToken)
            String(Base64.decode(jwt.payload, Base64.URL_SAFE))
        } catch (e: Exception) {
            Log.e(tag, e.message.toString())
            ""
        }
    }

    fun getSignature(sToken: String?): String {
        return try {
            val jwt = JWT.decode(sToken)
            jwt.signature
        } catch (e: Exception) {
            Log.e(tag, e.message.toString())
            ""
        }
    }
}
