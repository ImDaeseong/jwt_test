package com.daeseong.jwt_android


import android.util.Log
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.util.*
import android.util.Base64

class HS256 {

    private val tag = HS256::class.java.simpleName

    private val sPWD = "password1234567890"

    fun createToken(iss: String?, exp: Long?, http: Boolean?, userId: String?, userName: String?): String {
        var token = ""

        try {
            val header: MutableMap<String, Any> = HashMap()
            header["alg"] = "HS256"
            header["typ"] = "JWT"
            token = JWT.create().withHeader(header)
                .withClaim("iss", iss)
                .withClaim("exp", exp)
                .withClaim("https://daeseong.com/jwt", http)
                .withClaim("userId", userId)
                .withClaim("userName", userName)
                .sign(Algorithm.HMAC256(sPWD))
        } catch (ex: Exception) {
            ex.message.toString()
        }
        return token
    }

    private fun split(sToken: String): Array<String?> {
        val result = arrayOfNulls<String>(3)
        val split = sToken.split("\\.").toTypedArray()
        result[0] = split[0]
        result[1] = split[1]
        result[2] = split[2]
        return result
    }

    fun readToken(sToken: String?) {

        try {

            val jwt = JWT.decode(sToken)
            Log.e(tag, "jwt.getToken():" + jwt.token)
            Log.e(tag, "jwt.getHeader():" + jwt.header)
            Log.e(tag, "jwt.getAlgorithm():" + jwt.algorithm)
            Log.e(tag, "jwt.getPayload():" + jwt.payload)
            Log.e(tag, "jwt.getSignature():" + jwt.signature)

            val split = split(jwt.token)
            Log.e(tag, "split1:" + split[0])
            Log.e(tag, "split2:" + split[1])
            Log.e(tag, "split3:" + split[2])

            val claim1 = jwt.getClaim("iss")
            val claim2 = jwt.getClaim("exp")
            val claim3 = jwt.getClaim("https://daeseong.com/jwt")
            val claim4 = jwt.getClaim("userId")
            val claim5 = jwt.getClaim("userName")

            Log.e(tag, "iss:" + claim1.asString())
            Log.e(tag, "exp:" + claim2.asLong())
            Log.e(tag, "https://daeseong.com/jwt:" + claim3.asBoolean())
            Log.e(tag, "userId:" + claim4.asString())
            Log.e(tag, "userName:" + claim5.asString())

        } catch (e: Exception) {
            e.message.toString()
        }
    }

    fun getAlgorithm(sToken: String?): String {
        var Algorithm = ""
        try {
            val jwt = JWT.decode(sToken)
            Algorithm = jwt.algorithm
        } catch (e: Exception) {
            e.message.toString()
        }
        return Algorithm
    }

    fun getHeader(sToken: String?): String {
        var Header = ""
        try {
            val jwt = JWT.decode(sToken)
            Header = String(Base64.decode(jwt.header, Base64.URL_SAFE))
        } catch (e: Exception) {
            e.message.toString()
        }
        return Header
    }

    fun getPayload(sToken: String?): String {
        var payload = ""
        try {
            val jwt = JWT.decode(sToken)
            payload = String(Base64.decode(jwt.payload, Base64.URL_SAFE))
        } catch (e: Exception) {
            e.message.toString()
        }
        return payload
    }

    fun getSignature(sToken: String?): String {
        var signature = ""
        try {
            val jwt = JWT.decode(sToken)
            signature = jwt.signature
        } catch (e: Exception) {
            e.message.toString()
        }
        return signature
    }
}