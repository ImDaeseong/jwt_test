package com.daeseong.jwt_android


import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException


class MainActivity : AppCompatActivity() {

    private val tag = MainActivity::class.java.simpleName

    private var button1: Button? = null
    private var button2:Button? = null

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        button1 = findViewById(R.id.button1)
        button1!!.setOnClickListener { //token create

            val obj = HS256()
            val token: String = obj.createToken("daeseong.com", "14852700000".toLong(), true, "userId1234567890", "daeseong")
            Log.e(tag, "createToken token:$token")

            //token read
            obj.readToken(token)

            //verify token
            val Algorithm: String = obj.getAlgorithm(token)
            val Header: String = obj.getHeader(token)
            val Payload: String = obj.getPayload(token)
            val Signature: String = obj.getSignature(token)
            Log.e(tag, "Algorithm:$Algorithm")
            Log.e(tag, "Header:$Header")
            Log.e(tag, "Payload:$Payload")
            Log.e(tag, "Signature:$Signature")
        }

        button2 = findViewById(R.id.button2)
        button2!!.setOnClickListener { 
          
           //token create
            val obj = RSA()
            val token: String = obj.createToken("daeseong.com", "14852700000".toLong(), true, "userId1234567890", "daeseong")
            Log.e(tag, "createToken token:$token")

            //verify token
            try {
                val Header: String = obj.getHeader(token)
                val Payload: String = obj.getPayload(token)
                Log.e(tag, "Header:$Header")
                Log.e(tag, "Payload:$Payload")
                obj.verifyToken(token)

            } catch (e: InvalidKeySpecException) {
                e.printStackTrace()
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            }
        }
    }
}
