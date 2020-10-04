package com.webmah.sensorhealthcare

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.android.synthetic.main.activity_sensordatatogatewayandconfirm.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection


class SensorDataToGatewayAndConfirm : AppCompatActivity() {

    private lateinit var signatureResult: String
    private lateinit var enMessage: String
    private val TAG = "SMHEC"
    private val iv = "123456789abcdefh".toByteArray()
    private lateinit var clientPrivateKey: PrivateKey
    private lateinit var clientPublicKey: PublicKey
    private lateinit var clientAES: SecretKey
    private lateinit var serverResponse: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sensordatatogatewayandconfirm)

        val SENDPATIENTPROBLEM = intent.getStringExtra("SENDPATIENTDATA")
        p_data.text = "Patient Readings: $SENDPATIENTPROBLEM"

        checkNetworkConnection()

        if (checkKeysExists()) {
            encryptAndSignAndSend()
        }

    }

    private fun checkNetworkConnection(): Boolean {
        val connMgr = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val networkInfo = connMgr.activeNetworkInfo
        val isConnected: Boolean = if(networkInfo != null) networkInfo.isConnected() else false
        if (networkInfo != null && isConnected) {
            // show "Connected" & type of network "WIFI or MOBILE"
            howIsConnected.text = "Connected " + networkInfo.typeName
        } else {
            // show "Not Connected"
            howIsConnected.text = "Not Connected"
        }
        return isConnected
    }

    private fun checkKeysExists(): Boolean {
        val sharedPreference =  getSharedPreferences(SHAREDLOCATION, Context.MODE_PRIVATE)
        if(sharedPreference.contains("clientPrivateKey") && sharedPreference.contains("clientPublicKey") && sharedPreference.contains("clientAES")){
            // decode the base64 encoded string
            val seck = sharedPreference.getString("clientAES", "no")
            if(seck == "no")
            {
                return false
            }
            System.out.println(seck)
            val secKey: ByteArray = Base64.decode(seck, Base64.DEFAULT)
            clientAES = SecretKeySpec(secKey, 0, secKey.size, "AES")

            // decode the base64 encoded string
            val pukey: ByteArray = Base64.decode(sharedPreference.getString("clientPublicKey", "no"), Base64.DEFAULT)
            val keySpec = X509EncodedKeySpec(pukey)
            val keyFactory = KeyFactory.getInstance("EC")
            clientPublicKey = keyFactory.generatePublic(keySpec)

            val prkey: ByteArray = Base64.decode(sharedPreference.getString("clientPrivateKey", "no"), Base64.DEFAULT)
            val keySpec1 = PKCS8EncodedKeySpec(prkey)
            val keyFactory1 = KeyFactory.getInstance("EC")
            clientPrivateKey = keyFactory1.generatePrivate(keySpec1)

            return true
        }
        return false
    }

    private fun encryptAndSignAndSend() {

        val pdata = p_data.text.toString()
        //encryption
        serverResponse = "no"
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val parameterSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, clientAES, parameterSpec)
        val bytes = cipher.doFinal(pdata.toByteArray())
        val clientENPdata = Base64.encodeToString(bytes, Base64.DEFAULT)
        pdata_encrypted.text = "Encrypted Patient Readings: $clientENPdata"
        val ivs = Base64.encodeToString(iv, Base64.DEFAULT)

        //sign

        //We sign the data with the private key. We use ECDAS algorithm along SHA-256 digest algorithm
        val signature: ByteArray? = Signature.getInstance("SHA256withECDSA").run {
            initSign(clientPrivateKey)
            update(pdata.toByteArray())
            sign()
        }

        if (signature != null) {
            //We encode and store in a variable the value of the signature
            signatureResult = Base64.encodeToString(signature, Base64.DEFAULT)
            pdata_signature.text = "Patient Readings Digital Signature: \r\n $signatureResult"
        }

        if (checkNetworkConnection()) {
            val jsonObject = JSONObject()
            jsonObject.accumulate("iv", ivs)
            jsonObject.accumulate("clientENPdata", clientENPdata)
            jsonObject.accumulate("clientSignature", signatureResult)
            lifecycleScope.launch {
                val result = httpPost("https://webmah.com/sensorhealthcare/ConfirmSensorHealthCareContact.php", jsonObject)
                server_msg.text = serverResponse
            }
        }
        else
            Toast.makeText(this, "Not Connected!", Toast.LENGTH_SHORT).show()

    }

    @Throws(IOException::class, JSONException::class)
    private suspend fun httpPost(myUrl: String, jsonObject: JSONObject): String {

        val result = withContext(Dispatchers.IO) {
            val url = URL(myUrl)
            // 1. create HttpURLConnection
            val conn = url.openConnection() as HttpsURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")

            // 2. build JSON object
            //val jsonObject = buidJsonObject()

            // 3. add JSON content to POST request body
            setPostRequestContent(conn, jsonObject)

            // 4. make POST request to the given URL
            conn.connect()

            // 5. return response message
            conn.responseMessage + ""

            if (conn.responseCode == HttpsURLConnection.HTTP_OK) {
                val stream = BufferedInputStream(conn.inputStream)
                serverResponse = readStream(inputStream = stream)
            } else {
                serverResponse = "Problem in Getting Server Response"
            }

        }
        return result.toString()
    }

    @Throws(IOException::class)
    private fun setPostRequestContent(conn: HttpURLConnection, jsonObject: JSONObject) {

        val os = conn.outputStream
        val writer = BufferedWriter(OutputStreamWriter(os, "UTF-8"))
        writer.write(jsonObject.toString())
        Log.i(TAG, jsonObject.toString())
        writer.flush()
        writer.close()
        os.close()
    }

    private fun readStream(inputStream: BufferedInputStream): String {
        val bufferedReader = BufferedReader(InputStreamReader(inputStream))
        val stringBuilder = StringBuilder()
        bufferedReader.forEachLine { stringBuilder.append(it) }
        return stringBuilder.toString()
    }

}

private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val SHAREDLOCATION = "SENSORMOBILEHEALTHCARE"