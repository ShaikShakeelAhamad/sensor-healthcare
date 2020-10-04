package com.webmah.sensorhealthcare

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_monitoringpatient.*
import java.text.SimpleDateFormat
import java.util.*

class MonitoringPatient : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_monitoringpatient)

        val PATIENTDATA = intent.getStringExtra("PATIENTINFO")

        sendMonitorData.setOnClickListener {

            val heartrate = heartRate.text.toString()
            val BP = BP.text.toString()
            val SENDPATIENTDATA = "$PATIENTDATA $heartrate $BP"

            val intent = Intent(this, SensorDataToGatewayAndConfirm::class.java)
            intent.putExtra("SENDPATIENTDATA", SENDPATIENTDATA)
            startActivity(intent)
        }

    }
}