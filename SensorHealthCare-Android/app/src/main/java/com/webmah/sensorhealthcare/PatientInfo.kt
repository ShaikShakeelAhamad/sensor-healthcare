package com.webmah.sensorhealthcare

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import kotlinx.android.synthetic.main.activity_patientinfo.*
import java.text.SimpleDateFormat
import java.util.*

class PatientInfo : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_patientinfo)

        monitorData.setOnClickListener {
            val tname = "PatientContactHealthCare"
            val pid = pid.text.toString()
            val pname = pname.text.toString()
            val page = page.text.toString()
            val problem = pproblem.text.toString()
            val cdoctor = pdoctor.text.toString()
            val lastvisit = plastvisit.text.toString()
            val sdf = SimpleDateFormat("yyyy.MM.dd G 'at' HH:mm:ss z")
            val currentDateandTime: String = sdf.format(Date())
            val PATIENTINFO = "$tname, $pid, $pname, $page, $problem, $cdoctor, $lastvisit, $currentDateandTime"

            val intent = Intent(this, MonitoringPatient::class.java)
            intent.putExtra("PATIENTINFO", PATIENTINFO)
            startActivity(intent)

        }

    }
}