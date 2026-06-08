package com.test.secaudit

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.util.concurrent.Executors

/**
 * Dedicated screen: lists apps flagged as risky (score >= 3) with their reasons
 * and actions to review/uninstall them. Scans in background.
 */
class AppListActivity : BaseSecActivity() {

    private lateinit var container: LinearLayout
    private val amber = Color.parseColor("#F9A825")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(18), px(22), px(18), px(28))
        }
        setContentView(ScrollView(this).apply { isFillViewport = true; addView(container) })

        container.addView(TextView(this).apply {
            text = "Flagged Apps"
            textSize = 24f
            setTextColor(col(R.color.textPrimary))
            setTypeface(typeface, Typeface.BOLD)
        })
        val loading = TextView(this).apply {
            text = "Analyzing apps…"
            textSize = 14f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(16), 0, 0)
        }
        container.addView(loading)

        Executors.newSingleThreadExecutor().execute {
            val result = AppScanner.scan(this)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                container.removeView(loading)
                render(result)
            }
        }
    }

    private fun render(result: ScanResult) {
        container.addView(TextView(this).apply {
            text = if (result.flagged.isEmpty())
                "No suspicious apps detected among ${result.totalUserApps} user apps."
            else
                "${result.flagged.size} of ${result.totalUserApps} user apps flagged. " +
                    "Review each one; the risk score is a hint, not a malware verdict."
            textSize = 13f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(6), 0, px(8))
        })

        for (app in result.flagged) {
            container.addView(buildAppCard(app), LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                topMargin = px(10)
            })
        }
    }

    private fun buildAppCard(app: AppRisk): View {
        val accent = if (app.high) col(R.color.warn) else amber
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(col(R.color.surface), px(16), accent and 0x55FFFFFF.toInt(), px(1))
            setPadding(px(16), px(14), px(16), px(14))
        }

        // Header: nombre + chip nivel
        card.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(TextView(this@AppListActivity).apply {
                text = app.label
                textSize = 16f
                setTextColor(col(R.color.textPrimary))
                setTypeface(typeface, Typeface.BOLD)
            }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            addView(TextView(this@AppListActivity).apply {
                text = if (app.high) "HIGH" else "MEDIUM"
                textSize = 11f
                setTypeface(typeface, Typeface.BOLD)
                setTextColor(accent)
                background = rounded(accent and 0x22FFFFFF.toInt(), px(20))
                setPadding(px(12), px(5), px(12), px(5))
            })
        })
        card.addView(TextView(this).apply {
            text = app.pkg
            textSize = 11f
            setTextColor(col(R.color.textSecondary))
            setPadding(0, px(2), 0, px(8))
        })

        // Motivos
        for (r in app.reasons) {
            card.addView(TextView(this).apply {
                text = "•  ${r.text}"
                textSize = 13f
                setTextColor(col(R.color.textSecondary))
                setLineSpacing(px(2).toFloat(), 1f)
                setPadding(0, px(2), 0, px(2))
            })
        }

        // Acciones
        card.addView(LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, px(10), 0, 0)
            addView(makeButton("App info", filled = false) { openAppInfo(app.pkg) })
            addView(makeButton("Uninstall", filled = false) { uninstall(app.pkg) },
                LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { leftMargin = px(10) })
        })
        return card
    }

    private fun openAppInfo(pkg: String) = launchFirst(
        listOf(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")),
            Intent(Settings.ACTION_APPLICATION_SETTINGS)
        )
    )

    private fun uninstall(pkg: String) = launchFirst(
        listOf(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    )
}
