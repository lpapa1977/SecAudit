package com.test.secaudit

import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

enum class Sev { GOOD, WARN, INFO }

/**
 * Base with UI helpers (dark style, no XML) reused by MainActivity and AppListActivity:
 * dp→px conversion, colors, rounded backgrounds and buttons.
 */
abstract class BaseSecActivity : AppCompatActivity() {

    protected val density by lazy { resources.displayMetrics.density }
    protected fun px(v: Int) = (v * density).toInt()

    protected fun col(id: Int) = ContextCompat.getColor(this, id)

    protected fun sevColor(s: Sev) = when (s) {
        Sev.GOOD -> col(R.color.good)
        Sev.WARN -> col(R.color.warn)
        Sev.INFO -> col(R.color.info)
    }

    protected fun rounded(fill: Int, radius: Int, strokeColor: Int = 0, strokeW: Int = 0) =
        GradientDrawable().apply {
            setColor(fill)
            cornerRadius = radius.toFloat()
            if (strokeW > 0) setStroke(strokeW, strokeColor)
        }

    /** Styled button (no XML): filled accent or outline. */
    protected fun makeButton(label: String, filled: Boolean, onClick: () -> Unit): View =
        TextView(this).apply {
            text = label
            textSize = 14f
            gravity = Gravity.CENTER
            setTypeface(typeface, Typeface.BOLD)
            isClickable = true
            setPadding(px(20), px(12), px(20), px(12))
            if (filled) {
                setTextColor(Color.parseColor("#0D1117"))
                background = rounded(col(R.color.accent), px(12))
            } else {
                setTextColor(col(R.color.accent))
                background = rounded(Color.TRANSPARENT, px(12), col(R.color.accent), px(1))
            }
            setOnClickListener { onClick() }
        }

    /** Launches the first intent that resolves; falls back to general Settings. */
    protected fun launchFirst(candidates: List<android.content.Intent>) {
        for (i in candidates) {
            try { startActivity(i); return } catch (_: Exception) { /* try next */ }
        }
        try { startActivity(android.content.Intent(android.provider.Settings.ACTION_SETTINGS)) } catch (_: Exception) {}
    }
}
