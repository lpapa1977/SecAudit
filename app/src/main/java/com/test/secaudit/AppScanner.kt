package com.test.secaudit

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

data class Reason(val text: String, val weight: Int)

data class AppRisk(
    val pkg: String,
    val label: String,
    val sideloaded: Boolean,
    val reasons: List<Reason>,
    val score: Int
) {
    val high: Boolean get() = score >= 5
}

data class ScanResult(
    val flagged: List<AppRisk>,        // non-system, score >= 3, sorted desc
    val hidden: List<AppRisk>,         // non-system without launcher icon
    val hiddenRisky: Boolean,          // a hidden app is from an untrusted source
    val accessibility: List<String>,   // labels of non-system accessibility services
    val notifListeners: List<String>,  // labels with notification access (non-system)
    val deviceAdmins: List<String>,    // labels of non-system device admins
    val sideloadedCount: Int,
    val totalUserApps: Int
)

/**
 * Rootless app fleet scanner using composite signals. Runs on a background thread.
 * Focuses on user apps (non-system). Sensitive permissions only score when the install
 * source is not Google Play (composite signal), to avoid flagging legitimate store apps.
 */
object AppScanner {

    private val PLAY_STORES = setOf("com.android.vending", "com.google.android.feedback")

    fun scan(ctx: Context): ScanResult {
        val pm = ctx.packageManager
        val self = ctx.packageName
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager

        val accPkgs = enabledServicePkgs(ctx, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val notifPkgs = enabledServicePkgs(ctx, "enabled_notification_listeners")
        val adminPkgs = deviceAdminPkgs(ctx)

        @Suppress("DEPRECATION")
        val pkgs: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (_: Exception) { emptyList() }

        val flagged = ArrayList<AppRisk>()
        val hidden = ArrayList<AppRisk>()
        var sideloadedCount = 0
        var userApps = 0
        val accLabels = ArrayList<String>()
        val notifLabels = ArrayList<String>()
        val adminLabels = ArrayList<String>()

        for (pi in pkgs) {
            val ai = pi.applicationInfo ?: continue
            val pkg = pi.packageName
            if (pkg == self) continue
            val isSystem = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            val label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(pkg)

            // Summary labels: powerful services held by non-system apps.
            if (!isSystem && pkg in accPkgs) accLabels.add(label)
            if (!isSystem && pkg in notifPkgs) notifLabels.add(label)
            if (!isSystem && pkg in adminPkgs) adminLabels.add(label)

            // Suspicious/hidden analysis limited to user apps.
            if (isSystem) continue
            userApps++

            val sideloaded = isSideloaded(pm, pkg)
            if (sideloaded) sideloadedCount++

            val reasons = ArrayList<Reason>()

            val hasLauncher = pm.getLaunchIntentForPackage(pkg) != null ||
                pm.getLeanbackLaunchIntentForPackage(pkg) != null
            val isHidden = !hasLauncher
            if (isHidden) reasons.add(Reason("No launcher icon (hidden app)", 2))

            if (pkg in accPkgs) reasons.add(Reason("Active accessibility service: can read screen and simulate taps", 3))
            if (pkg in adminPkgs) reasons.add(Reason("Device administrator: resists uninstall", 3))
            if (pkg in notifPkgs) reasons.add(Reason("Reads all notifications (including 2FA codes)", 3))

            val granted = grantedPermissions(pi)
            val uid = ai.uid

            if ("android.permission.SYSTEM_ALERT_WINDOW" in granted &&
                appOpAllowed(ops, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, uid, pkg)
            ) reasons.add(Reason("Can draw over other apps (overlays)", 2))

            if ("android.permission.REQUEST_INSTALL_PACKAGES" in granted)
                reasons.add(Reason("Can install other apps", 2))

            if (appOpAllowed(ops, AppOpsManager.OPSTR_GET_USAGE_STATS, uid, pkg))
                reasons.add(Reason("Access to app usage statistics", 1))

            if (ai.targetSdkVersion < Build.VERSION_CODES.M)
                reasons.add(Reason("Targets a very old API (targetSdk ${ai.targetSdkVersion}): bypasses modern permissions", 2))

            if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0)
                reasons.add(Reason("Compiled in debug mode", 1))

            if (sideloaded) reasons.add(Reason("Installed outside Google Play", 1))

            // Sensitive permissions only score if origin is NOT Play (composite signal).
            val danger = listOf(
                "android.permission.READ_SMS" to "read SMS",
                "android.permission.SEND_SMS" to "send SMS",
                "android.permission.READ_CALL_LOG" to "call log",
                "android.permission.RECORD_AUDIO" to "microphone",
                "android.permission.CAMERA" to "camera",
                "android.permission.READ_CONTACTS" to "contacts",
                "android.permission.ACCESS_BACKGROUND_LOCATION" to "background location"
            ).filter { it.first in granted }
            if (danger.isNotEmpty() && sideloaded) {
                reasons.add(Reason(
                    "Sensitive permissions: " + danger.joinToString(", ") { it.second },
                    danger.size.coerceAtMost(3)
                ))
            }

            val score = reasons.sumOf { it.weight }
            val risk = AppRisk(pkg, label, sideloaded, reasons, score)
            if (isHidden) hidden.add(risk)
            if (score >= 3) flagged.add(risk)
        }

        flagged.sortByDescending { it.score }
        return ScanResult(
            flagged = flagged,
            hidden = hidden,
            hiddenRisky = hidden.any { it.sideloaded },
            accessibility = accLabels,
            notifListeners = notifLabels,
            deviceAdmins = adminLabels,
            sideloadedCount = sideloadedCount,
            totalUserApps = userApps
        )
    }

    // ----------------------------------------------------------------- helpers

    private fun grantedPermissions(pi: PackageInfo): Set<String> {
        val perms = pi.requestedPermissions ?: return emptySet()
        val flags = pi.requestedPermissionsFlags
        if (flags == null || flags.size != perms.size) return perms.toSet()
        val out = HashSet<String>()
        for (i in perms.indices) {
            if (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) out.add(perms[i])
        }
        return out
    }

    private fun isSideloaded(pm: PackageManager, pkg: String): Boolean {
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                pm.getInstallSourceInfo(pkg).installingPackageName
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
        } catch (_: Exception) { null }
        return installer == null || installer !in PLAY_STORES
    }

    private fun appOpAllowed(ops: AppOpsManager?, op: String, uid: Int, pkg: String): Boolean {
        if (ops == null) return false
        return try {
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                ops.unsafeCheckOpNoThrow(op, uid, pkg)
            else @Suppress("DEPRECATION") ops.checkOpNoThrow(op, uid, pkg)
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: Exception) { false }
    }

    /** Parses a component list ("pkg/.Service:pkg2/...") into a set of package names. */
    private fun enabledServicePkgs(ctx: Context, secureKey: String): Set<String> {
        val raw = try { Settings.Secure.getString(ctx.contentResolver, secureKey) } catch (_: Exception) { null }
            ?: return emptySet()
        return raw.split(':')
            .mapNotNull { it.substringBefore('/').takeIf { p -> p.isNotBlank() } }
            .toSet()
    }

    private fun deviceAdminPkgs(ctx: Context): Set<String> {
        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return emptySet()
        return try { dpm.activeAdmins?.map { it.packageName }?.toSet() ?: emptySet() }
        catch (_: Exception) { emptySet() }
    }
}
