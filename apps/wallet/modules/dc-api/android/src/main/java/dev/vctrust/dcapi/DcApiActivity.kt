package dev.vctrust.dcapi

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.registry.provider.selectedCredentialSet
import androidx.credentials.registry.provider.selectedEntryId
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultReactActivityDelegate
import java.lang.ref.WeakReference
import java.security.MessageDigest
import java.util.UUID
import org.json.JSONObject

/**
 * The activity Credential Manager starts when the user picks this wallet for a DC API request. It reads the request and
 * the verifier's origin, renders the "dcapi" React component with them, and returns what the component decides:
 * a DigitalCredential ({protocol, data}) or a cancellation. Each launch gets a random token; the component answers with
 * it, so an answer can only ever complete the request it was built for.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class DcApiActivity : ReactActivity() {
  private var launch: Bundle = Bundle()
  private var request: ProviderGetCredentialRequest? = null
  private var token: String? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    launch = readRequest()
    val t = UUID.randomUUID().toString()
    token = t
    synchronized(open) { open[t] = WeakReference(this) }
    launch.putString("token", t)
    super.onCreate(null)
  }

  override fun onDestroy() {
    token?.let { synchronized(open) { open.remove(it) } }
    super.onDestroy()
  }

  override fun getMainComponentName(): String = "dcapi"

  override fun createReactActivityDelegate(): ReactActivityDelegate =
    object : DefaultReactActivityDelegate(this, mainComponentName) {
      override fun getLaunchOptions(): Bundle = launch
    }

  private fun readRequest(): Bundle {
    val out = Bundle()
    try {
      // Only Credential Manager may start a request: the request extras (and the origin in them) are otherwise forgeable.
      val caller = callingPackage
      if (!isCredentialManager(caller)) throw SecurityException("Not started by Credential Manager (caller: ${caller ?: "unknown"})")
      val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        ?: throw IllegalStateException("The intent carries no credential request")
      val option = request.credentialOptions.filterIsInstance<GetDigitalCredentialOption>().firstOrNull()
        ?: throw IllegalStateException("The request has no digital credential option")
      out.putString("requestJson", option.requestJson)
      out.putString("origin", origin(request.callingAppInfo))
      out.putString("selectionJson", selection(request))
      this.request = request
    } catch (e: Exception) {
      Log.w(TAG, "Cannot read the DC API request", e)
      out.putString("error", e.message ?: e.toString())
    }
    return out
  }

  /**
   * The caller is the platform's Credential Manager, judged by more than its package name (which a sideloaded app can
   * take where the real one is absent): it must be a system app, and Play services must also be signed with one of the
   * certificates Google publishes for it in the privileged-apps list bundled with this module.
   */
  private fun isCredentialManager(caller: String?): Boolean {
    if (caller != GMS && caller != SYSTEM_CREDENTIAL_MANAGER) return false
    val info = try { packageManager.getApplicationInfo(caller, 0) } catch (e: PackageManager.NameNotFoundException) { return false }
    if (info.flags and ApplicationInfo.FLAG_SYSTEM == 0) return false
    if (caller != GMS || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return true
    return publishedCertificates(GMS).any { packageManager.hasSigningCertificate(GMS, it, PackageManager.CERT_INPUT_SHA256) }
  }

  /** SHA-256 certificate digests listed for a package in the bundled privileged-apps list (release builds). */
  private fun publishedCertificates(packageName: String): List<ByteArray> {
    val apps = JSONObject(allowlist()).getJSONArray("apps")
    return (0 until apps.length()).map { apps.getJSONObject(it).getJSONObject("info") }
      .filter { it.optString("package_name") == packageName }
      .flatMap { info -> info.getJSONArray("signatures").let { sigs -> (0 until sigs.length()).map { sigs.getJSONObject(it) } } }
      .filter { it.optString("build") == "release" || Build.TYPE == "userdebug" }
      .map { sig -> sig.getString("cert_fingerprint_sha256").split(":").map { it.toInt(16).toByte() }.toByteArray() }
  }

  private fun allowlist(): String = resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }

  /**
   * What the user picked in the system picker, as the matcher reported it: the index of the request in {requests: [...]}
   * and, per DCQL credential query id, the registered credential id. JSON {requestIndex?, credentials: {dcqlId: id}}.
   */
  private fun selection(request: ProviderGetCredentialRequest): String {
    val out = JSONObject()
    val credentials = JSONObject()
    request.selectedCredentialSet?.credentials?.forEach { c ->
      val metadata = c.metadata?.let { runCatching { JSONObject(it) }.getOrNull() }
      metadata?.optInt("dc_request_index", -1)?.takeIf { it >= 0 }?.let { out.put("requestIndex", it) }
      metadata?.optString("dcql_cred_id")?.takeIf { it.isNotEmpty() }?.let { credentials.put(it, c.credentialId) }
    }
    if (credentials.length() == 0) request.selectedEntryId?.let { out.put("entryId", it) }
    return out.put("credentials", credentials).toString()
  }

  /**
   * The web origin a privileged browser (Google's allowlist) asked for, or for an app its own identity,
   * android:apk-key-hash:<base64url SHA-256 of its signing certificate>. An origin claimed by an app that is not on the
   * allowlist is never used.
   */
  private fun origin(info: CallingAppInfo): String {
    val web = try { info.getOrigin(allowlist()) } catch (e: IllegalStateException) { null }
    // The platform may spell the default port; the Origin the verifier binds to (and lists in expected_origins) does not.
    if (web != null) return web.removeSuffix("/").let { if (it.startsWith("https://")) it.removeSuffix(":443") else it }
    val cert = info.signingInfoCompat.signingCertificateHistory.firstOrNull()
      ?: throw IllegalStateException("The calling app ${info.packageName} has no signing certificate")
    val hash = MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
    return "android:apk-key-hash:" + Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
  }

  private fun complete(build: (Intent) -> Unit) {
    val result = Intent()
    build(result)
    setResult(Activity.RESULT_OK, result)
    finish()
  }

  companion object {
    private const val TAG = "DcApi"
    private const val GMS = "com.google.android.gms"
    private const val SYSTEM_CREDENTIAL_MANAGER = "com.android.credentialmanager"
    /** Requests being shown, by launch token. */
    private val open = HashMap<String, WeakReference<DcApiActivity>>()

    private fun take(token: String): DcApiActivity? = synchronized(open) { open.remove(token)?.get() }

    /** Answers the request launched with {@code token}; false when it is not open or was never a valid request. */
    fun respond(token: String, responseJson: String): Boolean {
      val a = take(token) ?: return false
      val request = a.request ?: return false.also { a.runOnUiThread { a.finish() } }
      a.runOnUiThread {
        a.complete { PendingIntentHandler.setGetCredentialResponse(it, GetCredentialResponse(DigitalCredential(responseJson)), request) }
      }
      return true
    }

    /**
     * Ends the request without an answer. The message is fixed: it reaches native verifier apps, and a cancellation must
     * look like any other (OpenID4VP §15.9.2). Play services then shows its picker again, where the user can close it.
     */
    fun cancel(token: String): Boolean {
      val a = take(token) ?: return false
      a.runOnUiThread {
        if (a.request == null) a.finish()   // a launch that was refused: nothing to answer
        else a.complete { PendingIntentHandler.setGetCredentialException(it, GetCredentialCancellationException("Cancelled")) }
      }
      return true
    }
  }
}
