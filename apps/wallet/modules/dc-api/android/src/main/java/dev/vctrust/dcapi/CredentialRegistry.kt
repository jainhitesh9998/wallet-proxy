package dev.vctrust.dcapi

import android.content.Context
import android.graphics.Bitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import org.json.JSONArray
import org.json.JSONObject

/**
 * Registers the wallet's credentials with Credential Manager under Google's OpenID4VP matcher, which picks the ones a
 * DC API request (DCQL) can be answered with and shows them in the system picker. Each registration replaces the last.
 */
object CredentialRegistry {
  private const val REGISTRY_ID = "vctrust-wallet"

  suspend fun register(context: Context, entriesJson: String): Int {
    val list = JSONArray(entriesJson)
    val icon = appIcon(context)
    val entries = (0 until list.length()).mapNotNull { entry(list.getJSONObject(it), icon) }
    RegistryManager.create(context).registerCredentials(
      OpenId4VpRegistry(
        credentialEntries = entries,
        id = REGISTRY_ID,
        supportedProtocols = listOf(
          OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_SIGNED,
          OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_MULTISIGNED,
          OpenId4VpRegistry.PROTOCOL_OPENID4VP_1_0_UNSIGNED,
        ),
      )
    )
    return entries.size
  }

  private fun entry(o: JSONObject, icon: Bitmap): DigitalCredentialEntry? {
    val id = o.getString("id")
    val type = o.getString("type")
    val display = setOf(VerificationEntryDisplayProperties(title = o.getString("title"), subtitle = o.optString("subtitle").ifBlank { null }, icon = icon))
    val claims = o.getJSONArray("claims")
    return when (o.getString("format")) {
      "mso_mdoc" -> MdocEntry(
        docType = type,
        fields = (0 until claims.length()).mapNotNull { i ->
          val c = claims.getJSONObject(i)
          val path = c.getJSONArray("path")
          if (path.length() != 2) return@mapNotNull null
          MdocField(namespace = path.getString(0), identifier = path.getString(1), fieldValue = value(c), fieldDisplayPropertySet = fieldDisplay(c, path.getString(1)))
        },
        entryDisplayPropertySet = display,
        id = id,
      )
      "dc+sd-jwt" -> SdJwtEntry(
        verifiableCredentialType = type,
        claims = (0 until claims.length()).map { i ->
          val c = claims.getJSONObject(i)
          val path = c.getJSONArray("path")
          val segments = (0 until path.length()).map { path.getString(it) }
          SdJwtClaim(path = segments, value = value(c), fieldDisplayPropertySet = fieldDisplay(c, segments.last()))
        },
        entryDisplayPropertySet = display,
        id = id,
      )
      else -> null
    }
  }

  private fun value(c: JSONObject): String? = if (c.has("value") && !c.isNull("value")) c.getString("value") else null

  private fun fieldDisplay(c: JSONObject, fallback: String) =
    setOf(VerificationFieldDisplayProperties(displayName = c.optString("name").ifBlank { fallback }, displayValue = value(c)))

  private fun appIcon(context: Context): Bitmap =
    context.packageManager.getApplicationIcon(context.packageName).toBitmap(48, 48)
}
