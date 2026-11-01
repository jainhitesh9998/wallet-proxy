package dev.vctrust.dcapi

import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** The JS side of the DC API bridge: registration with Credential Manager and the answer to the current request. */
class DcApiModule : Module() {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

  override fun definition() = ModuleDefinition {
    Name("DcApi")

    AsyncFunction("registerCredentials") { entriesJson: String, promise: Promise ->
      val context = appContext.reactContext?.applicationContext
        ?: return@AsyncFunction promise.reject("ERR_DCAPI_CONTEXT", "No Android context", null)
      scope.launch {
        try {
          promise.resolve(CredentialRegistry.register(context, entriesJson))
        } catch (e: Exception) {
          promise.reject("ERR_DCAPI_REGISTER", e.message ?: e.toString(), e)
        }
      }
    }

    Function("finish") { token: String, responseJson: String -> DcApiActivity.respond(token, responseJson) }

    Function("cancel") { token: String -> DcApiActivity.cancel(token) }

    OnDestroy { scope.coroutineContext[kotlinx.coroutines.Job]?.cancel() }
  }
}
