# Credential Manager's registry finds its Play services provider by reflection, and Play services' identity
# credentials client (de)serializes its requests reflectively; R8 must not strip or rename either.
-keep class androidx.credentials.registry.** { *; }
-keep class com.google.android.gms.identitycredentials.** { *; }
-keep class androidx.credentials.provider.** { *; }
