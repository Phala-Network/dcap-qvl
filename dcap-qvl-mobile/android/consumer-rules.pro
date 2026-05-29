# Keep the UniFFI-generated JNA bridges and data classes — they're referenced
# reflectively from native code.
-keep class com.phala.dcapqvl.** { *; }
-keep class com.sun.jna.** { *; }
