# KBox Monitor 混淆规则（minifyEnabled=false 默认不生效，保留以备开启）
-keep class com.squareup.okhttp3.okhttp.* { *; }
-dontwarn okhttp3.**
-dontwarn okio.**