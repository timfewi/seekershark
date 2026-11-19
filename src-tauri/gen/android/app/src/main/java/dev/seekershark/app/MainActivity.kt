package dev.seekershark.app

import android.os.Bundle
import android.graphics.Color
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.core.graphics.Insets
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)

    // Fit the entire WebView, including HTML dialogs, inside the system bars.
    // CSS env(safe-area-inset-*) alone is not reliable in Android WebViews.
    val content = findViewById<View>(android.R.id.content)
    content.setBackgroundColor(Color.rgb(5, 5, 5))
    val safeTypes = WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val safe = insets.getInsets(safeTypes)
      view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
      WindowInsetsCompat.Builder(insets)
        .setInsets(safeTypes, Insets.NONE)
        .setInsetsIgnoringVisibility(safeTypes, Insets.NONE)
        .setDisplayCutout(null)
        .build()
    }
    ViewCompat.requestApplyInsets(content)
  }
}
