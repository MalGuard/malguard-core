package com.malguard.mobilepreview;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

public final class MainActivity extends Activity {
    private static final int FILE_PICK_REQUEST = 1001;

    private WebView webView;
    private Uri selectedFileUri;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowContentAccess(false);
        settings.setBlockNetworkLoads(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);

        webView.setWebViewClient(new WebViewClient());
        webView.addJavascriptInterface(new MobileBridge(), "MalGuardMobile");
        webView.loadUrl("file:///android_asset/index.html");
    }

    private final class MobileBridge {
        @JavascriptInterface
        public void chooseFile() {
            runOnUiThread(() -> {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                startActivityForResult(intent, FILE_PICK_REQUEST);
            });
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != FILE_PICK_REQUEST) {
            return;
        }

        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            webView.evaluateJavascript("window.onMalGuardFileCancelled && window.onMalGuardFileCancelled()", null);
            return;
        }

        selectedFileUri = data.getData();
        final String displayName = getDisplayName(selectedFileUri);
        final String safeName = JSONObject.quote(displayName);
        webView.evaluateJavascript(
            "window.onMalGuardFileChosen && window.onMalGuardFileChosen(" + safeName + ")",
            null);
    }

    private String getDisplayName(Uri uri) {
        String name = "Selected file";
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (index >= 0) {
                    String candidate = cursor.getString(index);
                    if (candidate != null && !candidate.isBlank()) {
                        name = candidate;
                    }
                }
            }
        } catch (RuntimeException ignored) {
            // Keep the generic name. The preview never reads or uploads file contents.
        }
        return name;
    }

    @Override
    protected void onDestroy() {
        selectedFileUri = null;
        if (webView != null) {
            webView.removeJavascriptInterface("MalGuardMobile");
            webView.loadUrl("about:blank");
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
