// AesModule.java
package com.tectiv3.aes;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.bridge.ReactMethod;

@ReactModule(name = AesModule.NAME)
public class AesModule extends ReactContextBaseJavaModule {
  public static final String NAME = "AesModule";
  private native void nativeInstall(long jsiPtr);

  public AesModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  public String getName() {
    return NAME;
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public boolean install() {
    try {
      System.loadLibrary("aesmodule");

      ReactApplicationContext context = getReactApplicationContext();
      nativeInstall(context.getJavaScriptContextHolder().get());
      return true;
    } catch (Exception exception) {
      return false;
    }
  }
}