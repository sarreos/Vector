package org.matrix.vector.daemon.env

import android.net.LocalServerSocket
import android.os.Build
import android.os.FileObserver
import android.os.SELinux
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths
import kotlinx.coroutines.launch
import org.matrix.vector.ipc.IManagerService
import org.matrix.vector.daemon.VectorDaemon

private const val TAG = "VectorDex2Oat"

// Wrapper states mirrored directly from the IManagerService AIDL contract.
val DEX2OAT_OK = IManagerService.DEX2OAT_OK
val DEX2OAT_MOUNT_FAILED = IManagerService.DEX2OAT_MOUNT_FAILED
val DEX2OAT_SEPOLICY_INCORRECT = IManagerService.DEX2OAT_SEPOLICY_INCORRECT
val DEX2OAT_SELINUX_PERMISSIVE = IManagerService.DEX2OAT_SELINUX_PERMISSIVE
val DEX2OAT_CRASHED = IManagerService.DEX2OAT_CRASHED

object Dex2OatServer {
  private const val WRAPPER32 = "bin/dex2oat32"
  private const val WRAPPER64 = "bin/dex2oat64"
  private const val HOOKER32 = "bin/liboat_hook32.so"
  private const val HOOKER64 = "bin/liboat_hook64.so"

  private val dex2oatArray = arrayOfNulls<String>(6)
  private val fdArray = arrayOfNulls<FileDescriptor>(6)

  @Volatile
  var compatibility = DEX2OAT_OK
    private set

  private external fun setSockCreateContext(context: String?): Boolean

  private external fun getSockPath(): String

  /** The nodes whose writes mean the SELinux state this daemon depends on may have moved. */
  private val SELINUX_NODES = listOf("/sys/fs/selinux/enforce", "/sys/fs/selinux/policy")

  /**
   * Watches [SELINUX_NODES] on every release this daemon runs on.
   *
   * `FileObserver(List<File>, int)` is API 29 and the minimum here is 27, where the only
   * constructors are the single-path ones -- deprecated in 29 precisely because they were replaced
   * by these. So below 29 this is one observer per node, and `stopWatching` has to reach all of
   * them, which is why the two live behind an object rather than being a `FileObserver` itself.
   */
  private object SelinuxObserver {
    private val observers: List<FileObserver> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          listOf(
              object : FileObserver(SELINUX_NODES.map(::File), FileObserver.CLOSE_WRITE) {
                override fun onEvent(event: Int, path: String?) = onSelinuxEvent()
              })
        } else {
          SELINUX_NODES.map { node ->
            @Suppress("DEPRECATION")
            object : FileObserver(node, FileObserver.CLOSE_WRITE) {
              override fun onEvent(event: Int, path: String?) = onSelinuxEvent()
            }
          }
        }

    fun startWatching() = observers.forEach(FileObserver::startWatching)

    fun stopWatching() = observers.forEach(FileObserver::stopWatching)
  }

  private fun onSelinuxEvent() {
    synchronized(this) {
      if (compatibility == DEX2OAT_CRASHED) {
        SelinuxObserver.stopWatching()
        return
      }

      val enforcing =
          runCatching {
                Files.newInputStream(Paths.get("/sys/fs/selinux/enforce")).use {
                  it.read() == '1'.code
                }
              }
              .getOrDefault(false)

      when {
        !enforcing -> {
          if (compatibility == DEX2OAT_OK) setRedirections(false)
          compatibility = DEX2OAT_SELINUX_PERMISSIVE
        }
        hasSePolicyErrors() -> {
          if (compatibility == DEX2OAT_OK) setRedirections(false)
          compatibility = DEX2OAT_SEPOLICY_INCORRECT
        }
        compatibility != DEX2OAT_OK -> {
          if (setRedirections(true)) {
            compatibility = DEX2OAT_OK
          } else {
            setRedirections(false)
            compatibility = DEX2OAT_MOUNT_FAILED
            SelinuxObserver.stopWatching()
          }
        }
      }
    }
  }

  init {
    // Android 10 vs 11+ path differences
    if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
      checkAndAddDex2Oat("/apex/com.android.runtime/bin/dex2oat")
      checkAndAddDex2Oat("/apex/com.android.runtime/bin/dex2oatd")
      checkAndAddDex2Oat("/apex/com.android.runtime/bin/dex2oat64")
      checkAndAddDex2Oat("/apex/com.android.runtime/bin/dex2oatd64")
    } else {
      checkAndAddDex2Oat("/apex/com.android.art/bin/dex2oat32")
      checkAndAddDex2Oat("/apex/com.android.art/bin/dex2oatd32")
      checkAndAddDex2Oat("/apex/com.android.art/bin/dex2oat64")
      checkAndAddDex2Oat("/apex/com.android.art/bin/dex2oatd64")
    }

    openDex2oat(4, "/data/adb/modules/zygisk_vector/bin/liboat_hook32.so")
    openDex2oat(5, "/data/adb/modules/zygisk_vector/bin/liboat_hook64.so")
  }

  private fun hasSePolicyErrors(): Boolean {
    return SELinux.checkSELinuxAccess(
        "u:r:untrusted_app:s0", "u:object_r:dex2oat_exec:s0", "file", "execute") ||
        SELinux.checkSELinuxAccess(
            "u:r:untrusted_app:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")
  }

  private fun openDex2oat(id: Int, path: String) {
    runCatching {
      fdArray[id] = Os.open(path, OsConstants.O_RDONLY, 0)
      dex2oatArray[id] = path
    }
  }

  private fun checkAndAddDex2Oat(path: String) {
    val file = File(path)
    if (!file.exists()) return

    runCatching {
          FileInputStream(file).use { fis ->
            val header = ByteArray(5)
            if (fis.read(header) != 5) return
            // Verify ELF Magic: 0x7F 'E' 'L' 'F'
            if (header[0] != 0x7F.toByte() ||
                header[1] != 'E'.code.toByte() ||
                header[2] != 'L'.code.toByte() ||
                header[3] != 'F'.code.toByte())
                return

            val is32Bit = header[4] == 1.toByte()
            val is64Bit = header[4] == 2.toByte()
            val isDebug = path.contains("dex2oatd")

            val index =
                when {
                  is32Bit -> if (isDebug) 1 else 0
                  is64Bit -> if (isDebug) 3 else 2
                  else -> -1
                }

            if (index != -1 && dex2oatArray[index] == null) {
              dex2oatArray[index] = path
              fdArray[index] = Os.open(path, OsConstants.O_RDONLY, 0)
              Log.i(TAG, "Detected $path -> Assigned Index $index")
            }
          }
        }
        .onFailure { dex2oatArray[dex2oatArray.indexOf(path)] = null }
  }

  /**
   * NoMount's CLI is installed by its metamodule. Prefer the module-local symlink so this
   * works with both KernelSU and APatch without depending on their manager-specific paths.
   */
  private fun noMountBinary(): String? {
    val candidates =
        listOf(
            "/data/adb/modules/nomount/bin/nm",
            "/data/adb/ksu/bin/nm",
            "/data/adb/ap/bin/nm")
    return candidates.firstOrNull { File(it).isFile && File(it).canExecute() }
  }

  private fun runNoMount(vararg args: String): Boolean {
    val binary = noMountBinary()
    if (binary == null) {
      Log.e(TAG, "NoMount CLI not found; install and enable the NoMount metamodule")
      return false
    }

    return runCatching {
          val process =
              ProcessBuilder(listOf(binary) + args)
                  .redirectErrorStream(true)
                  .start()
          val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
          val exitCode = process.waitFor()
          if (output.isNotEmpty()) Log.d(TAG, "nm ${args.joinToString(" ")}: $output")
          if (exitCode != 0) {
            Log.e(TAG, "nm ${args.joinToString(" ")} failed with exit code $exitCode")
          }
          exitCode == 0
        }
        .onFailure { Log.e(TAG, "Failed to execute NoMount", it) }
        .getOrDefault(false)
  }

  private fun setDex2OatFallback(enabled: Boolean) {
    val args =
        if (enabled) {
          listOf("resetprop", "dalvik.vm.dex2oat-flags", "--inline-max-code-units=0")
        } else {
          listOf("resetprop", "--delete", "dalvik.vm.dex2oat-flags")
        }

    runCatching {
          val process = ProcessBuilder(args).redirectErrorStream(true).start()
          val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
          val exitCode = process.waitFor()
          if (output.isNotEmpty()) Log.d(TAG, "resetprop: $output")
          if (exitCode != 0) Log.e(TAG, "resetprop failed with exit code $exitCode")
        }
        .onFailure { Log.e(TAG, "Failed to update dex2oat fallback property", it) }
  }

  /**
   * Redirect every discovered ART compiler entry point to the matching Vector wrapper.
   *
   * Re-adding an existing NoMount rule updates its target, so this is safe to call after
   * daemon restarts and when SELinux policy changes.
   */
  private fun setRedirections(enabled: Boolean): Boolean {
    val targets = (0 until 4).mapNotNull { dex2oatArray[it] }.distinct()

    if (!enabled) {
      var success = true
      for (i in 0 until 4) {
        val target = dex2oatArray[i] ?: continue
        if (!runNoMount("rule", "del", target)) success = false
      }
      setDex2OatFallback(true)
      return success
    }

    if (targets.isEmpty()) {
      Log.e(TAG, "No stock dex2oat binaries were discovered")
      setDex2OatFallback(true)
      return false
    }

    val wrapperPaths = arrayOfNulls<String>(2)
    for (i in 0 until 4) {
      if (dex2oatArray[i] == null) continue
      val arch = if (i < 2) 0 else 1
      if (wrapperPaths[arch] == null) {
        val relativePath = if (arch == 0) WRAPPER32 else WRAPPER64
        val wrapper =
            runCatching { File(relativePath).canonicalPath }.getOrNull()
        if (wrapper == null || !File(wrapper).isFile || !File(wrapper).canExecute()) {
          Log.e(TAG, "Vector dex2oat wrapper is missing or not executable: $relativePath")
          setDex2OatFallback(true)
          return false
        }
        wrapperPaths[arch] = wrapper
      }
    }

    // Check that the NoMount userspace/kernel interface is alive before installing rules.
    if (!runNoMount("version")) {
      setDex2OatFallback(true)
      return false
    }

    for (i in 0 until 4) {
      val target = dex2oatArray[i] ?: continue
      val wrapper = wrapperPaths[if (i < 2) 0 else 1]!!
      if (!runNoMount("rule", "add", target, wrapper)) {
        Log.e(TAG, "Failed to redirect $target to $wrapper")
        // Roll back partial installation rather than leaving only some compiler paths wrapped.
        for (rollback in 0 until 4) {
          dex2oatArray[rollback]?.let { runNoMount("rule", "del", it) }
        }
        setDex2OatFallback(true)
        return false
      }
    }

    setDex2OatFallback(false)
    return true
  }

  fun start() {
    if (!setRedirections(true)) {
      setRedirections(false)
      compatibility = DEX2OAT_MOUNT_FAILED
      return
    }

    SelinuxObserver.startWatching()
    onSelinuxEvent()

    // A permissive or incompatible SELinux policy disables the wrapper in onSelinuxEvent().
    if (compatibility != DEX2OAT_OK) return

    // Run the socket accept loop in an IO coroutine
    VectorDaemon.scope.launch { runSocketLoop() }
  }

  private fun runSocketLoop() {
    Log.i(TAG, "Dex2oat wrapper daemon start")
    val sockPath = getSockPath()
    Log.d(TAG, "wrapper path: $sockPath")

    val xposedFile = "u:object_r:xposed_file:s0"
    val dex2oatExec = "u:object_r:dex2oat_exec:s0"

    if (SELinux.checkSELinuxAccess("u:r:dex2oat:s0", dex2oatExec, "file", "execute_no_trans")) {
      SELinux.setFileContext(WRAPPER32, dex2oatExec)
      SELinux.setFileContext(WRAPPER64, dex2oatExec)
      setSockCreateContext("u:r:dex2oat:s0")
    } else {
      SELinux.setFileContext(WRAPPER32, xposedFile)
      SELinux.setFileContext(WRAPPER64, xposedFile)
      setSockCreateContext("u:r:installd:s0")
    }
    SELinux.setFileContext(HOOKER32, xposedFile)
    SELinux.setFileContext(HOOKER64, xposedFile)

    runCatching {
          // Closed by hand rather than with `use`: LocalServerSocket only implements Closeable
          // from API 28, and this daemon runs from 27. The client socket below has implemented it
          // since 17, so that one keeps `use`.
          val server = LocalServerSocket(sockPath)
          try {
            setSockCreateContext(null)
            while (true) {
              // This blocks until the C++ wrapper connects
              server.accept().use { client ->
                val input = client.inputStream
                val output = client.outputStream
                val id = input.read()
                if (id in fdArray.indices && fdArray[id] != null) {
                  client.setFileDescriptorsForSend(arrayOf(fdArray[id]!!))
                  output.write(1)
                }
              }
            }
          } finally {
            server.close()
          }
        }
        .onFailure {
          Log.e(TAG, "Dex2oat wrapper daemon crashed", it)
          if (compatibility == DEX2OAT_OK) {
            setRedirections(false)
            compatibility = DEX2OAT_CRASHED
          }
        }
  }
}
