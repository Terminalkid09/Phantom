"""The beacon must ship the SAME stealth/feature set on Linux and macOS.

Windows has always had real anti-analysis, a masked sleep and module hiding;
POSIX used to fall back to stubs (``is_vm(){return false;}`` etc.), which is
why a Linux/macOS beacon was materially weaker than a Windows one. These tests
pin the parity that closed that gap, and the *documented* Windows-only list so
nobody re-introduces a silent stub.
"""
import pathlib
import unittest

_SRC = pathlib.Path("phantom/payloads/beacon/src")


def _read(name: str) -> str:
    return (_SRC / name).read_text(encoding="utf-8")


class TestEvasionPosix(unittest.TestCase):
    def setUp(self):
        self.h = _read("evasion.h")

    def test_debugger_check_is_real_on_posix(self):
        # Linux: TracerPid in /proc/self/status. macOS: P_TRACED via sysctl.
        self.assertIn("/proc/self/status", self.h)
        self.assertIn("TracerPid:", self.h)
        self.assertIn("P_TRACED", self.h)
        self.assertIn("KERN_PROC_PID", self.h)
        # the old unconditional stub must be gone
        self.assertNotIn("inline bool is_debugger_present() { return false; }",
                         self.h)

    def test_vm_check_is_real_on_posix(self):
        # Linux: DMI vendor/product strings. macOS: kern.hv_vmm_present.
        self.assertIn("/sys/class/dmi/id/product_name", self.h)
        self.assertIn("hv_vmm_present", self.h)
        self.assertNotIn("inline bool is_vm() { return false; }", self.h)
        # hypervisor CPU bit is deliberately NOT the trigger (Hyper-V/WSL2/VBS)
        self.assertIn("virtual machine", self.h)

    def test_amsi_etw_are_documented_noops_not_hidden_stubs(self):
        # AMSI/ETW have no in-process POSIX equivalent; the header must SAY so.
        self.assertIn("inline void patch_amsi() {}", self.h)
        self.assertIn("inline void patch_etw() {}", self.h)
        self.assertIn("AMSI", self.h)
        self.assertIn("no-ops", self.h)

    def test_masquerade_uses_prctl_on_linux(self):
        self.assertIn("prctl(PR_SET_NAME", self.h)
        self.assertIn("<sys/prctl.h>", self.h)

    def test_masquerade_is_actually_wired(self):
        # rename_process() was defined on every platform (Windows PEB
        # `FullDllName` rewrite, Linux/Android prctl) and documented in
        # docs/beacon_platform_matrix.md, but never CALLED — so the whole
        # capability was inert. beacon_main must invoke it, once.
        main = _read("main.cpp")
        self.assertIn("anti::masquerade::rename_process(", main)

    def test_amsi_and_etw_patching_is_actually_wired(self):
        # patch_amsi()/patch_etw() have REAL Windows implementations
        # (AmsiScanBuffer / EtwEventWrite patches) and the platform matrix
        # declares both as a Windows capability — yet neither was ever
        # CALLED, so the documented capability was inert. beacon_main must
        # invoke both, under the same anti-analysis gate as the rest.
        main = _read("main.cpp")
        self.assertIn("anti::patch_amsi();", main)
        self.assertIn("anti::patch_etw();", main)


class TestSharedDefensiveDetection(unittest.TestCase):
    def setUp(self):
        self.h = _read("evasion.h")

    def test_detection_lives_in_one_shared_namespace(self):
        self.assertIn("namespace dfns {", self.h)
        self.assertIn("detect_defensive_services", self.h)
        self.assertIn("kDefensiveKeywords", self.h)
        # edrkill must consume the shared helper, not a private copy
        self.assertIn("dfns::detect_defensive_services()", self.h)


class TestEdrcheckPosix(unittest.TestCase):
    def setUp(self):
        self.h = _read("evasion.h")

    def test_posix_report_exists(self):
        self.assertIn("selinux_enforcing", self.h)
        self.assertIn("apparmor_enabled", self.h)
        self.assertIn("ebpf_programs", self.h)
        self.assertIn("audit_active", self.h)
        self.assertIn("sys_extensions", self.h)     # macOS EndpointSecurity
        self.assertIn("sip_enabled", self.h)        # macOS SIP
        self.assertIn("inline std::string format(const EdrReport& rep)", self.h)

    def test_main_no_longer_refuses_edrcheck_on_posix(self):
        main = _read("main.cpp")
        self.assertNotIn("edrcheck: windows only", main)
        self.assertIn("edrcheck::format(rep)", main)


class TestPosixSleepMask(unittest.TestCase):
    def setUp(self):
        self.h = _read("sleep_mask.h")

    def test_posix_masked_sleep_exists(self):
        # same entry point as the Windows Ekko path, so one call site works
        self.assertGreaterEqual(self.h.count("ekko_sleep_masked"), 2)
        self.assertIn("pthread_getattr_np", self.h)
        self.assertIn("nanosleep", self.h)
        self.assertIn("Rc4Context", self.h)
        # only the idle region below the live frames may be touched
        self.assertIn("__builtin_frame_address", self.h)

    def test_main_calls_masked_sleep_on_posix(self):
        main = _read("main.cpp")
        self.assertGreaterEqual(main.count("ekko::ekko_sleep_masked(jitter_sleep)"), 2)


class TestPosixModuleHiding(unittest.TestCase):
    def setUp(self):
        self.h = _read("peb_unlink.h")

    def test_linux_unlinks_from_link_map(self):
        self.assertIn("_r_debug.r_map", self.h)
        self.assertIn("dl_iterate_phdr", self.h)
        # bionic (Android) and dyld (macOS) have no writable link_map: the
        # glibc-only path must be gated so those builds never break.
        self.assertIn("PHANTOM_HAVE_LINK_MAP", self.h)
        self.assertIn("__ANDROID__", self.h)

    def test_macos_and_android_are_an_honest_noop(self):
        self.assertIn("inline bool hide_module() { return false; }", self.h)

    def test_main_includes_and_calls_it_outside_the_windows_guard(self):
        main = _read("main.cpp")
        # the header must be included on every platform, not inside #ifdef _WIN32
        self.assertIn('#include "peb_unlink.h"', main)
        self.assertGreaterEqual(main.count("peb_unlink::hide_module()"), 2)
        self.assertIn('#include "sleep_mask.h"', main)


class TestAndroidParity(unittest.TestCase):
    """Android is Linux, but NOT desktop Linux: the emulator tells differ."""

    def setUp(self):
        self.h = _read("evasion.h")

    def test_android_emulator_probes_exist(self):
        for needle in ("__ANDROID__", "/dev/qemu_pipe", "/dev/goldfish_pipe",
                       "ro.kernel.qemu", "goldfish", "ranchu",
                       "sys/system_properties.h"):
            self.assertIn(needle, self.h, needle)

    def test_android_emulator_check_uses_properties_and_qemu_paths(self):
        # The desktop DMI files are usually absent on Android images, so the
        # check must ask bionic for the properties directly.
        self.assertIn("__system_property_get", self.h)
        self.assertIn("access(path, F_OK)", self.h)
        # ...and it must be its OWN branch, not folded into the DMI #else.
        self.assertIn("#elif defined(__ANDROID__) || defined(ANDROID)", self.h)

    def test_debugger_and_masquerade_work_on_android(self):
        # TracerPid and prctl are available on every Android image.
        self.assertIn("TracerPid:", self.h)
        self.assertIn("prctl(PR_SET_NAME", self.h)

    def test_masked_sleep_documents_the_api_21_floor(self):
        sleep = _read("sleep_mask.h")
        self.assertIn("pthread_getattr_np", sleep)
        doc = pathlib.Path("docs/beacon_platform_matrix.md").read_text(
            encoding="utf-8")
        self.assertIn("API 21", doc)


class TestWindowsOnlyConceptsAreDocumented(unittest.TestCase):
    """These have no POSIX analogue and must stay inside #ifdef _WIN32."""

    WINDOWS_ONLY = ("syscalls.h", "apc_injection.h",
                    "smb.h", "ppid_spoof.h", "sleep_ekko.h",
                    "winhttp_dynamic.h", "wasapi_capture.h")

    def test_headers_are_windows_guarded(self):
        for name in self.WINDOWS_ONLY:
            text = _read(name)
            self.assertIn("_WIN32", text, f"{name} lost its Windows guard")

    def test_doc_matrix_lists_them(self):
        doc = pathlib.Path("docs/beacon_platform_matrix.md").read_text(
            encoding="utf-8")
        for name in self.WINDOWS_ONLY:
            self.assertIn(name, doc, name)
        # and points at the POSIX reality for the ones that DO exist now
        for feature in ("TracerPid", "kern.hv_vmm_present", "link_map",
                        "ekko_sleep_masked", "selinux"):
            self.assertIn(feature, doc, feature)

    def test_the_list_is_marked_as_accepted(self):
        doc = pathlib.Path("docs/beacon_platform_matrix.md").read_text(
            encoding="utf-8")
        self.assertIn("accepted", doc.lower())


class TestMatrixHasEveryPlatform(unittest.TestCase):
    """The contract table must name all four beacon targets."""

    def test_anti_analysis_table_covers_windows_linux_macos_android(self):
        doc = pathlib.Path("docs/beacon_platform_matrix.md").read_text(
            encoding="utf-8")
        rows = [line for line in doc.splitlines()
                if line.startswith("| Capability")]
        self.assertTrue(rows, "anti-analysis table missing")
        for platform in ("Windows", "Linux", "macOS", "Android"):
            self.assertIn(platform, rows[0], platform)
        # every data row must carry a value for each platform
        header = rows[0]
        columns = header.count("|")
        table = doc.splitlines()[doc.splitlines().index(header):]
        for line in table[2:]:
            if not line.startswith("|"):
                break
            self.assertEqual(line.count("|"), columns, line)


if __name__ == "__main__":
    unittest.main()
