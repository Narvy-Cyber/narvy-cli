"""Google Play readiness checks. Each check reads facts from the binary and
compares them to a requirement transcribed in data/play.py. A check never
infers intent: if the binary does not settle the question, the verdict is
"not_determined"."""
from __future__ import annotations

import datetime as dt
from typing import List, Optional, Tuple

from ..model import (BLOCKER, FAIL, INFO, NOT_APPLICABLE, NOT_DETERMINED, PASS, WARNING,
                     Evidence, Result, make)
from ..data import play as P
from .elf import ELFError, parse_elf_header
from .loader import AndroidApp
from .xmlmodel import Element, Value, K_BOOL, K_INT, K_REF, K_STRING

COMPONENT_TAGS = ("activity", "service", "receiver")


# ---------------------------------------------------------------- helpers
def _resolve(app: AndroidApp, v: Optional[Value], depth: int = 0) -> List[Value]:
    if v is None:
        return []
    if v.kind == K_REF and depth < 5:
        out: List[Value] = []
        for r in app.resolve(int(v.data)):
            out.extend(_resolve(app, r, depth + 1))
        return out
    return [v]


def resolve_bool(app: AndroidApp, v: Optional[Value]) -> Tuple[Optional[bool], str]:
    """(value, textual evidence). value None = absent or not determinable."""
    if v is None:
        return None, "absent"
    vals = _resolve(app, v)
    bools = set()
    for x in vals:
        if x.kind == K_BOOL:
            bools.add(bool(x.data))
        elif x.kind == K_STRING and str(x.data) in ("true", "false"):
            bools.add(str(x.data) == "true")
        elif x.kind == K_INT:
            bools.add(int(x.data) != 0)
        else:
            return None, f"unresolved value {v.as_text()}"
    if len(bools) == 1:
        b = bools.pop()
        txt = "true" if b else "false"
        return b, (txt if v.kind != K_REF else f"{v.as_text()} -> {txt}")
    if not bools:
        return None, f"unresolved reference {v.as_text()}"
    return None, f"{v.as_text()} differs between configurations"


def resolve_int(app: AndroidApp, v: Optional[Value]) -> Tuple[Optional[int], str]:
    if v is None:
        return None, "absent"
    vals = _resolve(app, v)
    ints = set()
    for x in vals:
        if x.kind == K_INT:
            ints.add(int(x.data))
        elif x.kind == K_STRING:
            try:
                ints.add(int(str(x.data), 0))
            except ValueError:
                return None, f"non-numeric value {x.data!r}"
        else:
            return None, f"unresolved value {v.as_text()}"
    if len(ints) == 1:
        return ints.pop(), v.as_text() if v.kind != K_REF else f"{v.as_text()} -> resolved"
    return None, f"unresolved value {v.as_text()}"


def application(app: AndroidApp) -> Optional[Element]:
    apps = app.manifest.find_children("application")
    return apps[0] if apps else None


def sdk_levels(app: AndroidApp) -> Tuple[Optional[int], Optional[int], str]:
    """(minSdk, targetSdk, evidence). Defaults follow the <uses-sdk> docs:
    minSdkVersion defaults to 1, targetSdkVersion defaults to minSdkVersion."""
    uses = app.manifest.find_children("uses-sdk")
    if not uses:
        return 1, 1, "<uses-sdk> absent (Android defaults: minSdkVersion=1, targetSdkVersion=minSdkVersion)"
    u = uses[0]
    mv = u.attr("minSdkVersion")
    tv = u.attr("targetSdkVersion")
    min_sdk, min_ev = resolve_int(app, mv) if mv is not None else (1, "absent (default 1)")
    if tv is None:
        return min_sdk, min_sdk, f"targetSdkVersion absent, defaults to minSdkVersion ({min_ev})"
    target, t_ev = resolve_int(app, tv)
    return min_sdk, target, f"targetSdkVersion={tv.as_text() if target is None else target}"


def requested_permissions(app: AndroidApp) -> List[Tuple[str, Element]]:
    out = []
    for tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
        for el in app.manifest.find_children(tag):
            n = el.attr("name")
            if n is not None and n.kind == K_STRING:
                out.append((str(n.data), el))
    return out


def _name(el: Element) -> str:
    n = el.attr("name")
    return str(n.data) if n is not None else "(unnamed)"


def _t(en: str, fr: str):
    return {"en": en, "fr": fr}


def _pl(n: int, one: str, many: str) -> str:
    return (one if n == 1 else many).format(n=n)


# ---------------------------------------------------------------- form factor
def form_factor(app: AndroidApp) -> Tuple[Optional[str], str]:
    feats = []
    for el in app.manifest.find_children("uses-feature"):
        n = el.attr("name")
        if n is None or n.kind != K_STRING:
            continue
        req, _ = resolve_bool(app, el.attr("required"))
        feats.append((str(n.data), True if req is None else req))
    required = {n for n, r in feats if r}
    if "android.hardware.type.watch" in required:
        return "wear", "uses-feature android.hardware.type.watch"
    if "android.hardware.type.automotive" in required:
        return "automotive", "uses-feature android.hardware.type.automotive"
    if "android.software.leanback" in required or "android.hardware.type.television" in required:
        return "tv", "uses-feature android.software.leanback / android.hardware.type.television (required)"
    if any(n.startswith("android.software.xr") for n in required):
        return None, "XR feature required: Google's XR target rule cannot be mapped from the manifest alone"
    return "phone", "no Wear OS / Automotive / TV required feature: phone and tablet rule"


# ---------------------------------------------------------------- checks
REQ_TARGET = _t("Target API level meets Google Play's current requirement",
                  "Le niveau d'API cible respecte l'exigence actuelle de Google Play")


def check_target_sdk(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-TARGET-SDK"
    _min, target, ev = sdk_levels(app)
    ff, ff_ev = form_factor(app)
    evid = [Evidence(app.manifest_path, ev), Evidence(app.manifest_path, ff_ev, "form factor")]
    if target is None:
        return make(cid, NOT_DETERMINED, BLOCKER, REQ_TARGET, P.TARGET_SDK_URL,
                    "The targetSdkVersion value could not be resolved to a number.",
                    "La valeur de targetSdkVersion n'a pas pu être résolue en nombre.", evid,
                    title=_t("Target API level not determined (targetSdkVersion unresolved)",
                             "Niveau d'API cible non déterminé (targetSdkVersion non résolu)"))
    if ff is None:
        return make(cid, NOT_DETERMINED, BLOCKER, REQ_TARGET, P.TARGET_SDK_URL,
                    f"targetSdkVersion is {target}, but the form factor rule that applies could not be determined.",
                    f"targetSdkVersion vaut {target}, mais la règle applicable au type d'appareil n'a pas pu être déterminée.",
                    evid, title=_t(f"Target API {target}: device type rule not determined",
                                   f"API cible {target} : règle du type d'appareil non déterminée"))
    req = P.target_requirement(as_of, ff)
    if req is None:
        return make(cid, NOT_APPLICABLE, BLOCKER, REQ_TARGET, P.TARGET_SDK_URL,
                    "No target API requirement is recorded for this date.",
                    "Aucune exigence de niveau d'API cible n'est enregistrée pour cette date.", evid,
                    title=_t("No Google Play target API requirement recorded for this date",
                             "Aucune exigence Google Play d'API cible enregistrée à cette date"))
    need, eff, ext = req
    if target >= need:
        return make(cid, PASS, BLOCKER, REQ_TARGET, P.TARGET_SDK_URL,
                    f"targetSdkVersion {target} meets the requirement (API {need} or higher since {eff.isoformat()}).",
                    f"targetSdkVersion {target} respecte l'exigence (API {need} minimum depuis le {eff.isoformat()}).",
                    evid, title=_t(f"Target API {target} meets Google Play's requirement (API {need})",
                                   f"API cible {target} conforme à l'exigence de Google Play (API {need})"))
    ext_en = ext_fr = ""
    if ext is not None and as_of < ext:
        ext_en = f" Google lets you request an extension until {ext.isoformat()}."
        ext_fr = f" Google permet de demander une prolongation jusqu'au {ext.isoformat()}."
    return make(cid, FAIL, BLOCKER, REQ_TARGET, P.TARGET_SDK_URL,
                f"targetSdkVersion is {target}. Since {eff.isoformat()}, new apps and app updates must target "
                f"API {need} or higher to be submitted to Google Play.{ext_en}",
                f"targetSdkVersion vaut {target}. Depuis le {eff.isoformat()}, les nouvelles applications et les "
                f"mises à jour doivent cibler l'API {need} ou plus pour être soumises sur Google Play.{ext_fr}",
                evid, title=_t(f"Target API {target} is below Google Play's requirement (API {need})",
                               f"API cible {target} inférieure à l'exigence de Google Play (API {need})"))


REQ_16KB = _t("Native libraries support 16 KB memory pages (ELF alignment)",
                "Les bibliothèques natives supportent les pages mémoire de 16 Ko (alignement ELF)")


def check_16kb_elf(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-16KB-ELF"
    libs = [lib for lib in app.native_libs if lib.abi in P.PAGE_SIZE_ABIS]
    if not libs:
        abis = sorted({lib.abi for lib in app.native_libs})
        txt = ", ".join(abis) if abis else "none"
        return make(cid, PASS, WARNING, REQ_16KB, P.PAGE_SIZE_URL,
                    "No 64-bit (arm64-v8a, x86_64) native library in this file: nothing to align.",
                    "Aucune bibliothèque native 64 bits (arm64-v8a, x86_64) dans ce fichier : rien à aligner.",
                    [Evidence("lib/", f"ABIs present: {txt}")],
                    title=_t("No 64-bit native library to align for 16 KB pages",
                             "Aucune bibliothèque native 64 bits à aligner pour les pages de 16 Ko"))
    bad: List[Evidence] = []
    unknown: List[Evidence] = []
    skipped: List[Evidence] = []
    good = 0
    for lib in libs:
        try:
            head = lib.read_head(65536)
            if head[:4] != b"\x7fELF":
                # Not loaded by the system dynamic linker (Google's check script only inspects ELF files).
                skipped.append(Evidence(lib.display, "not an ELF file, skipped", f"magic {head[:4].hex()}"))
                continue
            try:
                info = parse_elf_header(head)
            except ELFError:
                head = lib.read_head(min(lib.size, 8 * 1024 * 1024))
                info = parse_elf_header(head)
        except (ELFError, Exception) as exc:  # noqa: BLE001
            unknown.append(Evidence(lib.display, "unreadable", str(exc)[:200]))
            continue
        if info.elf_class != 2:
            unknown.append(Evidence(lib.display, "not a 64-bit ELF in a 64-bit ABI directory"))
            continue
        if not info.loads:
            unknown.append(Evidence(lib.display, "no PT_LOAD segment"))
            continue
        m = info.min_load_align
        if m < P.PAGE_SIZE_ALIGN:
            bad.append(Evidence(lib.display, f"min LOAD p_align = {m} (2**{m.bit_length() - 1 if m else 0})",
                                "required: 16384 (2**14)"))
        else:
            good += 1
    _min, target, _ = sdk_levels(app)
    enforced = as_of >= P.PAGE_SIZE_ENFORCED and target is not None and target >= P.PAGE_SIZE_TARGET_SDK
    sev = BLOCKER if enforced else WARNING
    if bad:
        when_en = ("Google Play blocks such updates since 2027-02-01." if enforced else
                   "From 2027-02-01, Google Play will block updates of apps targeting API 35+ that do not support 16 KB pages.")
        when_fr = ("Google Play bloque ces mises à jour depuis le 2027-02-01." if enforced else
                   "À partir du 2027-02-01, Google Play bloquera les mises à jour des applications ciblant l'API 35+ "
                   "qui ne supportent pas les pages de 16 Ko.")
        return make(cid, FAIL, sev, REQ_16KB, P.PAGE_SIZE_URL,
                    f"{len(bad)} of {len(libs)} 64-bit native libraries have a LOAD segment aligned below 16 KB. "
                    f"They will not load on 16 KB page devices. {when_en}",
                    f"{len(bad)} bibliothèque(s) native(s) 64 bits sur {len(libs)} ont un segment LOAD aligné sous 16 Ko. "
                    f"Elles ne se chargeront pas sur les appareils à pages de 16 Ko. {when_fr}",
                    bad + unknown + skipped,
                    title=_t(f"64-bit native libraries not aligned for 16 KB pages: {len(bad)} of {len(libs)}",
                             f"Bibliothèques natives 64 bits non alignées pour les pages de 16 Ko : {len(bad)} sur {len(libs)}"))
    if unknown:
        return make(cid, NOT_DETERMINED, sev, REQ_16KB, P.PAGE_SIZE_URL,
                    f"{good} libraries are aligned, {len(unknown)} could not be read.",
                    f"{good} bibliothèque(s) alignée(s), {len(unknown)} illisible(s).", unknown + skipped,
                    title=_t(_pl(len(unknown), "16 KB alignment not determined: {n} native library unreadable",
                                 "16 KB alignment not determined: {n} native libraries unreadable"),
                             _pl(len(unknown), "Alignement 16 Ko non déterminé : {n} bibliothèque native illisible",
                                 "Alignement 16 Ko non déterminé : {n} bibliothèques natives illisibles")))
    if good == 0:
        return make(cid, PASS, sev, REQ_16KB, P.PAGE_SIZE_URL,
                    "No 64-bit ELF native library to check.", "Aucune bibliothèque native ELF 64 bits à vérifier.", skipped,
                    title=_t("No 64-bit ELF native library to align for 16 KB pages",
                             "Aucune bibliothèque native ELF 64 bits à aligner pour les pages de 16 Ko"))
    return make(cid, PASS, sev, REQ_16KB, P.PAGE_SIZE_URL,
                f"All {good} 64-bit native libraries have LOAD segments aligned to 16 KB or more.",
                f"Les {good} bibliothèques natives 64 bits ont des segments LOAD alignés sur 16 Ko ou plus.",
                skipped + [Evidence(lib.display, "aligned") for lib in libs[:20]],
                title=_t(f"64-bit native libraries aligned for 16 KB pages: {good} of {good}",
                         f"Bibliothèques natives 64 bits alignées pour les pages de 16 Ko : {good} sur {good}"))


REQ_ZIP = _t("Uncompressed native libraries are 16 KB zip-aligned",
               "Les bibliothèques natives non compressées sont alignées à 16 Ko dans l'archive")


def check_16kb_zipalign(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-16KB-ZIPALIGN"
    if not app.zip_alignment_relevant:
        return make(cid, NOT_APPLICABLE, WARNING, REQ_ZIP, P.PAGE_SIZE_URL,
                    "App bundle: Google Play generates and aligns the APKs itself.",
                    "App Bundle : Google Play génère et aligne lui-même les APK.",
                    title=_t("App bundle: Google Play aligns the APKs it generates",
                             "App Bundle : Google Play aligne lui-même les APK qu'il génère"))
    libs = [lib for lib in app.native_libs if lib.abi in P.PAGE_SIZE_ABIS and lib.stored]
    if not libs:
        return make(cid, NOT_APPLICABLE, WARNING, REQ_ZIP, P.PAGE_SIZE_URL,
                    "No uncompressed 64-bit native library in this file.",
                    "Aucune bibliothèque native 64 bits non compressée dans ce fichier.",
                    title=_t("No uncompressed 64-bit native library to zip-align",
                             "Aucune bibliothèque native 64 bits non compressée à aligner dans l'archive"))
    a = application(app)
    extract, ev = resolve_bool(app, a.attr("extractNativeLibs") if a is not None else None)
    if extract is None and ev != "absent":
        return make(cid, NOT_DETERMINED, WARNING, REQ_ZIP, P.PAGE_SIZE_URL,
                    "android:extractNativeLibs could not be resolved.",
                    "android:extractNativeLibs n'a pas pu être résolu.",
                    [Evidence(app.manifest_path, ev, "application@extractNativeLibs")],
                    title=_t("16 KB zip alignment not determined (extractNativeLibs unresolved)",
                             "Alignement 16 Ko dans l'archive non déterminé (extractNativeLibs non résolu)"))
    if extract is None or extract:
        return make(cid, NOT_APPLICABLE, WARNING, REQ_ZIP, P.PAGE_SIZE_URL,
                    "Native libraries are extracted at install time (extractNativeLibs is true or absent), so their "
                    "position inside the APK does not matter.",
                    "Les bibliothèques natives sont extraites à l'installation (extractNativeLibs vaut true ou est absent), "
                    "leur position dans l'APK n'a donc pas d'importance.",
                    [Evidence(app.manifest_path, ev, "application@extractNativeLibs")],
                    title=_t("Native libraries extracted at install: zip alignment does not apply",
                             "Bibliothèques natives extraites à l'installation : alignement dans l'archive sans objet"))
    bad = [Evidence(lib.display, f"data offset {lib.data_offset} (offset mod 16384 = {lib.data_offset % 16384})")
           for lib in libs if lib.data_offset is not None and lib.data_offset % P.PAGE_SIZE_ALIGN != 0]
    unknown = [Evidence(lib.display, "data offset unreadable") for lib in libs if lib.data_offset is None]
    _min, target, _ = sdk_levels(app)
    enforced = as_of >= P.PAGE_SIZE_ENFORCED and target is not None and target >= P.PAGE_SIZE_TARGET_SDK
    sev = BLOCKER if enforced else WARNING
    if bad:
        return make(cid, FAIL, sev, REQ_ZIP, P.PAGE_SIZE_URL,
                    f"{len(bad)} uncompressed 64-bit native libraries are not 16 KB aligned inside the APK while "
                    "extractNativeLibs is false (zipalign -c -P 16 would fail). Build with AGP 8.5.1+ or zipalign -P 16.",
                    f"{len(bad)} bibliothèque(s) native(s) 64 bits non compressée(s) ne sont pas alignées à 16 Ko dans l'APK "
                    "alors que extractNativeLibs vaut false (zipalign -c -P 16 échouerait). Compilez avec AGP 8.5.1+ "
                    "ou zipalign -P 16.", bad,
                    title=_t(_pl(len(bad), "{n} uncompressed native library not 16 KB zip-aligned",
                                 "{n} uncompressed native libraries not 16 KB zip-aligned"),
                             _pl(len(bad), "{n} bibliothèque native non compressée non alignée à 16 Ko dans l'archive",
                                 "{n} bibliothèques natives non compressées non alignées à 16 Ko dans l'archive")))
    if unknown:
        return make(cid, NOT_DETERMINED, sev, REQ_ZIP, P.PAGE_SIZE_URL,
                    "Some library offsets could not be read.", "Certains décalages de bibliothèques n'ont pas pu être lus.",
                    unknown, title=_t("16 KB zip alignment not determined (library offsets unreadable)",
                                      "Alignement 16 Ko dans l'archive non déterminé (décalages illisibles)"))
    return make(cid, PASS, sev, REQ_ZIP, P.PAGE_SIZE_URL,
                f"All {len(libs)} uncompressed 64-bit native libraries are 16 KB aligned.",
                f"Les {len(libs)} bibliothèques natives 64 bits non compressées sont alignées à 16 Ko.",
                title=_t(_pl(len(libs), "The uncompressed native library is 16 KB zip-aligned",
                             "All {n} uncompressed native libraries are 16 KB zip-aligned"),
                         _pl(len(libs), "La bibliothèque native non compressée est alignée à 16 Ko dans l'archive",
                             "Les {n} bibliothèques natives non compressées sont alignées à 16 Ko dans l'archive")))


REQ_EXPORTED = _t("Components with intent filters declare android:exported (targetSdk 31+)",
                    "Les composants avec intent-filter déclarent android:exported (targetSdk 31+)")


def check_exported(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-EXPORTED"
    a = application(app)
    comps = []
    if a is not None:
        for c in a.children:
            if c.tag in COMPONENT_TAGS and c.find_children("intent-filter"):
                comps.append(c)
    _min, target, t_ev = sdk_levels(app)
    if not comps:
        return make(cid, NOT_APPLICABLE, BLOCKER, REQ_EXPORTED, P.EXPORTED_URL,
                    "No activity, service or receiver with an intent filter.",
                    "Aucune activité, service ou receiver avec intent-filter.",
                    title=_t("No component with an intent filter", "Aucun composant avec intent-filter"))
    if target is None:
        return make(cid, NOT_DETERMINED, BLOCKER, REQ_EXPORTED, P.EXPORTED_URL,
                    "targetSdkVersion could not be resolved.", "targetSdkVersion n'a pas pu être résolu.",
                    [Evidence(app.manifest_path, t_ev)],
                    title=_t("android:exported rule not determined (targetSdkVersion unresolved)",
                             "Règle android:exported non déterminée (targetSdkVersion non résolu)"))
    if target < 31:
        return make(cid, NOT_APPLICABLE, BLOCKER, REQ_EXPORTED, P.EXPORTED_URL,
                    f"targetSdkVersion {target} < 31: the explicit android:exported rule does not apply.",
                    f"targetSdkVersion {target} < 31 : la règle android:exported explicite ne s'applique pas.",
                    [Evidence(app.manifest_path, t_ev)],
                    title=_t(f"Target API {target}: explicit android:exported not required (31+)",
                             f"API cible {target} : android:exported explicite non exigé (31+)"))
    missing = [c for c in comps if c.attr("exported") is None]
    if missing:
        ev = [Evidence(app.manifest_path, f"<{c.tag} android:name=\"{_name(c)}\">", "has <intent-filter>, no android:exported")
              for c in missing]
        return make(cid, FAIL, BLOCKER, REQ_EXPORTED, P.EXPORTED_URL,
                    f"{len(missing)} component(s) use intent filters without an explicit android:exported. "
                    "With targetSdk 31+, the app cannot be installed on Android 12 or higher.",
                    f"{len(missing)} composant(s) utilisent des intent-filter sans android:exported explicite. "
                    "Avec targetSdk 31+, l'application ne peut pas être installée sur Android 12 ou plus.", ev,
                    title=_t(_pl(len(missing), "{n} component with an intent filter lacks android:exported",
                                 "{n} components with intent filters lack android:exported"),
                             _pl(len(missing), "{n} composant avec intent-filter sans android:exported",
                                 "{n} composants avec intent-filter sans android:exported")))
    return make(cid, PASS, BLOCKER, REQ_EXPORTED, P.EXPORTED_URL,
                f"All {len(comps)} components with intent filters declare android:exported.",
                f"Les {len(comps)} composants avec intent-filter déclarent android:exported.",
                title=_t(_pl(len(comps), "The component with an intent filter declares android:exported",
                             "All {n} components with intent filters declare android:exported"),
                         _pl(len(comps), "Le composant avec intent-filter déclare android:exported",
                             "Les {n} composants avec intent-filter déclarent android:exported")))


def _fgs_types(app: AndroidApp, svc: Element) -> Tuple[Optional[List[str]], str]:
    v = svc.attr("foregroundServiceType")
    if v is None:
        return [], "absent"
    vals = _resolve(app, v)
    if len(vals) != 1:
        return None, f"unresolved {v.as_text()}"
    x = vals[0]
    if x.kind == K_INT:
        mask = int(x.data) & 0xFFFFFFFF
        names = [n for bit, n in sorted(P.FGS_FLAGS.items()) if mask & bit]
        unknown_bits = mask & ~sum(P.FGS_FLAGS)
        if unknown_bits:
            return None, f"unknown flag bits 0x{unknown_bits:x}"
        return names, "|".join(names) or "0"
    if x.kind == K_STRING:
        names = [s.strip() for s in str(x.data).split("|") if s.strip()]
        known = set(P.FGS_FLAGS.values())
        if all(n in known for n in names):
            return names, "|".join(names)
    return None, f"unparsed {v.as_text()}"


REQ_FGS = _t("Foreground services declare a type (Android 14, targetSdk 34+)",
               "Les services de premier plan déclarent un type (Android 14, targetSdk 34+)")
REQ_FGS_PERM = _t("Each foreground service type has its matching permission",
                    "Chaque type de service de premier plan a sa permission associée")
REQ_FGS_DECL = _t("Foreground service types need a Play Console declaration",
                    "Les types de services de premier plan exigent une déclaration dans la Play Console")


def check_fgs(app: AndroidApp, as_of: dt.date) -> List[Result]:
    _min, target, t_ev = sdk_levels(app)
    perms = {p for p, _ in requested_permissions(app)}
    a = application(app)
    services = a.find_children("service") if a is not None else []
    typed: List[Tuple[Element, List[str], str]] = []
    unresolved: List[Evidence] = []
    for s in services:
        types, ev = _fgs_types(app, s)
        if types is None:
            unresolved.append(Evidence(app.manifest_path, f"<service android:name=\"{_name(s)}\">", ev))
        elif types:
            typed.append((s, types, ev))
    has_fgs_perm = "android.permission.FOREGROUND_SERVICE" in perms
    out: List[Result] = []
    if target is None:
        for cid, req, url, title in (
                ("PLAY-FGS-TYPE", REQ_FGS, P.FGS_URL,
                 _t("Foreground service types not determined (targetSdkVersion unresolved)",
                    "Types de services de premier plan non déterminés (targetSdkVersion non résolu)")),
                ("PLAY-FGS-PERMISSION", REQ_FGS_PERM, P.FGS_TYPES_URL,
                 _t("Foreground service permissions not determined (targetSdkVersion unresolved)",
                    "Permissions des services de premier plan non déterminées (targetSdkVersion non résolu)")),
                ("PLAY-FGS-DECLARATION", REQ_FGS_DECL, P.FGS_PLAY_URL,
                 _t("Foreground service declaration not determined (targetSdkVersion unresolved)",
                    "Déclaration des services de premier plan non déterminée (targetSdkVersion non résolu)"))):
            out.append(make(cid, NOT_DETERMINED, WARNING if cid == "PLAY-FGS-DECLARATION" else INFO, req, url,
                            "targetSdkVersion could not be resolved.",
                            "targetSdkVersion n'a pas pu être résolu.", [Evidence(app.manifest_path, t_ev)], title=title))
        return out
    if target < 34:
        for cid, req, url, title in (
                ("PLAY-FGS-TYPE", REQ_FGS, P.FGS_URL,
                 _t(f"Target API {target}: foreground service types not required (34+)",
                    f"API cible {target} : types de services de premier plan non exigés (34+)")),
                ("PLAY-FGS-PERMISSION", REQ_FGS_PERM, P.FGS_TYPES_URL,
                 _t(f"Target API {target}: foreground service type permissions not required (34+)",
                    f"API cible {target} : permissions par type de service de premier plan non exigées (34+)")),
                ("PLAY-FGS-DECLARATION", REQ_FGS_DECL, P.FGS_PLAY_URL,
                 _t(f"Target API {target}: no foreground service declaration required (34+)",
                    f"API cible {target} : aucune déclaration de services de premier plan exigée (34+)"))):
            out.append(make(cid, NOT_APPLICABLE, WARNING if cid == "PLAY-FGS-DECLARATION" else INFO, req, url,
                            f"targetSdkVersion {target} < 34: foreground service type rules do not apply.",
                            f"targetSdkVersion {target} < 34 : les règles de type de service de premier plan ne s'appliquent pas.",
                            title=title))
        return out

    # 1. FOREGROUND_SERVICE requested but no service declares any type
    if not has_fgs_perm:
        out.append(make("PLAY-FGS-TYPE", NOT_APPLICABLE, INFO, REQ_FGS, P.FGS_URL,
                        "The app does not request android.permission.FOREGROUND_SERVICE.",
                        "L'application ne demande pas android.permission.FOREGROUND_SERVICE.",
                        title=_t("FOREGROUND_SERVICE not requested", "FOREGROUND_SERVICE non demandée")))
    elif typed:
        out.append(make("PLAY-FGS-TYPE", PASS, INFO, REQ_FGS, P.FGS_URL,
                        f"{len(typed)} service(s) declare android:foregroundServiceType.",
                        f"{len(typed)} service(s) déclarent android:foregroundServiceType.",
                        [Evidence(app.manifest_path, f"{_name(s)}: {ev}") for s, _t2, ev in typed],
                        title=_t(_pl(len(typed), "{n} service declares a foreground service type",
                                     "{n} services declare a foreground service type"),
                                 _pl(len(typed), "{n} service déclare un type de service de premier plan",
                                     "{n} services déclarent un type de service de premier plan"))))
    elif unresolved:
        out.append(make("PLAY-FGS-TYPE", NOT_DETERMINED, INFO, REQ_FGS, P.FGS_URL,
                        "Some foregroundServiceType values could not be resolved.",
                        "Certaines valeurs de foregroundServiceType n'ont pas pu être résolues.", unresolved,
                        title=_t("Foreground service types not determined (values unresolved)",
                                 "Types de services de premier plan non déterminés (valeurs non résolues)")))
    else:
        out.append(make("PLAY-FGS-TYPE", FAIL, INFO, REQ_FGS, P.FGS_URL,
                        "The app requests FOREGROUND_SERVICE and targets API 34+, but no <service> declares "
                        "android:foregroundServiceType, so no service can run in the foreground on Android 14+ "
                        "(startForeground throws MissingForegroundServiceTypeException). Either the permission is "
                        "unused and can be removed, or a foreground service is missing its type.",
                        "L'application demande FOREGROUND_SERVICE et cible l'API 34+, mais aucun <service> ne déclare "
                        "android:foregroundServiceType : aucun service ne peut donc tourner au premier plan sur Android 14+ "
                        "(startForeground lève MissingForegroundServiceTypeException). Soit la permission est inutilisée "
                        "et peut être retirée, soit un service de premier plan n'a pas son type.",
                        [Evidence(app.manifest_path, "android.permission.FOREGROUND_SERVICE", "uses-permission"),
                         Evidence(app.manifest_path, f"{len(services)} <service> element(s), none with foregroundServiceType")],
                        title=_t("FOREGROUND_SERVICE requested, no service declares a type",
                                 "FOREGROUND_SERVICE demandée, aucun service ne déclare de type")))

    # 2. per-type permission
    missing: List[Evidence] = []
    for s, types, _ev in typed:
        if not has_fgs_perm:
            missing.append(Evidence(app.manifest_path, f"{_name(s)}", "android.permission.FOREGROUND_SERVICE not requested"))
        for t in types:
            perm = P.FGS_PERMISSION.get(t)
            if perm and perm not in perms:
                missing.append(Evidence(app.manifest_path, f"{_name(s)}: type {t}", f"{perm} not requested"))
    if not typed:
        out.append(make("PLAY-FGS-PERMISSION", NOT_APPLICABLE, INFO, REQ_FGS_PERM, P.FGS_TYPES_URL,
                        "No service declares a foreground service type.",
                        "Aucun service ne déclare de type de service de premier plan.",
                        title=_t("No foreground service type declared", "Aucun type de service de premier plan déclaré")))
    elif missing:
        out.append(make("PLAY-FGS-PERMISSION", FAIL, INFO, REQ_FGS_PERM, P.FGS_TYPES_URL,
                        "Some services declare a foreground service type without the matching FOREGROUND_SERVICE_* "
                        "permission. If the app starts one of them in the foreground with that type, Android 14+ throws a "
                        "SecurityException. Services declared by libraries often list types the app never uses.",
                        "Certains services déclarent un type de service de premier plan sans la permission "
                        "FOREGROUND_SERVICE_* correspondante. Si l'application en démarre un au premier plan avec ce type, "
                        "Android 14+ lève une SecurityException. Les services déclarés par des bibliothèques listent souvent "
                        "des types que l'application n'utilise jamais.", missing,
                        title=_t("Foreground service types declared without their permission",
                                 "Types de services de premier plan déclarés sans leur permission")))
    else:
        out.append(make("PLAY-FGS-PERMISSION", PASS, INFO, REQ_FGS_PERM, P.FGS_TYPES_URL,
                        "Every declared foreground service type has its permission.",
                        "Chaque type de service de premier plan déclaré a sa permission.",
                        title=_t("Each foreground service type has its permission",
                                 "Chaque type de service de premier plan a sa permission")))

    # 3. Play Console declaration
    if typed:
        all_types = sorted({t for _s, ts, _e in typed for t in ts})
        short = ", ".join(all_types[:3]) + (f" +{len(all_types) - 3}" if len(all_types) > 3 else "")
        out.append(make("PLAY-FGS-DECLARATION", FAIL, WARNING, REQ_FGS_DECL, P.FGS_PLAY_URL,
                        f"The app targets API 34+ and declares foreground service types ({', '.join(all_types)}). "
                        "Google Play requires a foreground service declaration in Play Console (App content) for them.",
                        f"L'application cible l'API 34+ et déclare des types de services de premier plan ({', '.join(all_types)}). "
                        "Google Play exige une déclaration des services de premier plan dans la Play Console (Contenu de l'application).",
                        [Evidence(app.manifest_path, f"{_name(s)}: {ev}") for s, _t2, ev in typed],
                        [P.FGS_TYPES_URL],
                        title=_t(f"Play Console declaration needed for foreground service types ({short})",
                                 f"Déclaration Play Console exigée pour les types de services de premier plan ({short})")))
    else:
        out.append(make("PLAY-FGS-DECLARATION", NOT_APPLICABLE, WARNING, REQ_FGS_DECL, P.FGS_PLAY_URL,
                        "No foreground service type declared.", "Aucun type de service de premier plan déclaré.",
                        title=_t("No foreground service type to declare", "Aucun type de service de premier plan à déclarer")))
    return out


REQ_PERMS = _t("Permissions that need a Play Console declaration",
                 "Permissions qui exigent une déclaration dans la Play Console")


def check_permission_declarations(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-PERMISSION-DECLARATION"
    _min, target, _ = sdk_levels(app)
    ev: List[Evidence] = []
    groups = []
    urls = []
    for perm, el in requested_permissions(app):
        spec = P.DECLARED_PERMISSIONS.get(perm)
        if spec is None and perm.startswith(P.HEALTH_PERMISSION_PREFIX):
            spec = ("Health Connect", P.HEALTH_URL, None)
        if spec is None:
            continue
        group, url, cond = spec
        if cond == "target34" and (target is None or target < 34):
            continue
        mx = el.attr("maxSdkVersion")
        detail = f"group: {group}" + (f"; maxSdkVersion={mx.as_text()}" if mx is not None else "")
        ev.append(Evidence(app.manifest_path, perm, detail))
        if group not in groups:
            groups.append(group)
        if url not in urls:
            urls.append(url)
    a = application(app)
    if a is not None:
        for s in a.find_children("service"):
            p = s.attr("permission")
            if p is not None and p.kind == K_STRING and str(p.data) == P.ACCESSIBILITY_BIND:
                ev.append(Evidence(app.manifest_path, f"<service android:name=\"{_name(s)}\">",
                                   "android:permission=BIND_ACCESSIBILITY_SERVICE (AccessibilityService API)"))
                if "AccessibilityService API" not in groups:
                    groups.append("AccessibilityService API")
                if P.ACCESSIBILITY_URL not in urls:
                    urls.append(P.ACCESSIBILITY_URL)
    if not ev:
        return make(cid, PASS, WARNING, REQ_PERMS, P.PERMISSIONS_POLICY_URL,
                    "No permission that requires a Play Console declaration form.",
                    "Aucune permission nécessitant un formulaire de déclaration dans la Play Console.",
                    title=_t("No permission needs a Play Console declaration",
                             "Aucune permission n'exige de déclaration dans la Play Console"))
    g = ", ".join(groups)
    return make(cid, FAIL, WARNING, REQ_PERMS, P.PERMISSIONS_POLICY_URL,
                f"Needs a Play Console declaration: the app requests restricted permissions or APIs ({g}). "
                "Complete the permissions declaration form; undeclared or non-compliant use leads to rejection.",
                f"Déclaration Play Console nécessaire : l'application demande des permissions ou API restreintes ({g}). "
                "Remplissez le formulaire de déclaration des permissions ; un usage non déclaré ou non conforme entraîne un refus.",
                ev, [P.DECLARATION_FORM_URL] + urls,
                title=_t(f"Play Console declaration needed: {g}", f"Déclaration Play Console exigée : {g}"))


REQ_DEBUG = _t("Release build is not debuggable", "Le build de release n'est pas débogable")


def check_debuggable(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-DEBUGGABLE"
    a = application(app)
    v = a.attr("debuggable") if a is not None else None
    b, ev = resolve_bool(app, v)
    evid = [Evidence(app.manifest_path, ev, "application@android:debuggable")]
    if v is not None and b is None:
        return make(cid, NOT_DETERMINED, BLOCKER, REQ_DEBUG, P.DEBUGGABLE_URL,
                    "android:debuggable is set but its value could not be resolved.",
                    "android:debuggable est défini mais sa valeur n'a pas pu être résolue.", evid,
                    title=_t("Debuggable flag not determined (android:debuggable unresolved)",
                             "Statut débogable non déterminé (android:debuggable non résolu)"))
    if b:
        return make(cid, FAIL, BLOCKER, REQ_DEBUG, P.DEBUGGABLE_URL,
                    "android:debuggable is true. Google Play rejects debuggable APKs and app bundles.",
                    "android:debuggable vaut true. Google Play refuse les APK et App Bundles débogables.", evid,
                    title=_t("Build is debuggable (android:debuggable=true)", "Build débogable (android:debuggable=true)"))
    return make(cid, PASS, BLOCKER, REQ_DEBUG, P.DEBUGGABLE_URL,
                "The app is not debuggable.", "L'application n'est pas débogable.", evid,
                title=_t("Build is not debuggable", "Build non débogable"))


REQ_CLEARTEXT = _t("Cleartext (HTTP) traffic is not allowed globally",
                     "Le trafic en clair (HTTP) n'est pas autorisé globalement")


def check_cleartext(app: AndroidApp, as_of: dt.date) -> Result:
    cid = "PLAY-CLEARTEXT"
    a = application(app)
    _min, target, t_ev = sdk_levels(app)
    if target is None:
        return make(cid, NOT_DETERMINED, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                    "targetSdkVersion could not be resolved, so the platform default is unknown.",
                    "targetSdkVersion n'a pas pu être résolu, la valeur par défaut de la plateforme est donc inconnue.",
                    [Evidence(app.manifest_path, t_ev)],
                    title=_t("Cleartext policy not determined (targetSdkVersion unresolved)",
                             "Politique de trafic en clair non déterminée (targetSdkVersion non résolu)"))
    default_allowed = target <= 27
    nsc_attr = a.attr("networkSecurityConfig") if a is not None else None
    if nsc_attr is not None and nsc_attr.kind == K_REF and int(nsc_attr.data) == 0:
        nsc_attr = None  # @null: no network security config
    if nsc_attr is not None:
        vals = _resolve(app, nsc_attr)
        paths = sorted({str(x.data) for x in vals if x.kind == K_STRING})
        if not paths:
            return make(cid, NOT_DETERMINED, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                        "A network security config is referenced but could not be located.",
                        "Une configuration de sécurité réseau est référencée mais n'a pas pu être trouvée.",
                        [Evidence(app.manifest_path, nsc_attr.as_text(), "application@android:networkSecurityConfig")],
                        title=_t("Cleartext policy not determined (network security config not found)",
                                 "Politique de trafic en clair non déterminée (configuration de sécurité réseau introuvable)"))
        base_allowed_files = []
        domains: List[str] = []
        for path in paths:
            try:
                root = app.read_xml(path)
            except Exception as exc:  # noqa: BLE001
                return make(cid, NOT_DETERMINED, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                            f"The network security config {path} could not be parsed.",
                            f"La configuration de sécurité réseau {path} n'a pas pu être analysée.",
                            [Evidence(path, str(exc)[:200])],
                            title=_t("Cleartext policy not determined (network security config unreadable)",
                                     "Politique de trafic en clair non déterminée (configuration de sécurité réseau illisible)"))
            base_allowed = default_allowed
            for bc in root.find_children("base-config"):
                v = bc.attr("cleartextTrafficPermitted", android_only=False)
                if v is not None:
                    b, _ = resolve_bool(app, v)
                    if b is None:
                        return make(cid, NOT_DETERMINED, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                                    "base-config cleartextTrafficPermitted could not be resolved.",
                                    "base-config cleartextTrafficPermitted n'a pas pu être résolu.", [Evidence(path, v.as_text())],
                                    title=_t("Cleartext policy not determined (base-config value unresolved)",
                                             "Politique de trafic en clair non déterminée (valeur de base-config non résolue)"))
                    base_allowed = b
            if base_allowed:
                base_allowed_files.append(path)
            for dc in root.iter("domain-config"):
                v = dc.attr("cleartextTrafficPermitted", android_only=False)
                b, _ = resolve_bool(app, v) if v is not None else (None, "")
                if b:
                    for d in dc.find_children("domain"):
                        domains.append(d.text.strip() or "(empty domain)")
        if base_allowed_files:
            return make(cid, FAIL, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                        "The network security config allows cleartext HTTP by default (base-config), for every domain not "
                        "restricted by a domain-config. "
                        "Not a Play upload blocker, but traffic can be read or modified on the network.",
                        "La configuration de sécurité réseau autorise le HTTP en clair par défaut (base-config), pour tout domaine "
                        "non restreint par un domain-config. "
                        "Ce n'est pas bloquant pour Google Play, mais le trafic peut être lu ou modifié sur le réseau.",
                        [Evidence(p, "base-config cleartextTrafficPermitted=true" + (" (platform default)" if default_allowed else ""))
                         for p in base_allowed_files],
                        title=_t("Cleartext HTTP allowed by default (network security config)",
                                 "HTTP en clair autorisé par défaut (configuration de sécurité réseau)"))
        if domains:
            return make(cid, FAIL, INFO, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                        f"Cleartext HTTP is allowed only for specific domains ({len(domains)} domain entries).",
                        f"Le HTTP en clair est autorisé uniquement pour certains domaines ({len(domains)} entrées).",
                        [Evidence(paths[0] if len(paths) == 1 else ",".join(paths), d, "domain-config cleartextTrafficPermitted=true")
                         for d in domains[:50]],
                        title=_t(_pl(len(domains), "Cleartext HTTP allowed for {n} domain",
                                     "Cleartext HTTP allowed for {n} domains"),
                                 _pl(len(domains), "HTTP en clair autorisé pour {n} domaine",
                                     "HTTP en clair autorisé pour {n} domaines")))
        return make(cid, PASS, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_URL,
                    "The network security config does not allow cleartext traffic.",
                    "La configuration de sécurité réseau n'autorise pas le trafic en clair.", [Evidence(p, "checked") for p in paths],
                    title=_t("Cleartext HTTP not allowed (network security config)",
                             "HTTP en clair non autorisé (configuration de sécurité réseau)"))
    v = a.attr("usesCleartextTraffic") if a is not None else None
    b, ev = resolve_bool(app, v)
    if v is not None and b is None:
        return make(cid, NOT_DETERMINED, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_MANIFEST_URL,
                    "android:usesCleartextTraffic could not be resolved.", "android:usesCleartextTraffic n'a pas pu être résolu.",
                    [Evidence(app.manifest_path, ev)],
                    title=_t("Cleartext policy not determined (usesCleartextTraffic unresolved)",
                             "Politique de trafic en clair non déterminée (usesCleartextTraffic non résolu)"))
    allowed = default_allowed if b is None else b
    if allowed:
        why_en = ("android:usesCleartextTraffic=\"true\"" if b else
                  f"no explicit setting and targetSdk {target} <= 27 (platform default allows cleartext)")
        why_fr = ("android:usesCleartextTraffic=\"true\"" if b else
                  f"aucun réglage explicite et targetSdk {target} <= 27 (la plateforme autorise le clair par défaut)")
        return make(cid, FAIL, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_MANIFEST_URL,
                    f"Cleartext HTTP is allowed for all domains: {why_en}. Not a Play upload blocker, but traffic can be "
                    "read or modified on the network.",
                    f"Le HTTP en clair est autorisé pour tous les domaines : {why_fr}. Ce n'est pas bloquant pour Google Play, "
                    "mais le trafic peut être lu ou modifié sur le réseau.",
                    [Evidence(app.manifest_path, ev, "application@android:usesCleartextTraffic")],
                    title=_t("Cleartext HTTP allowed for all domains (usesCleartextTraffic=true)" if b else
                             f"Cleartext HTTP allowed for all domains (default for target API {target})",
                             "HTTP en clair autorisé pour tous les domaines (usesCleartextTraffic=true)" if b else
                             f"HTTP en clair autorisé pour tous les domaines (défaut pour l'API cible {target})"))
    return make(cid, PASS, WARNING, REQ_CLEARTEXT, P.CLEARTEXT_MANIFEST_URL,
                "Cleartext HTTP is not allowed (explicitly or by the platform default for targetSdk 28+).",
                "Le HTTP en clair n'est pas autorisé (explicitement ou par défaut avec targetSdk 28+).",
                [Evidence(app.manifest_path, ev, "application@android:usesCleartextTraffic")],
                title=_t("Cleartext HTTP not allowed", "HTTP en clair non autorisé"))


def run_android_checks(app: AndroidApp, as_of: dt.date) -> List[Result]:
    results = [
        check_target_sdk(app, as_of),
        check_16kb_elf(app, as_of),
        check_16kb_zipalign(app, as_of),
        check_exported(app, as_of),
    ]
    results.extend(check_fgs(app, as_of))
    results.extend([
        check_permission_declarations(app, as_of),
        check_debuggable(app, as_of),
        check_cleartext(app, as_of),
    ])
    return results


def app_info(app: AndroidApp) -> dict:
    m = app.manifest
    min_sdk, target, _ = sdk_levels(app)
    vc = m.attr("versionCode")
    vn = m.attr("versionName")
    return {
        "id": app.package,
        "version": str(vn.data) if vn is not None and vn.kind == K_STRING else None,
        "build": str(vc.data) if vc is not None else None,
        "min_os": str(min_sdk) if min_sdk is not None else None,
        "target_sdk": str(target) if target is not None else None,
    }
