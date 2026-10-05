"""App Store readiness checks for IPA files."""
from __future__ import annotations

import datetime as dt
import re
from typing import Dict, List, Optional, Set, Tuple

from ..data import apple as A
from ..model import BLOCKER, FAIL, INFO, NOT_APPLICABLE, NOT_DETERMINED, PASS, WARNING, Evidence, Result, make
from .loader import IPA, Bundle


def _t(en: str, fr: str):
    return {"en": en, "fr": fr}


def _rel(ipa: IPA, path: str) -> str:
    return path[len("Payload/"):] if path.startswith("Payload/") else path


def _declared(ipa: IPA, manifest_paths: List[str]) -> Dict[str, Set[str]]:
    """category -> declared reason codes, over the given manifests."""
    out: Dict[str, Set[str]] = {}
    for mp in manifest_paths:
        m = ipa.manifests.get(mp)
        if not isinstance(m, dict):
            continue
        for entry in m.get("NSPrivacyAccessedAPITypes") or []:
            if not isinstance(entry, dict):
                continue
            cat = entry.get("NSPrivacyAccessedAPIType")
            reasons = entry.get("NSPrivacyAccessedAPITypeReasons") or []
            if isinstance(cat, str):
                out.setdefault(cat, set()).update(r for r in reasons if isinstance(r, str))
    return out


def _covering_manifests(ipa: IPA, b: Bundle) -> List[str]:
    if b.kind == "dylib":
        # a loose dylib is included by the bundle whose directory holds it
        owner = max((x for x in ipa.bundles if x.kind != "dylib" and b.path.startswith(x.path)),
                    key=lambda x: len(x.path), default=ipa.main)
        return owner.own_manifests + owner.nested_manifests
    return b.own_manifests + b.nested_manifests


def _is_apple_runtime(b: Bundle) -> bool:
    return b.kind == "dylib" and b.name.startswith("libswift")


TITLE_RR = _t("Required-reason APIs are declared in the privacy manifest (ITMS-91053)",
              "Les API à justification sont déclarées dans le manifeste de confidentialité (ITMS-91053)")


def check_required_reason(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-REQUIRED-REASON-API"
    url = A.REQUIRED_REASON_URL
    if as_of < A.REQUIRED_REASON_ENFORCED:
        return make(cid, NOT_APPLICABLE, WARNING, TITLE_RR, url, "Not enforced before 2024-05-01.",
                    "Non appliqué avant le 2024-05-01.")
    fails: List[Evidence] = []
    undetermined: List[Evidence] = []
    passes: List[Evidence] = []
    for b in ipa.bundles:
        if b.executable_path is None:
            continue
        if _is_apple_runtime(b):
            continue
        where = _rel(ipa, b.executable_path)
        if b.slices is None:
            undetermined.append(Evidence(where, "binary not analysed", b.load_error))
            continue
        imports = b.imports
        needed: Dict[str, List[str]] = {}
        either: List[str] = []
        for sym in sorted(imports):
            cats = A.SYMBOLS.get(sym)
            if not cats:
                continue
            if len(cats) == 1:
                needed.setdefault(cats[0], []).append(sym)
            else:
                either.append(sym)
        manifests = _covering_manifests(ipa, b)
        declared = _declared(ipa, manifests)
        mtxt = ", ".join(_rel(ipa, m) for m in manifests) or "no privacy manifest covers this binary"
        for cat, syms in sorted(needed.items()):
            if cat in declared:
                passes.append(Evidence(where, f"{cat} declared", f"symbols: {', '.join(syms)}"))
            else:
                fails.append(Evidence(where, f"{cat} not declared",
                                      f"imported symbols: {', '.join(syms)}; manifests checked: {mtxt}"))
        if either:
            cats = A.SYMBOLS[either[0]]
            if not any(c in declared for c in cats):
                fails.append(Evidence(where, f"{' or '.join(cats)} not declared",
                                      f"imported symbols: {', '.join(either)} (Apple lists them under both categories); "
                                      f"manifests checked: {mtxt}"))
        # selector evidence (never a fail on its own)
        sel_cats: Dict[str, List[str]] = {}
        sel_unknown = False
        for sl in b.slices:
            if sl.selrefs is None:
                sel_unknown = True
                continue
            for sel, (cat, api) in A.SELECTORS.items():
                if sel in sl.selrefs:
                    sel_cats.setdefault(cat, []).append(api)
        for cat, apis in sorted(sel_cats.items()):
            if cat in declared or cat in needed:
                continue
            undetermined.append(Evidence(where, f"{cat} possibly used",
                                         f"sends Objective-C message(s) {', '.join(sorted(set(apis)))} by selector name; "
                                         f"the receiver class cannot be proven statically; manifests checked: {mtxt}"))
        if sel_unknown and not needed and not either:
            notes = "; ".join(sorted({sl.selrefs_note for sl in b.slices if sl.selrefs is None}))
            passes.append(Evidence(where, "selector references not readable", notes))
    if fails:
        n_bin = len({e.path for e in fails})
        return make(cid, FAIL, WARNING, TITLE_RR, url,
                    f"{n_bin} binary(ies) import required-reason APIs whose category is not declared in the privacy "
                    "manifest of the bundle that contains them. Apple's documentation requires a declaration and says "
                    "such uploads are not accepted since 2024-05-01 (ITMS-91053). Reported as a warning, not a blocker: "
                    "Apple's scanner is not public and App Store apps with undeclared imports exist, so a rejection "
                    "cannot be predicted with certainty.",
                    f"{n_bin} binaire(s) importent des API à justification dont la catégorie n'est pas déclarée dans le "
                    "manifeste de confidentialité du bundle qui les contient. La documentation Apple exige une "
                    "déclaration et indique que ces envois sont refusés depuis le 2024-05-01 (ITMS-91053). Signalé en "
                    "avertissement et non en bloquant : l'outil d'analyse d'Apple n'est pas public et des applications "
                    "publiées contiennent des imports non déclarés, un refus ne peut donc pas être prédit avec certitude.",
                    fails + undetermined, [A.API_TYPE_URL])
    if undetermined:
        return make(cid, NOT_DETERMINED, WARNING, TITLE_RR, url,
                    "No undeclared required-reason API was proven, but some evidence could not be settled.",
                    "Aucune API à justification non déclarée n'a été prouvée, mais certains éléments n'ont pas pu être tranchés.",
                    undetermined + passes, [A.API_TYPE_URL])
    return make(cid, PASS, WARNING, TITLE_RR, url,
                "Every required-reason API category referenced by a binary is declared in the covering privacy manifest.",
                "Chaque catégorie d'API à justification référencée par un binaire est déclarée dans le manifeste qui le couvre.",
                passes, [A.API_TYPE_URL])


TITLE_PM = _t("Privacy manifests are present and valid", "Les manifestes de confidentialité sont présents et valides")


def check_privacy_manifest(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-PRIVACY-MANIFEST"
    url = A.PRIVACY_MANIFEST_URL
    invalid: List[Evidence] = []
    for mp, m in sorted(ipa.manifests.items()):
        if m is None:
            invalid.append(Evidence(_rel(ipa, mp), "not a valid property list", ipa.manifest_errors.get(mp, "")))
            continue
        for entry in m.get("NSPrivacyAccessedAPITypes") or []:
            if not isinstance(entry, dict):
                invalid.append(Evidence(_rel(ipa, mp), "NSPrivacyAccessedAPITypes entry is not a dictionary"))
                continue
            cat = entry.get("NSPrivacyAccessedAPIType")
            reasons = entry.get("NSPrivacyAccessedAPITypeReasons")
            if cat not in A.REASONS:
                invalid.append(Evidence(_rel(ipa, mp), f"unknown category {cat!r}"))
                continue
            if not isinstance(reasons, list) or not reasons:
                invalid.append(Evidence(_rel(ipa, mp), f"{cat}: no reason code"))
                continue
            bad = [r for r in reasons if r not in A.REASONS[cat]]
            if bad:
                invalid.append(Evidence(_rel(ipa, mp), f"{cat}: reason code(s) not in Apple's list: {', '.join(map(str, bad))}"))
    main_has = bool(ipa.main.own_manifests)
    if invalid:
        return make(cid, FAIL, WARNING, TITLE_PM, url,
                    "Some privacy manifests are malformed or use categories / reason codes that are not in Apple's "
                    "documented list.",
                    "Certains manifestes de confidentialité sont mal formés ou utilisent des catégories ou codes de "
                    "justification absents de la liste documentée par Apple.", invalid, [A.API_TYPE_URL])
    if not main_has:
        return make(cid, FAIL, INFO, TITLE_PM, url,
                    "The app bundle has no PrivacyInfo.xcprivacy at its root. It is only mandatory when the app's own "
                    "code uses required-reason APIs (see APPSTORE-REQUIRED-REASON-API), but Apple recommends one.",
                    "Le bundle de l'application n'a pas de PrivacyInfo.xcprivacy à sa racine. Il n'est obligatoire que si "
                    "le code de l'application utilise des API à justification (voir APPSTORE-REQUIRED-REASON-API), mais "
                    "Apple le recommande.",
                    [Evidence(_rel(ipa, ipa.app_dir), "PrivacyInfo.xcprivacy absent"),
                     Evidence("(all bundles)", f"{len(ipa.manifests)} privacy manifest(s) in the IPA")])
    return make(cid, PASS, WARNING, TITLE_PM, url,
                f"{len(ipa.manifests)} privacy manifest(s) found, all valid.",
                f"{len(ipa.manifests)} manifeste(s) de confidentialité trouvé(s), tous valides.",
                [Evidence(_rel(ipa, p), "valid") for p in sorted(ipa.manifests)][:30])


TITLE_SDK = _t("Listed third-party SDKs ship their own privacy manifest",
               "Les SDK tiers listés par Apple embarquent leur propre manifeste de confidentialité")


def check_listed_sdks(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-THIRD-PARTY-SDK"
    url = A.SDK_LIST_URL
    listed = set(A.LISTED_SDKS)
    found = [b for b in ipa.bundles if b.kind == "framework" and b.name[:-len(".framework")] in listed]
    if not found:
        return make(cid, NOT_APPLICABLE, WARNING, TITLE_SDK, url,
                    "No embedded framework matches Apple's list of commonly used SDKs. Statically linked SDKs are not "
                    "detected by this check.",
                    "Aucun framework embarqué ne correspond à la liste Apple des SDK courants. Les SDK liés statiquement "
                    "ne sont pas détectés par ce contrôle.")
    missing = [b for b in found if not (b.own_manifests or b.nested_manifests)]
    ok = [b for b in found if b not in missing]
    sig_note_en = ("The SDK signature requirement cannot be verified from an IPA: embedded frameworks are re-signed "
                   "with the app's identity. Xcode verifies it at build time.")
    sig_note_fr = ("L'exigence de signature des SDK ne peut pas être vérifiée depuis une IPA : les frameworks embarqués "
                   "sont re-signés avec l'identité de l'application. Xcode la vérifie à la compilation.")
    if missing:
        return make(cid, FAIL, WARNING, TITLE_SDK, url,
                    f"{len(missing)} framework(s) on Apple's list ship without a privacy manifest. App Store Connect "
                    "rejects this for a new app, or for an update that adds the SDK. " + sig_note_en,
                    f"{len(missing)} framework(s) de la liste Apple sont livrés sans manifeste de confidentialité. App Store "
                    "Connect le refuse pour une nouvelle application, ou pour une mise à jour qui ajoute ce SDK. " + sig_note_fr,
                    [Evidence(_rel(ipa, b.path), "no PrivacyInfo.xcprivacy in the framework") for b in missing] +
                    [Evidence(_rel(ipa, b.path), "privacy manifest present") for b in ok])
    return make(cid, PASS, WARNING, TITLE_SDK, url,
                f"All {len(found)} listed framework(s) ship a privacy manifest. " + sig_note_en,
                f"Les {len(found)} framework(s) listés embarquent un manifeste de confidentialité. " + sig_note_fr,
                [Evidence(_rel(ipa, b.path), "privacy manifest present") for b in ok])


TITLE_ATS = _t("App Transport Security is not disabled globally (NSAllowsArbitraryLoads)",
               "App Transport Security n'est pas désactivé globalement (NSAllowsArbitraryLoads)")


def check_ats(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-ATS"
    url = A.ATS_URL
    disabled: List[Evidence] = []
    ignored: List[Evidence] = []
    exceptions: List[Evidence] = []
    for b in ipa.bundles:
        if b.kind not in ("app", "appex") or not isinstance(b.info, dict):
            continue
        ats = b.info.get("NSAppTransportSecurity")
        where = _rel(ipa, b.path + "Info.plist")
        if not isinstance(ats, dict):
            continue
        if ats.get("NSAllowsArbitraryLoads") is True:
            overrides = [k for k in A.ATS_OVERRIDE_KEYS if k in ats]
            if overrides:
                ignored.append(Evidence(where, "NSAllowsArbitraryLoads = true",
                                        f"ignored on iOS 10+ because {', '.join(overrides)} is present"))
            else:
                disabled.append(Evidence(where, "NSAllowsArbitraryLoads = true"))
        dom = ats.get("NSExceptionDomains")
        if isinstance(dom, dict):
            for d, cfg in dom.items():
                if isinstance(cfg, dict) and cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    exceptions.append(Evidence(where, f"{d}: NSExceptionAllowsInsecureHTTPLoads = true"))
    if disabled:
        return make(cid, FAIL, WARNING, TITLE_ATS, url,
                    "NSAllowsArbitraryLoads is true: ATS is disabled for all domains. App Review asks for a justification; "
                    "prefer per-domain exceptions.",
                    "NSAllowsArbitraryLoads vaut true : ATS est désactivé pour tous les domaines. L'App Review demande une "
                    "justification ; préférez des exceptions par domaine.", disabled + ignored + exceptions)
    if ignored or exceptions:
        return make(cid, FAIL, INFO, TITLE_ATS, url,
                    "ATS is not disabled globally, but insecure HTTP exceptions exist (listed in the evidence).",
                    "ATS n'est pas désactivé globalement, mais des exceptions HTTP non sécurisées existent (voir les preuves).",
                    ignored + exceptions)
    return make(cid, PASS, WARNING, TITLE_ATS, url, "ATS is not relaxed.", "ATS n'est pas assoupli.")


TITLE_USAGE = _t("Purpose strings exist for declared capabilities", "Les textes d'usage existent pour les capacités déclarées")

_USAGE_KEY_RE = re.compile(r"^(NS\w+UsageDescription|NFCReaderUsageDescription)$")


def check_usage_strings(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-PURPOSE-STRINGS"
    url = A.USAGE_URL
    fails: List[Evidence] = []
    unknown: List[Evidence] = []
    for b in ipa.bundles:
        if b.kind not in ("app", "appex") or not isinstance(b.info, dict):
            continue
        where = _rel(ipa, b.path + "Info.plist")
        localized = any(n.startswith(b.path) and n.endswith(".lproj/InfoPlist.strings") and
                        n[len(b.path):].count("/") == 1 for n in ipa.names)
        for k, v in b.info.items():
            if _USAGE_KEY_RE.match(k) and (not isinstance(v, str) or not v.strip()):
                if localized:
                    unknown.append(Evidence(where, f"{k} is empty", "localized InfoPlist.strings may provide the text"))
                else:
                    fails.append(Evidence(where, f"{k} is empty", "an empty purpose string is treated as missing"))
        # entitlements of this bundle's executable
        if b.slices is None:
            unknown.append(Evidence(where, "executable not analysed: entitlements unknown", b.load_error))
            continue
        ents = None
        for sl in b.slices:
            if sl.entitlements is not None:
                ents = sl.entitlements
                break
        if ents is None:
            unknown.append(Evidence(where, "no code signature entitlements: entitlement-based purpose strings not checked"))
            continue
        for ent, (keys, _doc) in A.ENTITLEMENT_USAGE_KEYS.items():
            val = ents.get(ent)
            if not val:
                continue
            present = [k for k in keys if isinstance(b.info.get(k), str) and b.info.get(k).strip()]
            if not present:
                fails.append(Evidence(where, f"entitlement {ent} without {' / '.join(keys)}"))
    if fails:
        return make(cid, FAIL, WARNING, TITLE_USAGE, url,
                    "Some purpose strings are missing or empty for capabilities the app declares. Accessing the protected "
                    "resource without its purpose string crashes the app, and App Review rejects it (guideline 5.1.1).",
                    "Certains textes d'usage sont absents ou vides pour des capacités déclarées par l'application. Accéder "
                    "à la ressource protégée sans texte d'usage fait planter l'application, et l'App Review la refuse "
                    "(règle 5.1.1).", fails + unknown,
                    [v[1] for v in A.ENTITLEMENT_USAGE_KEYS.values()])
    if unknown:
        return make(cid, NOT_DETERMINED, WARNING, TITLE_USAGE, url,
                    "No missing purpose string was proven, but some bundles could not be fully checked.",
                    "Aucun texte d'usage manquant n'a été prouvé, mais certains bundles n'ont pas pu être entièrement vérifiés.",
                    unknown)
    return make(cid, PASS, WARNING, TITLE_USAGE, url,
                "Declared purpose strings are non-empty and entitlement-gated capabilities have theirs.",
                "Les textes d'usage déclarés sont renseignés et les capacités liées aux entitlements ont le leur.")


def _major(s) -> Optional[int]:
    if not isinstance(s, str):
        return None
    m = re.search(r"(\d+)(?:\.\d+)*$", s.strip())
    if not m:
        return None
    return int(m.group(1))


TITLE_SDKVER = _t("Built with the SDK and Xcode required by App Store Connect",
                  "Compilé avec le SDK et la version de Xcode exigés par App Store Connect")


def check_sdk_version(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-SDK-VERSION"
    url = A.SDK_REQ_URL
    req = A.sdk_requirement(as_of)
    info = ipa.info
    plist_where = _rel(ipa, ipa.app_dir + "Info.plist")
    platforms = info.get("CFBundleSupportedPlatforms")
    ev = [Evidence(plist_where, str(info.get("DTSDKName")), "DTSDKName"),
          Evidence(plist_where, str(info.get("DTPlatformVersion")), "DTPlatformVersion"),
          Evidence(plist_where, str(info.get("DTXcode")), "DTXcode")]
    if ipa.main.slices:
        ev.append(Evidence(_rel(ipa, ipa.main.executable_path or ""), ", ".join(
            f"{s.arch}: sdk {s.sdk}" for s in ipa.main.slices), "LC_BUILD_VERSION / LC_VERSION_MIN"))
    if req is None:
        return make(cid, NOT_APPLICABLE, BLOCKER, TITLE_SDKVER, url, "No requirement recorded for this date.",
                    "Aucune exigence enregistrée pour cette date.", ev)
    need_sdk, need_xcode, eff = req
    if isinstance(platforms, list) and platforms and "iPhoneOS" not in platforms and eff < dt.date(2026, 4, 28):
        return make(cid, NOT_DETERMINED, BLOCKER, TITLE_SDKVER, url,
                    "Not an iOS app: the SDK requirement for this platform and date is not encoded.",
                    "Pas une application iOS : l'exigence de SDK pour cette plateforme et cette date n'est pas encodée.", ev)
    indicators = []
    for label, val in (("DTSDKName", info.get("DTSDKName")), ("DTPlatformVersion", info.get("DTPlatformVersion"))):
        m = _major(val)
        if m is not None:
            indicators.append((label, m))
    for sl in ipa.main.slices or []:
        m = _major(sl.sdk) if sl.sdk else None
        if m is not None:
            indicators.append((f"Mach-O {sl.arch} sdk", m))
    xcode_raw = info.get("DTXcode")
    xcode = int(xcode_raw) // 100 if isinstance(xcode_raw, str) and xcode_raw.isdigit() else None
    if not indicators:
        return make(cid, NOT_DETERMINED, BLOCKER, TITLE_SDKVER, url,
                    "The SDK used to build the app is not recorded in the binary or Info.plist.",
                    "Le SDK utilisé pour compiler l'application n'est enregistré ni dans le binaire ni dans l'Info.plist.", ev)
    below = [m for _l, m in indicators if m < need_sdk]
    if below and len(below) == len(indicators):
        sdk = max(m for _l, m in indicators)
        x_en = f", Xcode {xcode}" if xcode else ""
        return make(cid, FAIL, BLOCKER, TITLE_SDKVER, url,
                    f"This build cannot be uploaded: built with SDK {sdk}{x_en}. Since {eff.isoformat()}, App Store "
                    f"Connect requires Xcode {need_xcode} or later with the {need_sdk} SDKs.",
                    f"Ce build ne peut pas être envoyé : compilé avec le SDK {sdk}{x_en}. Depuis le {eff.isoformat()}, "
                    f"App Store Connect exige Xcode {need_xcode} ou plus avec les SDK {need_sdk}.", ev)
    if below or (xcode is not None and xcode < need_xcode):
        return make(cid, NOT_DETERMINED, BLOCKER, TITLE_SDKVER, url,
                    "The SDK / Xcode versions recorded in the Info.plist and the executable disagree.",
                    "Les versions de SDK / Xcode enregistrées dans l'Info.plist et l'exécutable ne concordent pas.", ev)
    sdk = min(m for _l, m in indicators)
    return make(cid, PASS, BLOCKER, TITLE_SDKVER, url,
                f"Built with SDK {sdk}" + (f" and Xcode {xcode}" if xcode else "") + f": meets the {eff.isoformat()} requirement.",
                f"Compilé avec le SDK {sdk}" + (f" et Xcode {xcode}" if xcode else "") + f" : conforme à l'exigence du {eff.isoformat()}.",
                ev)


TITLE_MINOS = _t("Minimum iOS version accepted by App Store Connect",
                 "Version minimale d'iOS acceptée par App Store Connect")


def _vtuple(s: str) -> Optional[Tuple[int, ...]]:
    try:
        return tuple(int(x) for x in s.strip().split("."))
    except (ValueError, AttributeError):
        return None


def check_min_os(ipa: IPA, as_of: dt.date) -> Result:
    cid = "APPSTORE-MIN-OS"
    url = A.MIN_OS_URL
    info = ipa.info
    where = _rel(ipa, ipa.app_dir + "Info.plist")
    req = A.min_os_requirement(as_of)
    mos = info.get("MinimumOSVersion")
    ev = [Evidence(where, str(mos), "MinimumOSVersion")]
    platforms = info.get("CFBundleSupportedPlatforms")
    if isinstance(platforms, list) and platforms and "iPhoneOS" not in platforms:
        return make(cid, NOT_APPLICABLE, BLOCKER, TITLE_MINOS, url, "Not an iOS / iPadOS app.",
                    "Pas une application iOS / iPadOS.", ev)
    if req is None:
        return make(cid, NOT_APPLICABLE, BLOCKER, TITLE_MINOS, url, "No requirement recorded for this date.",
                    "Aucune exigence enregistrée pour cette date.", ev)
    need, eff = req
    v = _vtuple(mos) if isinstance(mos, str) else None
    if v is None and ipa.main.slices:
        mins = {s.minos for s in ipa.main.slices if s.minos}
        if len(mins) == 1:
            m = mins.pop()
            v = _vtuple(m)
            ev.append(Evidence(_rel(ipa, ipa.main.executable_path or ""), m, "LC_BUILD_VERSION minos"))
    if v is None:
        return make(cid, NOT_DETERMINED, BLOCKER, TITLE_MINOS, url, "The minimum iOS version could not be read.",
                    "La version minimale d'iOS n'a pas pu être lue.", ev)
    vs = ".".join(map(str, v))
    if v[0] < need:
        return make(cid, FAIL, BLOCKER, TITLE_MINOS, url,
                    f"The app supports iOS {vs} and later. Since {eff.isoformat()}, iOS and iPadOS apps uploaded to "
                    f"App Store Connect must target iOS {need} or later.",
                    f"L'application supporte iOS {vs} et plus. Depuis le {eff.isoformat()}, les applications iOS et "
                    f"iPadOS envoyées sur App Store Connect doivent cibler iOS {need} ou plus.", ev)
    return make(cid, PASS, BLOCKER, TITLE_MINOS, url, f"Minimum iOS {vs} meets the iOS {need}+ requirement.",
                f"iOS minimum {vs} conforme à l'exigence iOS {need}+.", ev)


def run_ios_checks(ipa: IPA, as_of: dt.date) -> List[Result]:
    return [
        check_sdk_version(ipa, as_of),
        check_min_os(ipa, as_of),
        check_required_reason(ipa, as_of),
        check_privacy_manifest(ipa, as_of),
        check_listed_sdks(ipa, as_of),
        check_ats(ipa, as_of),
        check_usage_strings(ipa, as_of),
    ]


def app_info(ipa: IPA) -> dict:
    i = ipa.info
    enc = any(s.encrypted for s in (ipa.main.slices or []))
    return {
        "id": i.get("CFBundleIdentifier"),
        "version": i.get("CFBundleShortVersionString"),
        "build": i.get("CFBundleVersion"),
        "min_os": i.get("MinimumOSVersion"),
        "sdk": i.get("DTSDKName"),
        "fairplay_encrypted": enc,
    }
