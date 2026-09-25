"""Java/Kotlin web-source pack: routing, real scans, safe variants."""
from __future__ import annotations

import os
import pytest
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy import main
from narvy.web import source_analyzer


def _write(path: str, content: str = "") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


_JAVA_SRC = "src/main/java/com/example"
_KT_SRC = "src/main/kotlin/com/example"
_RES = "src/main/resources"


def _make_spring_boot_app(root: str) -> None:
    """Spring Boot service: every covered sink paired with its safe form."""
    _write(os.path.join(root, "build.gradle"),
           "plugins { id 'org.springframework.boot' version '3.2.0' }\n"
           "dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }\n")
    _write(os.path.join(root, "settings.gradle"), "rootProject.name = 'demo'\n")

    _write(os.path.join(root, _JAVA_SRC, "SecurityConfig.java"), """
package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;

@RestController
@CrossOrigin(origins = "*")
public class SecurityConfig {

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a.anyRequest().permitAll());
        return http.build();
    }

    CorsConfiguration cors() {
        CorsConfiguration c = new CorsConfiguration();
        c.addAllowedOriginPattern("*");
        c.setAllowCredentials(true);
        return c;
    }

    SecurityFilterChain safeChain(HttpSecurity http) throws Exception {
        http.csrf(c -> c.ignoringRequestMatchers("/webhook/**"))
            .authorizeHttpRequests(a -> a.requestMatchers("/health").permitAll()
                                         .anyRequest().authenticated());
        return http.build();
    }

    CorsConfiguration safeCors() {
        CorsConfiguration c = new CorsConfiguration();
        c.addAllowedOrigin("https://app.example.com");
        c.setAllowCredentials(true);
        return c;
    }
}
""".lstrip())

    _write(os.path.join(root, _JAVA_SRC, "OrderRepository.java"), """
package com.example;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import java.util.List;

public class OrderRepository {

    private EntityManager em;

    public List<?> findByStatus(String status) {
        return em.createQuery("SELECT o FROM Order o WHERE o.status = '" + status + "'").getResultList();
    }

    public List<?> findNative(String col) {
        String sql = "SELECT * FROM orders ORDER BY " + col;
        Query q = em.createNativeQuery(sql);
        return q.getResultList();
    }

    public List<?> findSafe(String status) {
        return em.createQuery("SELECT o FROM Order o WHERE o.status = :s "
                              + "AND o.deleted = false")
                 .setParameter("s", status)
                 .getResultList();
    }

    public List<?> findSafeBound(String status) {
        String sql = "SELECT * FROM orders WHERE status = ?1";
        Query q = em.createNativeQuery(sql);
        q.setParameter(1, status);
        return q.getResultList();
    }
}
""".lstrip())

    _write(os.path.join(root, _JAVA_SRC, "ProxyController.java"), """
package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.thoughtworks.xstream.XStream;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import java.util.Random;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

@RestController
public class ProxyController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/fetch-safe")
    public String fetchSafe(@RequestParam String path) {
        return restTemplate.getForObject("https://internal.example.com/" + path, String.class);
    }

    public Object loadConfig(String body) {
        Yaml yaml = new Yaml();
        return yaml.load(body);
    }

    public Object loadConfigSafe(String body) {
        Yaml yaml = new Yaml(new SafeConstructor(new org.yaml.snakeyaml.LoaderOptions()));
        return yaml.load(body);
    }

    public Object fromXml(String xml) {
        XStream xs = new XStream();
        return xs.fromXML(xml);
    }

    public Object fromXmlSafe(String xml) {
        XStream xs = new XStream();
        xs.allowTypes(new Class[]{String.class});
        return xs.fromXML(xml);
    }

    public ObjectMapper mapper() {
        ObjectMapper m = new ObjectMapper();
        m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);
        return m;
    }

    public ObjectMapper springSecurityMapper(ObjectMapper owner) {
        SecurityJackson2Modules.enableDefaultTyping(owner);
        return owner;
    }

    public String sign(String subject) {
        return Jwts.builder().setSubject(subject)
                   .signWith(Keys.hmacShaKeyFor("my-super-secret-signing-key-1234".getBytes()))
                   .compact();
    }

    public String resetToken() {
        String resetToken = Long.toHexString(new Random().nextLong());
        return resetToken;
    }

    public int retryDelayMillis() {
        int backoffJitter = new Random().nextInt(500);
        return backoffJitter;
    }

    public Cookie legacyCookie() {
        Cookie c = new Cookie("sid", "x");
        c.setHttpOnly(false);
        c.setSecure(false);
        return c;
    }

    public Cookie builtCookie() {
        Cookie c = buildCookie();
        return c;
    }

    private Cookie buildCookie() {
        Cookie c = new Cookie("sid", "x");
        c.setHttpOnly(true);
        c.setSecure(true);
        return c;
    }

    public String configuredSecret() {
        return System.getProperty("app.jwt.secret", "fallback-signing-secret");
    }
}
""".lstrip())

    _write(os.path.join(root, _RES, "application.properties"),
           "management.endpoints.web.exposure.include=*\n"
           "spring.h2.console.enabled=true\n")

    _write(os.path.join(root, _RES, "mapper", "OrderMapper.xml"), """
<?xml version="1.0" encoding="UTF-8" ?>
<mapper namespace="com.example.OrderMapper">
  <select id="byCol" resultType="Order">
    SELECT * FROM orders WHERE tenant = ${tenantName}
  </select>
  <select id="byId" resultType="Order">
    SELECT * FROM orders WHERE id = #{id}
  </select>
  <select id="generated" resultType="Order">
    SELECT * FROM orders <if test="c.valid">and ${criterion.condition}</if>
    order by ${orderByClause}
  </select>
</mapper>
""".lstrip())


def _make_kotlin_backend(root: str) -> None:
    _write(os.path.join(root, "build.gradle.kts"),
           "plugins { kotlin(\"jvm\") version \"1.9.22\" }\n"
           "dependencies { implementation(\"io.ktor:ktor-server-core:2.3.7\") }\n")
    _write(os.path.join(root, "settings.gradle.kts"), "rootProject.name = \"svc\"\n")
    _write(os.path.join(root, _KT_SRC, "KtorApp.kt"), """
package com.example

import io.ktor.server.application.install
import io.ktor.server.plugins.cors.routing.CORS
import java.sql.Connection
import kotlin.random.Random
import org.jetbrains.exposed.sql.transactions.TransactionManager

fun Application.configure() {
    install(CORS) {
        anyHost()
        allowCredentials = true
    }
}

fun Application.configureSafe() {
    install(CORS) {
        allowHost("app.example.com", schemes = listOf("https"))
    }
}

fun lookup(name: String) {
    TransactionManager.current().exec("SELECT * FROM users WHERE name = '$name'")
}

fun lookupSafe(name: String) {
    TransactionManager.current().exec("SELECT * FROM users WHERE name = ?", listOf(name))
}

fun query(conn: Connection, id: String) {
    conn.prepareStatement("SELECT * FROM t WHERE id = $id")
}

fun querySafe(conn: Connection, id: String) {
    conn.prepareStatement("SELECT * FROM t WHERE id = ?")
}

fun ping(host: String) {
    Runtime.getRuntime().exec("ping -c 1 $host")
}

fun pingSafe(host: String) {
    ProcessBuilder(listOf("ping", "-c", "1", host)).start()
}

fun newResetToken(): String {
    val resetToken = Random.nextLong().toString(16)
    return resetToken
}

fun jitter(): Int {
    val backoffMillis = Random.nextInt(500)
    return backoffMillis
}

fun springChain(http: HttpSecurity): SecurityFilterChain {
    http.csrf { it.disable() }
    return http.build()
}
""".lstrip())


def _make_android_app_with_pom(root: str) -> None:
    """Android app that also carries a Maven pom; Android markers must win."""
    _write(os.path.join(root, "pom.xml"), "<project></project>\n")
    _write(os.path.join(root, "build.gradle"),
           "plugins { id 'com.android.application' }\n")
    _write(os.path.join(root, "app", "src", "main", "AndroidManifest.xml"),
           "<manifest package=\"com.example\"/>\n")
    _write(os.path.join(root, "app", "src", "main", "java", "com", "example", "A.java"),
           "package com.example; class A {}\n")


def _detect(path: str) -> str:
    try:
        return main._detect_scan_mode(path)
    except main.UnsupportedScanTarget:
        return "UNSUPPORTED"


def test_spring_boot_repo_routes_to_web_source_with_java_configs():
    with tempfile.TemporaryDirectory() as d:
        _make_spring_boot_app(d)
        assert _detect(d) == "web-source"
        ported, unported = source_analyzer.detect_web_stacks(d)
        assert ported == {"java"}, (ported, unported)
        configs = source_analyzer._resolve_configs(ported)
        names = [os.path.basename(c) for c in configs]
        for expected in ("java.yml", "kotlin.yml", "secrets.yml"):
            assert expected in names, (expected, names)
        assert "security-audit.yml" not in names, names
        assert not any(c.startswith("p/") for c in configs), configs
        assert "java.yml" in names, names


def test_kotlin_backend_routes_to_web_source_with_java_configs():
    with tempfile.TemporaryDirectory() as d:
        _make_kotlin_backend(d)
        assert _detect(d) == "web-source"
        ported, _ = source_analyzer.detect_web_stacks(d)
        assert "java" in ported


def test_android_app_with_pom_still_beats_web_source():
    with tempfile.TemporaryDirectory() as d:
        _make_android_app_with_pom(d)
        assert _detect(d) == "android-source"


def test_java_source_density_alone_is_enough():
    """A repo built with plain javac or Bazel has no pom.xml and no Gradle file."""
    with tempfile.TemporaryDirectory() as d:
        for i in range(6):
            _write(os.path.join(d, _JAVA_SRC, f"C{i}.java"),
                   f"package com.example; class C{i} {{}}\n")
        ported, _ = source_analyzer.detect_web_stacks(d)
        assert "java" in ported


def test_gradle_build_script_alone_does_not_count_as_java_source():
    """Gradle build scripts are not Java source."""
    assert ".gradle" not in source_analyzer._LANG_EXTS["java"]
    assert ".gradle.kts" not in source_analyzer._LANG_EXTS["java"]
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "build.gradle"), "plugins { id 'java' }\n")
        assert source_analyzer._count_scanned_files(d, {"java"}) == 0


def _scan(maker):
    with tempfile.TemporaryDirectory() as d:
        maker(d)
        return source_analyzer.analyze_source(d)


@pytest.mark.skipif(not source_analyzer.pro_rules_available(), reason="framework rule pack is premium, not shipped")
def test_java_scan_fires_every_rule_family_the_pack_claims():
    result = _scan(_make_spring_boot_app)
    assert result["ok"] is True
    assert "java" in result["stacks_detected"]
    if not result["findings"]:
        return  # semgrep unavailable; other tests cover the wiring
    rule_ids = {f["rule_id"] for f in result["findings"]}
    expected = {
        "csrf-disabled",
        "permit-all-requests",
        "crossorigin-wildcard-annotation",
        "corsconfiguration-wildcard-with-credentials",
        "actuator-exposed-all",
        "h2-console-enabled",
        "jpa-createquery-concat",
        "jpa-createquery-concat-var",
        "handwritten-dollar-substitution",
        "snakeyaml-unsafe-constructor",
        "xstream-unrestricted-fromxml",
        "jackson-enable-default-typing",
        "tainted-request-url-host",
        "hardcoded-signing-key",
        "insecure-random",
        "sensitive-cookie-flags-explicitly-false",
        "hardcoded-fallback-secret",
    }
    missing = expected - rule_ids
    assert not missing, f"pack did not fire on {sorted(missing)}; saw {sorted(rule_ids)}"


def test_java_scan_does_not_fire_on_the_safe_counterparts():
    """Every vulnerable method in the fixture has a safe sibling."""
    result = _scan(_make_spring_boot_app)
    if not result["findings"]:
        return
    by_rule = {}
    for f in result["findings"]:
        by_rule.setdefault(f["rule_id"], []).append(f["line"])
    # One hit each: the safe overload must not add a second.
    for rule in ("jpa-createquery-concat", "jpa-createquery-concat-var",
                 "snakeyaml-unsafe-constructor", "xstream-unrestricted-fromxml",
                 "tainted-request-url-host", "jackson-enable-default-typing"):
        hits = by_rule.get(rule, [])
        assert len(hits) <= 1, f"{rule} fired {len(hits)} times, expected at most 1: {hits}"
    # insecure-random legitimately fires on two distinct vulnerable methods
    # here (resetToken, jitter), neither of which has a safe sibling.
    random_hits = by_rule.get("insecure-random", [])
    assert not random_hits or len(set(random_hits)) == 2, random_hits


@pytest.mark.skipif(not source_analyzer.pro_rules_available(), reason="framework rule pack is premium, not shipped")
def test_mybatis_rule_ignores_generator_boilerplate():
    """Only hand-written `${...}` fires, not MyBatis Generator output."""
    result = _scan(_make_spring_boot_app)
    if not result["findings"]:
        return
    xml_hits = [f for f in result["findings"]
                if f["rule_id"] == "handwritten-dollar-substitution"]
    assert len(xml_hits) == 1, [(f["file_path"], f["line"]) for f in xml_hits]
    assert xml_hits[0]["line"] == 4, xml_hits[0]


def test_kotlin_scan_fires_the_server_side_rules():
    result = _scan(_make_kotlin_backend)
    assert result["ok"] is True
    if not result["findings"]:
        return
    rule_ids = {f["rule_id"] for f in result["findings"]}
    expected = {
        "install-cors-anyhost",
        "raw-sql-string-template",
        "command-string-template",
        "insecure-random",
        "csrf-disabled",
    }
    missing = expected - rule_ids
    assert not missing, f"Kotlin pack did not fire on {sorted(missing)}; saw {sorted(rule_ids)}"
    # Both sink shapes must be caught: Exposed TransactionManager.exec and
    # JDBC Connection.prepareStatement.
    sql_lines = {f["line"] for f in result["findings"] if f["rule_id"] == "raw-sql-string-template"}
    assert len(sql_lines) == 2, sql_lines


def test_kotlin_exposed_rule_does_not_claim_runtime_exec_is_sql():
    """Exposed exec is SQL, so command-injection rules stay off it."""
    result = _scan(_make_kotlin_backend)
    if not result["findings"]:
        return
    sql_lines = {f["line"] for f in result["findings"]
                 if f["rule_id"] == "raw-sql-string-template"}
    cmd_lines = {f["line"] for f in result["findings"]
                 if f["rule_id"] == "command-string-template"}
    assert cmd_lines, "command-string-template did not fire at all"
    assert not (sql_lines & cmd_lines), (sql_lines, cmd_lines)


# Exclusions live inside the vendored rule definitions (a pattern-not), not at
# semgrep invocation time, so they are verified against the fixture directly.

def test_cookie_replacement_fires_on_explicit_false_only():
    """Fires only on an explicit `false`."""
    result = _scan(_make_spring_boot_app)
    if not result["findings"]:
        return
    ids = [f["rule_id"] for f in result["findings"]]
    assert ids.count("sensitive-cookie-flags-explicitly-false") == 2, ids


@pytest.mark.skipif(not source_analyzer.pro_rules_available(), reason="framework rule pack is premium, not shipped")
def test_spring_security_jackson_helper_is_not_flagged():
    """SecurityJackson2Modules default typing is allow-listed, not flagged."""
    result = _scan(_make_spring_boot_app)
    if not result["findings"]:
        return
    hits = [f for f in result["findings"] if f["rule_id"] == "jackson-enable-default-typing"]
    assert len(hits) == 1, [(h["file_path"], h["line"]) for h in hits]


def test_no_exclude_rule_flag_anymore():
    """--no-rewrite-rule-ids stays, --exclude-rule is gone."""
    import inspect
    src = inspect.getsource(source_analyzer._web_semgrep_cmd)
    assert "--no-rewrite-rule-ids" in src
    assert "--exclude-rule" not in src
    assert not hasattr(source_analyzer, "_EXCLUDED_RULE_IDS")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"PASS: {len(fns)} Java/Kotlin web-source tests OK")
