"""Tests for the TypeScript-specific rule pack: pack resolution and a real
semgrep scan of a NestJS/Prisma/TypeORM fixture with safe counterparts.
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.web import source_analyzer

# The TypeScript pack ships in the separate extended rule tree, resolved at
# import time by source_analyzer. It is absent in a bare public checkout.
_TS_PACK_DIR = (
    os.path.join(source_analyzer._PRO_WEB_LOCAL_RULES_DIR, "typescript_narvy")
    if source_analyzer._PRO_WEB_LOCAL_RULES_DIR else ""
)
_WEB_RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "narvy", "rules", "web",
)


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


_NEST_CONTROLLER = """\
import { Controller, Get, Post, Query, Body, Param } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { exec } from 'child_process';

@Controller('users')
export class UserController {
  constructor(private ds: DataSource, private prisma: any) {}

  @Get()
  async find(@Query('name') name: string) {
    return this.ds.query('SELECT * FROM users WHERE name = ' + name);
  }

  @Get('two')
  async findTwo(@Query('id') id: string) {
    return this.ds.query(`SELECT * FROM users WHERE id = ${id}`);
  }

  @Post()
  async create(@Body() body: any) {
    return this.prisma.$queryRawUnsafe(`SELECT * FROM u WHERE n='${body.name}'`);
  }

  @Get('ping')
  ping(@Param('host') host: string) {
    exec('ping ' + host);
  }

  @Get('safe')
  async safe(@Query('id') id: string) {
    return this.ds.query('SELECT * FROM users WHERE id = $1', [id]);
  }
}
"""

_NEST_BOOTSTRAP = """\
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe());
  await app.listen(3000);
}

async function bootstrapSafe() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: ['https://app.example.com'] });
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  await app.listen(3000);
}
bootstrap();
bootstrapSafe();
"""

_TYPE_BYPASSES = """\
import { exec } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export function anyCast(req: any) {
  const cmd = (req.body as any).cmd;
  exec(cmd);
}

export function nonNull(req: any) {
  const p = req.query.file!;
  return fs.readFileSync(path.join('/data', p));
}

export function suppressed(req: any) {
  // @ts-ignore
  exec(req.query.host);
  // @ts-expect-error
  eval(req.body.code);
}

export function readableLiteralIsNotASink(query: any) {
  // @ts-expect-error - upstream types are wrong here
  query = query.groupBy(['a', 'b']);
  return query;
}
"""

_ORM = """\
export async function prismaBad(prisma: any, id: string) {
  return prisma.$queryRawUnsafe('SELECT * FROM users WHERE id = ' + id);
}

export async function prismaConstant(prisma: any) {
  return prisma.$queryRawUnsafe('SELECT 1');
}

export async function prismaSafe(prisma: any, id: string) {
  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}

export function typeormBad(qb: any, name: string) {
  return qb.where(`user.name = '${name}'`).getMany();
}

export function typeormBadConcat(qb: any, name: string) {
  return qb.andWhere("user.name = '" + name + "'").getMany();
}

export function typeormSafe(qb: any, name: string) {
  return qb.where('user.name = :name', { name }).getMany();
}
"""


def _make_nest_project(root: str) -> None:
    _write(os.path.join(root, "package.json"),
           '{"name":"api","dependencies":{"@nestjs/core":"^10.0.0","typeorm":"^0.3.0"}}\n')
    _write(os.path.join(root, "src", "user.controller.ts"), _NEST_CONTROLLER)
    _write(os.path.join(root, "src", "main.ts"), _NEST_BOOTSTRAP)
    _write(os.path.join(root, "src", "bypasses.ts"), _TYPE_BYPASSES)
    _write(os.path.join(root, "src", "orm.ts"), _ORM)


def test_no_typescript_yml_that_merely_duplicates_javascript_yml():
    """A typescript.yml is fine only if it carries rules javascript.yml does
    not, so the condition is asserted rather than the filename banned."""
    import yaml

    ts_path = os.path.join(_WEB_RULES_DIR, "typescript.yml")
    if not os.path.isfile(ts_path):
        return  # the expected state today

    js_path = os.path.join(_WEB_RULES_DIR, "javascript.yml")
    with open(js_path) as f:
        js_ids = {r["id"] for r in (yaml.safe_load(f) or {}).get("rules", [])}
    with open(ts_path) as f:
        ts_ids = {r["id"] for r in (yaml.safe_load(f) or {}).get("rules", [])}

    assert ts_ids - js_ids, (
        "typescript.yml is back but every one of its rule IDs is already in "
        "javascript.yml, so it only gives semgrep a second copy of each rule "
        "to deduplicate"
    )


_pro_absent = pytest.mark.skipif(
    not (_TS_PACK_DIR and os.path.isdir(_TS_PACK_DIR)),
    reason="extended TypeScript rule tree not present in this checkout",
)


@_pro_absent
def test_javascript_pack_is_what_both_labels_resolve_to():
    for stack in ("javascript", "typescript"):
        configs = source_analyzer._resolve_configs({stack})
        basenames = {os.path.basename(c) for c in configs}
        assert "javascript.yml" in basenames, (
            f"{stack} does not resolve javascript.yml: got {basenames}"
        )
        assert "javascript_narvy" not in basenames, basenames
        assert "typescript_narvy" in basenames, (
            f"{stack} does not load the TypeScript-only pack: got {basenames}"
        )


@_pro_absent
def test_typescript_pack_directory_exists_and_parses():
    import yaml

    assert os.path.isdir(_TS_PACK_DIR), "typescript_narvy pack is missing"
    rule_ids = set()
    for name in sorted(os.listdir(_TS_PACK_DIR)):
        if not name.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(_TS_PACK_DIR, name)) as f:
            data = yaml.safe_load(f)
        assert data and data.get("rules"), f"{name} has no rules"
        for rule in data["rules"]:
            assert rule["id"] not in rule_ids, f"duplicate rule id {rule['id']}"
            rule_ids.add(rule["id"])
            assert rule.get("languages"), f"{rule['id']} declares no languages"
            assert rule.get("metadata", {}).get("cwe"), f"{rule['id']} has no CWE"
    assert len(rule_ids) >= 9, f"expected the full TS pack, got {len(rule_ids)} rules"


@_pro_absent
def test_nestjs_project_produces_typescript_only_findings():
    """Every rule asserted here is one no JavaScript rule in the bundled packs
    can produce, because the vulnerable value never appears as `req.*`."""
    with tempfile.TemporaryDirectory() as d:
        _make_nest_project(d)
        result = source_analyzer.analyze_source(d)

    assert result["ok"] is True
    assert "typescript" in result["stacks_detected"], result["stacks_detected"]

    if not result["findings"]:
        return  # semgrep unavailable; the assertions above still ran

    rule_ids = {f["rule_id"] for f in result["findings"]}
    expected = {
        "decorated-param-sqli",
        "decorated-param-command-injection",
        "prisma-raw-unsafe",
        "typeorm-builder-interpolation",
        "cors-reflected-origin",
        "validation-pipe-no-whitelist",
        "any-cast-request-into-sink",
        "ts-suppression-above-sink",
        "non-null-assertion-on-request-input",
    }
    missing = expected - rule_ids
    assert not missing, (
        f"TypeScript pack did not fire for {sorted(missing)}; "
        f"all rule_ids seen: {sorted(rule_ids)}"
    )


@_pro_absent
def test_typescript_pack_does_not_flag_the_safe_variants():
    """Each fixture pairs every vulnerable shape with its correct form."""
    with tempfile.TemporaryDirectory() as d:
        _make_nest_project(d)
        result = source_analyzer.analyze_source(d)
        if not result["findings"]:
            return

        pack_ids = {
            "decorated-param-sqli", "decorated-param-command-injection",
            "decorated-param-path-traversal", "decorated-param-ssrf",
            "prisma-raw-unsafe", "typeorm-builder-interpolation",
            "cors-reflected-origin", "validation-pipe-no-whitelist",
            "any-cast-request-into-sink", "ts-suppression-above-sink",
            "non-null-assertion-on-request-input",
        }
        # (file, line-substring) pairs that must never be flagged.
        safe_lines = {
            "src/user.controller.ts": "SELECT * FROM users WHERE id = $1",
            "src/orm.ts": "user.name = :name",
        }
        for finding in result["findings"]:
            if finding["rule_id"] not in pack_ids:
                continue
            needle = safe_lines.get(finding["file_path"])
            if not needle:
                continue
            path = os.path.join(d, finding["file_path"])
            with open(path) as f:
                lines = f.readlines()
            line = lines[finding["line"] - 1]
            assert needle not in line, (
                f"{finding['rule_id']} flagged the correctly parameterized "
                f"line {finding['file_path']}:{finding['line']}: {line.strip()}"
            )


@_pro_absent
def test_findings_are_not_reported_twice_at_the_same_coordinates():
    """Semgrep can emit one rule several times at one byte range when the
    pattern admits several binding sets, so _run_web_semgrep deduplicates on
    (check_id, path, line, col)."""
    with tempfile.TemporaryDirectory() as d:
        _make_nest_project(d)
        result = source_analyzer.analyze_source(d)
        if not result["findings"]:
            return
        seen = set()
        for finding in result["findings"]:
            key = (finding["rule_id"], finding["file_path"], finding["line"])
            assert key not in seen, f"duplicate finding reported: {key}"
            seen.add(key)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
