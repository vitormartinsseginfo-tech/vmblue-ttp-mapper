#!/usr/bin/env python3
"""
Gera um índice compacto que mapeia técnicas MITRE ATT&CK -> regras Sigma.
Uso:
  1) baixe o SigmaHQ:  curl -L -o sigma.tar.gz https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master
  2) extraia:          mkdir sigma && tar xzf sigma.tar.gz -C sigma
  3) rode:             python3 build_sigma_index.py sigma/sigma-master sigma-index.json
Hospede o sigma-index.json (Pages, R2, KV...) e aponte o Worker para ele.
"""
import os, sys, json, yaml

# Pastas consideradas (detecção). Ajuste se quiser incluir/excluir conjuntos.
INCLUDE_DIRS = ['rules', 'rules-emerging-threats', 'rules-threat-hunting', 'rules-dfir']
BRANCH = 'master'
REPO_BLOB = 'https://github.com/SigmaHQ/sigma/blob/' + BRANCH + '/'
LEVEL_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}

def main(root, out):
    index = {}          # techid -> list of rule entries
    seen = set()        # (techid, rule_id) para evitar duplicata
    total_rules = 0
    indexed_rules = 0

    for sub in INCLUDE_DIRS:
        base = os.path.join(root, sub)
        if not os.path.isdir(base):
            continue
        for dirpath, _, files in os.walk(base):
            for fn in files:
                if not fn.endswith('.yml'):
                    continue
                path = os.path.join(dirpath, fn)
                total_rules += 1
                try:
                    with open(path, encoding='utf-8') as f:
                        doc = yaml.safe_load(f)
                except Exception:
                    continue
                if not isinstance(doc, dict):
                    continue
                tags = doc.get('tags') or []
                techs = []
                for t in tags:
                    t = str(t).lower()
                    if t.startswith('attack.t') and len(t) > 8:
                        tid = t.split('.', 1)[1].upper()  # attack.t1059.001 -> T1059.001
                        # normaliza subtécnica: T1059.001 (mantém ponto)
                        techs.append(tid.replace('.', '.', 1))
                if not techs:
                    continue
                ls = doc.get('logsource') or {}
                rel = os.path.relpath(path, root).replace(os.sep, '/')
                entry = {
                    'title': doc.get('title', '').strip(),
                    'id': doc.get('id', ''),
                    'level': doc.get('level', ''),
                    'status': doc.get('status', ''),
                    'product': ls.get('product', ''),
                    'service': ls.get('service', ''),
                    'category': ls.get('category', ''),
                    'url': REPO_BLOB + rel
                }
                counted = False
                for tid in set(techs):
                    key = (tid, entry['id'] or entry['url'])
                    if key in seen:
                        continue
                    seen.add(key)
                    index.setdefault(tid, []).append(entry)
                    counted = True
                if counted:
                    indexed_rules += 1

    # ordena cada lista por severidade
    for tid in index:
        index[tid].sort(key=lambda e: LEVEL_RANK.get(e.get('level', ''), 9))

    meta = {
        'source': 'SigmaHQ/sigma@' + BRANCH,
        'techniques_covered': len(index),
        'rules_indexed': indexed_rules,
        'rules_scanned': total_rules
    }
    with open(out, 'w', encoding='utf-8') as f:
        json.dump({'_meta': meta, 'index': index}, f, ensure_ascii=False, separators=(',', ':'))

    print(json.dumps(meta, indent=2, ensure_ascii=False))
    print('Tamanho:', round(os.path.getsize(out) / 1024 / 1024, 2), 'MB ->', out)

if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else 'sigma/sigma-master'
    out = sys.argv[2] if len(sys.argv) > 2 else 'sigma-index.json'
    main(root, out)
