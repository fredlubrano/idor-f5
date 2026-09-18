# Hugging Face — modèle spécifique IDOR / aspiration

Ce guide explique comment **créer et brancher** un modèle HF calé sur le besoin de [idor-f5](https://github.com/fredlubrano/idor-f5) : détecter un **compte authentifié** qui aspire la DB via API (souvent en **HTTP 200**), pas du SQLi/XSS classique.

Aucun modèle public ne fait ça out-of-the-box. Tu entraînes le tien sur **les features déjà calculées par l’iRule**.

## Objectif du modèle

| Entrée | Sortie |
| --- | --- |
| Vecteur / texte des features session (IDs hashés, pas de bodies/tokens) | Label + score, mappé vers `confirm \| dismiss \| boost` |

Labels (`ml/label_map.json`) :

| id | name | Signification |
| --- | --- | --- |
| 0 | `normal` | Trafic métier dans la baseline |
| 1 | `legitim_sync` | Sync / pagination / burst court légitime |
| 2 | `sequential_enum` | Énumération scriptée (IDs monotones, rate élevé) |
| 3 | `data_aspiration` | Auth + beaucoup de 200 + distinct IDs + volume/focus |

Mapping vers iRulesLX (même contrat que [AI.md](AI.md)) :

| Label modèle | Action LX |
| --- | --- |
| `normal`, `legitim_sync` | `dismiss` |
| `sequential_enum` | `confirm` ou `boost` selon confiance |
| `data_aspiration` | `boost` (threat high si conf élevée) |

## Pipeline

```text
Shadow iRule → JSONL features → labels lab
       → train (sklearn OU DistilBERT/SmolLM OU LoRA Qwen)
       → push Hub privé
       → Inference Endpoint / TGI / vLLM
       → MU_AI_ENDPOINT + local_only_llm
```

Détail des outils : dossier [`ml/`](../ml/).

## Étape 1 — Collecter des features (shadow)

1. `mitigation.shadow: true` et/ou `ai.action: shadow` dans `config/default.yaml`
2. Exporter périodiquement les compteurs session (même schéma que le payload LX) vers un fichier JSONL
3. Schéma : `ml/schemas/feature_record.schema.json`
4. **Jamais** : Authorization, cookies bruts, bodies, object-ids en clair (`hash_ids: true`)

En lab sans BIG-IP, génère un jeu synthétique :

```bash
python ml/synthesize_dataset.py --out ml/data/train.jsonl --n 2000
```

## Étape 2 — Labeller

- Scripts d’attaque lab → label `sequential_enum` / `data_aspiration`
- Sync mobile / pagination → `legitim_sync`
- Trafic UI mixte → `normal`
- Colonne `label` (string) ou `label_id` (int) dans chaque ligne JSONL

Vérifier l’équilibre des classes (éviter 95 % `normal`).

## Étape 3 — Entraîner (3 options)

### A — Tabular rapide (recommandé pour commencer)

```bash
python ml/train_classifier.py --backend sklearn \
  --train ml/data/train.jsonl --out ml/artifacts/sklearn_model.joblib
```

Features numériques uniquement ; export ONNX possible ensuite.

### B — Sequence classification HF (texte sérialisé)

```bash
python ml/train_classifier.py --backend transformers \
  --model distilbert-base-uncased \
  --train ml/data/train.jsonl \
  --out ml/artifacts/idor-aspiration-clf \
  --push_to_hub fredlubrano/idor-aspiration-clf
```

Chaque exemple devient une phrase du type :

`auth=1 distinct=35 seq=0.82 focus=0.9 ok=0.95 bytes=8500000 aspiration=0.71 template=/api/accounts/{id}`

### C — Instruct LoRA (juge JSON, remplace gpt-4o-mini)

Base : [Qwen/Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct)  
Même prompt/contrat que `iruleslx/ai_enrich`. Plus lourd ; utile en `dual_judge` après A/B.

## Étape 4 — Évaluer

Optimiser surtout le **recall de `data_aspiration`** (rater un dump est pire qu’un faux positif calibrable).

```bash
python ml/train_classifier.py --backend sklearn \
  --train ml/data/train.jsonl --eval ml/data/train.jsonl --report
```

Garder une matrice de confusion et un seuil de confiance : sous le seuil → **fail-open** (`confirm` déterministe iRule).

## Étape 5 — Servir et brancher BIG-IP

1. Déployer le modèle (HF Inference Endpoint, TGI, ou petit service FastAPI dans `ml/serve_stub.py`)
2. Config :

```yaml
ai:
  privacy:
    local_only_llm: true
    local_endpoint: "https://<ton-endpoint>/v1/classify"
  model: fredlubrano/idor-aspiration-clf
```

3. Adapter `iruleslx/ai_enrich` pour appeler `/v1/classify` (label → action) si tu n’utilises pas l’API chat OpenAI-compatible.

Voir `ml/serve_stub.py` : API minimale `POST /v1/classify` → `{ action, threat, pattern, idor_likelihood, reason }`.

## Modèles HF publics utiles en *complément* (pas en remplacement)

| Modèle | Usage |
| --- | --- |
| [SecInt-SmolLM2-360M-nginx](https://huggingface.co/LeviDeHaan/SecInt-SmolLM2-360M-nginx) | Ligne access log hack/error/normal |
| [u-haru/log-inspector](https://huggingface.co/u-haru/log-inspector) | Access log suspicious/safe |
| [Qwen2.5-0.5B-Instruct](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct) | Base juge local instruct |

Ils ne voient pas “N object-ids distincts / baseline user”. Ton classifieur custom, oui.

## Ce qu’un modèle HF ne remplacera jamais

- Preuve d’**ownership** (fix applicatif)
- Mitigation (rate-limit / block iRule)
- Calibration continue (`ai.calibration.feedback`)

## Ordre recommandé

1. `synthesize_dataset` + `train_classifier --backend sklearn`  
2. Shadow A/B sur lab  
3. Train DistilBERT + Hub privé  
4. Inference Endpoint → LX  
5. Option LoRA Qwen pour `reason` / dual_judge  
