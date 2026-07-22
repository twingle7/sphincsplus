#!/usr/bin/env python3
"""Deduplicate and sort papers from all MCP search result files."""
import json, os, re, sys
from pathlib import Path

TOOL_RESULTS = Path(os.environ.get(
    "TOOL_RESULTS_DIR",
    r"C:\Users\Twinkle\.claude\projects\D--Desktop-sphincsplus\56011dd9-34aa-458b-ac0a-6dda1fbf66c1\tool-results"
))

def normalize_title(t):
    return re.sub(r'[^a-z0-9]', '', t.lower()) if t else ''

def first_author_name(authors):
    if not authors: return ''
    a = authors[0]
    if isinstance(a, dict):
        return a.get('name', '') or ''
    return str(a)

def extract_papers(filepath):
    """Extract paper records from a tool result JSON file."""
    papers = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except:
        return papers

    if 'results' in data:
        for r in data['results']:
            title = r.get('title', '')
            if not title or len(title) < 10:
                continue
            papers.append({
                'title': title,
                'year': r.get('year'),
                'doi': (r.get('doi') or '').lower(),
                'paperId': r.get('paperId', ''),
                'citationCount': r.get('citationCount', 0) or 0,
                'venue': r.get('venue', ''),
                'authors': [a.get('name','') if isinstance(a,dict) else str(a) for a in r.get('authors', [])],
                'openAccess': r.get('openAccess', {}).get('isOpenAccess', False),
                'pdfUrl': r.get('openAccess', {}).get('pdfUrl', ''),
                'abstract': r.get('abstract', ''),
                'query': data.get('query', ''),
            })
    return papers

def main():
    all_papers = []
    for f in sorted(TOOL_RESULTS.glob('call_*.txt')):
        papers = extract_papers(f)
        all_papers.extend(papers)

    print(f"Total raw records: {len(all_papers)}")

    # Dedup by DOI first
    seen_doi = set()
    seen_key = set()
    unique = []

    for p in all_papers:
        # Dedup by DOI
        doi = p['doi']
        if doi and doi in seen_doi:
            # Update citation count if higher
            for up in unique:
                if up['doi'] == doi:
                    up['citationCount'] = max(up['citationCount'], p['citationCount'])
                    if p['abstract'] and not up['abstract']:
                        up['abstract'] = p['abstract']
                    break
            continue

        # Dedup by (normalized_title, first_author, year)
        key = (normalize_title(p['title']), first_author_name(p['authors']), p['year'])
        if key in seen_key:
            for up in unique:
                uk = (normalize_title(up['title']), first_author_name(up['authors']), up['year'])
                if uk == key:
                    up['citationCount'] = max(up['citationCount'], p['citationCount'])
                    if p['doi'] and not up['doi']:
                        up['doi'] = p['doi']
                    break
            continue

        if doi:
            seen_doi.add(doi)
        seen_key.add(key)
        unique.append(p)

    print(f"After dedup: {len(unique)} papers")

    # Filter noise: must have authors, non-trivial title
    filtered = [p for p in unique
                if p['authors']
                and len(p['title']) > 15
                and not any(w in p['title'].lower() for w in ['table ', 'figure ', 'algorithm ', 'supplemental '])]
    print(f"After filtering noise: {len(filtered)} papers")

    # Sort by citations desc
    filtered.sort(key=lambda x: x['citationCount'], reverse=True)

    # Save
    out_path = Path(r'D:\Desktop\sphincsplus\literature-review\master_paper_list.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total': len(filtered),
            'generated': '2026-07-22',
            'papers': filtered
        }, f, indent=2, ensure_ascii=False)

    print(f"Saved to {out_path}")

    # Print top 20
    print("\n=== TOP 20 by citations ===")
    for i, p in enumerate(filtered[:20]):
        authors = ', '.join(p['authors'][:3])
        if len(p['authors']) > 3:
            authors += ' et al.'
        print(f"{i+1}. [{p['citationCount']}] {authors} ({p['year']}) - {p['title'][:100]}")
        if p['doi']:
            print(f"   DOI: {p['doi']}")

if __name__ == '__main__':
    main()
