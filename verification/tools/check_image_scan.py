"""Reject fixable severe vulnerabilities without hiding unfixed findings."""
import json
import sys


def check(report):
    if not isinstance(report, dict) or not isinstance(report.get('matches'), list):
        raise ValueError('Invalid image vulnerability report')
    unfixed = set()
    fixed = set()
    for match in report['matches']:
        vulnerability = match.get('vulnerability') if isinstance(match, dict) else None
        if not isinstance(vulnerability, dict):
            raise ValueError('Invalid vulnerability entry')
        identifier = vulnerability.get('id')
        severity = vulnerability.get('severity')
        fix = vulnerability.get('fix')
        if not isinstance(identifier, str) or not identifier or severity not in {
            'Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'
        } or not isinstance(fix, dict) or not isinstance(fix.get('versions'), list):
            raise ValueError('Invalid vulnerability metadata')
        if not all(isinstance(version, str) and version for version in fix['versions']):
            raise ValueError('Invalid fix versions')
        if severity in {'Critical', 'High'}:
            (fixed if fix['versions'] else unfixed).add(identifier)
    if fixed:
        raise ValueError('Fixable severe vulnerabilities: ' + ', '.join(sorted(fixed)))
    return sorted(unfixed)


if __name__ == '__main__':
    try:
        with open(sys.argv[1], encoding='utf-8') as source:
            unfixed = check(json.load(source))
    except (OSError, ValueError, IndexError) as error:
        raise SystemExit(str(error)) from error
    print('No fixable High/Critical findings. Unfixed severe findings requiring vendor/reachability review:')
    print('\n'.join(unfixed) if unfixed else 'none')
