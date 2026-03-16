#!/usr/bin/env python3
"""pcapsum - Network connection summary using lsof/netstat."""
import subprocess, argparse, re, sys, collections, json

def get_connections():
    try:
        out = subprocess.check_output(['lsof', '-i', '-n', '-P'], text=True, stderr=subprocess.DEVNULL)
    except:
        out = subprocess.check_output(['netstat', '-an'], text=True, stderr=subprocess.DEVNULL)
    return out

def parse_lsof(output):
    conns = []
    for line in output.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 9:
            conns.append({
                'process': parts[0], 'pid': parts[1], 'user': parts[2],
                'type': parts[4], 'protocol': parts[7] if len(parts) > 7 else '',
                'name': parts[-1]
            })
    return conns

def main():
    p = argparse.ArgumentParser(description='Network connection summary')
    p.add_argument('--process', help='Filter by process')
    p.add_argument('--listen', action='store_true', help='Listening only')
    p.add_argument('--established', action='store_true', help='Established only')
    p.add_argument('-j', '--json', action='store_true')
    p.add_argument('--by-process', action='store_true', help='Group by process')
    p.add_argument('--by-port', action='store_true', help='Group by port')
    args = p.parse_args()

    output = get_connections()
    conns = parse_lsof(output)

    if args.process:
        conns = [c for c in conns if args.process.lower() in c['process'].lower()]
    if args.listen:
        conns = [c for c in conns if 'LISTEN' in c.get('name', '')]
    if args.established:
        conns = [c for c in conns if 'ESTABLISHED' in c.get('protocol', '') or '->' in c.get('name', '')]

    if args.json:
        print(json.dumps(conns, indent=2)); return

    if args.by_process:
        groups = collections.Counter(c['process'] for c in conns)
        for proc, count in groups.most_common():
            print(f"  {count:>4}  {proc}")
    elif args.by_port:
        ports = collections.Counter()
        for c in conns:
            m = re.search(r':(\d+)', c.get('name', ''))
            if m: ports[m.group(1)] += 1
        for port, count in ports.most_common(20):
            print(f"  :{port:<6} {count} connections")
    else:
        print(f"{'PROCESS':<15} {'PID':<8} {'USER':<10} {'TYPE':<6} {'CONNECTION'}")
        for c in conns[:50]:
            print(f"{c['process']:<15} {c['pid']:<8} {c['user']:<10} {c['type']:<6} {c['name'][:60]}")
        if len(conns) > 50:
            print(f"\n... +{len(conns)-50} more")
    
    print(f"\nTotal: {len(conns)} connections")

if __name__ == '__main__':
    main()
