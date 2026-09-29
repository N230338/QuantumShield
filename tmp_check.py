from backend.app.bb84.core import run_bb84_qiskit
r = run_bb84_qiskit(128, seed=7, attack=False)
print('decision=', r['decision'])
print('qber=', r['qber'])
print('sifted=', len(r['matching_positions']))
