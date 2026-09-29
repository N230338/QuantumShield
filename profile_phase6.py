"""Temporary stage profiler for one BB84 run in each mode."""

from __future__ import annotations

import time

from backend.app.bb84 import core, eve


def profile(label: str, attack: bool) -> None:
    totals = {"circuit_building": 0.0, "transpile": 0.0, "aer_run_and_result": 0.0}
    original_build_core = core.build_qubit_circuit
    original_build_eve = eve.build_qubit_circuit
    original_transpile_core = core.transpile
    original_transpile_eve = eve.transpile
    original_sim_core = core.AerSimulator
    original_sim_eve = eve.AerSimulator

    def timed_build(original):
        def wrapped(*args, **kwargs):
            started = time.perf_counter()
            value = original(*args, **kwargs)
            totals["circuit_building"] += time.perf_counter() - started
            return value
        return wrapped

    def timed_transpile(original):
        def wrapped(*args, **kwargs):
            started = time.perf_counter()
            value = original(*args, **kwargs)
            totals["transpile"] += time.perf_counter() - started
            return value
        return wrapped

    def timed_simulator(original):
        class SimulatorProxy:
            def __init__(self, *args, **kwargs):
                self.backend = original(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self.backend, name)

            def run(self, *args, **kwargs):
                started = time.perf_counter()
                job = self.backend.run(*args, **kwargs)
                class JobProxy:
                    def result(self, *result_args, **result_kwargs):
                        result_started = time.perf_counter()
                        result = job.result(*result_args, **result_kwargs)
                        totals["aer_run_and_result"] += time.perf_counter() - result_started
                        return result
                totals["aer_run_and_result"] += time.perf_counter() - started
                return JobProxy()
        return SimulatorProxy

    core.build_qubit_circuit = timed_build(original_build_core)
    eve.build_qubit_circuit = timed_build(original_build_eve)
    core.transpile = timed_transpile(original_transpile_core)
    eve.transpile = timed_transpile(original_transpile_eve)
    core.AerSimulator = timed_simulator(original_sim_core)
    eve.AerSimulator = timed_simulator(original_sim_eve)

    started = time.perf_counter()
    result = core.run_bb84_qiskit(128, seed=128, attack=attack)
    elapsed = time.perf_counter() - started
    totals["other"] = elapsed - sum(totals.values())
    print(label, "total_seconds=", round(elapsed, 4))
    print(label, "stage_seconds=", {name: round(value, 4) for name, value in totals.items()})
    print(label, "baseline=", {
        "bob_bits": result["bob_bits"],
        "eve_bases": result["eve_bases"],
        "eve_bits": result["eve_bits"],
        "intercepted_mask": result["intercepted_mask"],
        "matching_positions": result["matching_positions"],
        "sampled_positions": result["sampled_positions"],
        "final_key": result["final_key"],
        "decision": result["decision"].value,
        "qber_sample_qber": result["qber_sample_qber"],
        "qber_full_sifted": result["qber_full_sifted"],
    })

profile("normal", False)
profile("attack", True)
