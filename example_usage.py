from client import SchnorrZeroKnowledgeProver

def run_example():
    print("=== GenPark Schnorr ZKP Example ===")
    prover = SchnorrZeroKnowledgeProver()
    print("ZKP Verification Result:", prover.benchmark_schnorr_zkp())

if __name__ == "__main__":
    run_example()
