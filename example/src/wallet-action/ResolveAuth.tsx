import { useState } from "react";
import { IPropsWalletAction } from "./wallet-action.types.ts";

export const ResolveAuth = ({ wallet, network }: IPropsWalletAction) => {
  const [domain, setDomain] = useState("example.app");
  const [action, setAction] = useState("Approve");
  const [msg, setMsg] = useState("Approve withdrawal of 100 USDC to bob.near");
  const [result, setResult] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(false);

  const handleResolveAuth = async () => {
    if (!wallet.resolveAuth) {
      setError("This wallet does not support resolveAuth (NEP-641)");
      return;
    }
    setResult("");
    setError("");
    setLoading(true);
    try {
      // NEP-641 recommends the domain-separated JSON payload so wallets render
      // it consistently and the dApp can rule out cross-dApp/cross-action replay.
      const payload = JSON.stringify({ domain, action, msg }, null, 2);
      const res = await wallet.resolveAuth({ payload, network });
      setResult(JSON.stringify(res, null, 2));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={"input-form"}>
      <p className={"input-form-label"}>NEP-641 Auth Resolve</p>
      <div className={"flex flex-col gap-3"}>
        <div className={"input-group"}>
          <p className={"input-label"}>Domain (dApp)</p>
          <input className={"input-text"} type="text" value={domain} onChange={(e) => setDomain(e.target.value)} />
        </div>
        <div className={"input-group"}>
          <p className={"input-label"}>Action</p>
          <input className={"input-text"} type="text" value={action} onChange={(e) => setAction(e.target.value)} />
        </div>
        <div className={"input-group"}>
          <p className={"input-label"}>Message</p>
          <input className={"input-text"} type="text" value={msg} onChange={(e) => setMsg(e.target.value)} />
        </div>
        <div className={"flex gap-2"}>
          <button className={"input-button compact flex-1"} disabled={loading} onClick={handleResolveAuth}>
            {loading ? "Signing..." : "Authorize"}
          </button>
        </div>
        {result && (
          <details open className={"border border-[rgb(42,42,42)] rounded-lg p-3"}>
            <summary className={"cursor-pointer select-none text-left text-xs text-[rgb(126,130,144)]"}>
              Authorization result
            </summary>
            <pre
              className={"input-text mono mt-2 whitespace-pre-wrap break-all"}
              style={{ textAlign: "left", fontSize: "0.75rem" }}
            >
              {result}
            </pre>
          </details>
        )}
        {error && <p className={"text-left text-xs text-red-400"}>{error}</p>}
      </div>
    </div>
  );
};
