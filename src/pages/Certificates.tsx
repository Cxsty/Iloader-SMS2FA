import "./Certificates.css";
import { invoke } from "@tauri-apps/api/core";
import { save, open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useError } from "../ErrorContext";
import { useTranslation } from "react-i18next";

export type Certificate = {
  name: string;
  certificateId: string;
  serialNumber: string;
  machineName: string;
  machineId: string;
};

export const Certificates = () => {
  const { t } = useTranslation();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const loadingRef = useRef<boolean>(false);
  const { err } = useError();

  const loadCertificates = useCallback(async () => {
    if (loadingRef.current) return;
    const promise = async () => {
      loadingRef.current = true;
      setLoading(true);
      let certs = await invoke<Certificate[]>("get_certificates");
      setCertificates(certs);
      setLoading(false);
      loadingRef.current = false;
    };
    toast.promise(promise, {
      loading: t("certificates.loading"),
      success: t("certificates.loaded_success"),
      error: (e) => err(t("certificates.failed_load"), e),
    });
  }, [setCertificates, t]);

  const revokeCertificate = useCallback(
    async (serialNumber: string) => {
      const promise = invoke<void>("revoke_certificate", {
        serialNumber,
      });
      promise.then(loadCertificates);
      toast.promise(promise, {
        loading: t("certificates.revoking"),
        success: t("certificates.revoked_success"),
        error: (e) => err(t("certificates.failed_revoke"), e),
      });
    },
    [setCertificates, loadCertificates, t],
  );

  const exportP12 = useCallback(async () => {
    const path = await save({
      defaultPath: "signing.p12",
      filters: [{ name: "PKCS#12", extensions: ["p12"] }],
    });
    if (!path) return;
    const password = window.prompt("p12 password (leave empty to use machine id)") || "";
    const promise = invoke<void>("export_signing_certificate", { password, path });
    toast.promise(promise, {
      loading: "Exporting signing certificate...",
      success: "Exported signing certificate",
      error: (e) => err("Failed to export signing certificate", e),
    });
  }, [err]);
  const extractProfile = useCallback(async () => {
    const ipa = await open({
      filters: [{ name: "IPA", extensions: ["ipa"] }],
    });
    if (!ipa || Array.isArray(ipa)) return;
    const out = await save({
      defaultPath: "embedded.mobileprovision",
      filters: [{ name: "Provisioning", extensions: ["mobileprovision"] }],
    });
    if (!out) return;
    const promise = invoke<void>("extract_provisioning_profile", { ipaPath: ipa, outputPath: out });
    toast.promise(promise, {
      loading: "Extracting provisioning profile...",
      success: "Extracted provisioning profile",
      error: (e) => err("Failed to extract provisioning profile", e),
    });
  }, [err]);
  const signIpa = useCallback(async () => {
    const ipa = await open({
      filters: [{ name: "IPA", extensions: ["ipa"] }],
    });
    if (!ipa || Array.isArray(ipa)) return;
    const out = await save({
      defaultPath: "signed.ipa",
      filters: [{ name: "IPA", extensions: ["ipa"] }],
    });
    if (!out) return;
    const promise = invoke<void>("sign_ipa_and_save", { ipaPath: ipa, outputPath: out });
    toast.promise(promise, {
      loading: "Signing IPA...",
      success: "Signed IPA saved",
      error: (e) => err("Failed to sign IPA", e),
    });
  }, [err]);

  useEffect(() => {
    loadCertificates();
  }, []);

  return (
    <>
      <h2>{t("certificates.manage")}</h2>
      {certificates.length === 0 ? (
        <div>{loading ? t("certificates.loading") : t("certificates.none_found")}</div>
      ) : (
        <div className="card">
          <div className="certificate-table-container">
            <table className="certificate-table">
              <thead>
                <tr className="certificate-item">
                  <th className="cert-item-part">{t("certificates.name")}</th>
                  <th className="cert-item-part">{t("certificates.serial_number")}</th>
                  <th className="cert-item-part">{t("certificates.machine_name")}</th>
                  <th className="cert-item-part">{t("certificates.machine_id")}</th>
                  <th>{t("certificates.revoke")}</th>
                </tr>
              </thead>
              <tbody>
                {certificates.map((cert, i) => (
                  <tr
                    key={cert.certificateId}
                    className={
                      "certificate-item" +
                      (i === certificates.length - 1 ? " cert-item-last" : "")
                    }
                  >
                    <td className="cert-item-part">{cert.name}</td>
                    <td className="cert-item-part">{cert.serialNumber}</td>
                    <td className="cert-item-part">{cert.machineName}</td>
                    <td className="cert-item-part">{cert.machineId}</td>
                    <td
                      className="cert-item-revoke"
                      role="button"
                      tabIndex={0}
                      onClick={() => revokeCertificate(cert.serialNumber)}
                    >
                      {t("certificates.revoke")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={exportP12}
      >
        Export signing certificate (.p12)
      </button>
      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={extractProfile}
      >
        Extract provisioning profile from IPA
      </button>
      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={signIpa}
      >
        Sign IPA and save
      </button>
      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={loadCertificates}
        disabled={loading}
      >
        {t("common.refresh")}
      </button>
    </>
  );
};
