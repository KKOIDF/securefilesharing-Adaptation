import { useState, useEffect } from "react";
import "@/App.css";
import axios from "axios";
import { Toaster, toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Lock, Upload, Download, Share2, Trash2, Shield, Users, Activity, FileText, LogOut, Key } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "http://127.0.0.1:8000";
const API = `${BACKEND_URL}/api`;
const GOOGLE_CLIENT_ID = process.env.REACT_APP_GOOGLE_CLIENT_ID;

function App() {
  const [view, setView] = useState("landing"); // landing, otp, dashboard
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [pendingEmail, setPendingEmail] = useState("");
  const [otpExpiresMinutes, setOtpExpiresMinutes] = useState(5);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [googleSigningIn, setGoogleSigningIn] = useState(false);

  // Public share link
  const [shareToken, setShareToken] = useState(null);
  const [shareLoading, setShareLoading] = useState(false);
  const [shareFileName, setShareFileName] = useState("");
  const [shareAccessCode, setShareAccessCode] = useState("");
  
  // Files
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadDialog, setUploadDialog] = useState(false);
  const [pendingUploadFile, setPendingUploadFile] = useState(null);
  const [pendingUploadPassword, setPendingUploadPassword] = useState("");

  const [downloadDialog, setDownloadDialog] = useState(false);
  const [downloadTarget, setDownloadTarget] = useState(null);
  const [downloadAccessCode, setDownloadAccessCode] = useState("");
  const [downloading, setDownloading] = useState(false);
  
  // Admin
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({});
  const [exampleStatus, setExampleStatus] = useState(null);
  const [deployChecklist, setDeployChecklist] = useState([]);
  
  // Dialogs
  const [shareDialog, setShareDialog] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [shareEmail, setShareEmail] = useState("");
  const [shareRole, setShareRole] = useState("viewer");

  const [accessCodeEmail, setAccessCodeEmail] = useState("");
  const [accessCodeTtl, setAccessCodeTtl] = useState("10");
  const [accessCodeCustom, setAccessCodeCustom] = useState("");
  const [createdAccessCode, setCreatedAccessCode] = useState("");
  const [creatingAccessCode, setCreatingAccessCode] = useState(false);

  const [accessCodes, setAccessCodes] = useState([]);
  const [loadingAccessCodes, setLoadingAccessCodes] = useState(false);
  const [revokingAccessCodeId, setRevokingAccessCodeId] = useState(null);

  const [renameDialog, setRenameDialog] = useState(false);
  const [renameValue, setRenameValue] = useState("");
  const [renaming, setRenaming] = useState(false);

  const [versionTarget, setVersionTarget] = useState(null);
  const [uploadingVersion, setUploadingVersion] = useState(false);

  const [linkDialog, setLinkDialog] = useState(false);
  const [linkExpires, setLinkExpires] = useState("10");
  const [linkMaxUses, setLinkMaxUses] = useState("1");
  const [linkZeroKnowledge, setLinkZeroKnowledge] = useState(true);
  const [createdLinkUrl, setCreatedLinkUrl] = useState("");
  const [linkAccessCode, setLinkAccessCode] = useState("");
  const [createdLinkAccessCode, setCreatedLinkAccessCode] = useState("");
  const [creatingLink, setCreatingLink] = useState(false);

  useEffect(() => {
    // Support public share links without login
    const path = window.location.pathname || "";
    if (path.startsWith("/share/")) {
      const tok = path.replace("/share/", "").split("/")[0];
      if (tok) {
        setShareToken(tok);
        setView("share");
        return;
      }
    }

    const savedToken = localStorage.getItem("token");
    const savedUser = localStorage.getItem("user");
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
      setView("dashboard");
    }
  }, []);

  useEffect(() => {
    if (view === "dashboard" && token) {
      loadFiles();
      loadExampleData();
      if (user?.role === "admin") {
        loadAdminData();
      }
    }
  }, [view, token]);

  useEffect(() => {
    if (view !== "otp" || resendCooldown <= 0) return undefined;
    const timer = window.setInterval(() => {
      setResendCooldown((current) => {
        if (current <= 1) {
          window.clearInterval(timer);
          return 0;
        }
        return current - 1;
      });
    }, 1000);

    return () => window.clearInterval(timer);
  }, [view, resendCooldown]);

  useEffect(() => {
    if (shareDialog && selectedFile?.id) {
      loadAccessCodes(selectedFile.id);
    }
  }, [shareDialog, selectedFile?.id]);

  const ensureGoogleScript = () => {
    if (window.google?.accounts?.id) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const existing = document.querySelector('script[data-google-identity="true"]');
      if (existing) {
        existing.addEventListener("load", () => resolve());
        existing.addEventListener("error", () => reject(new Error("Failed to load Google Identity script")));
        return;
      }
      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      script.dataset.googleIdentity = "true";
      script.onload = () => resolve();
      script.onerror = () => reject(new Error("Failed to load Google Identity script"));
      document.head.appendChild(script);
    });
  };

  const handleGoogleCredential = async (credentialResponse) => {
    const idToken = credentialResponse?.credential;
    if (!idToken) {
      toast.error("Google login failed (missing credential)");
      return;
    }
    try {
      setGoogleSigningIn(true);
      const res = await axios.post(`${API}/auth/google`, { id_token: idToken });
      setToken(res.data.access_token);
      setUser(res.data.user);
      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("user", JSON.stringify(res.data.user));
      toast.success("Login successful!");
      setView("dashboard");
    } catch (err) {
      toast.error(prettyApiError(err, "Google login failed"));
    } finally {
      setGoogleSigningIn(false);
    }
  };

  useEffect(() => {
    if (view !== "landing") return;
    if (!GOOGLE_CLIENT_ID) return;

    let cancelled = false;
    (async () => {
      try {
        await ensureGoogleScript();
        if (cancelled) return;

        window.google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCredential,
        });

        const el = document.getElementById("google-signin-btn");
        if (el) {
          el.innerHTML = "";
          window.google.accounts.id.renderButton(el, {
            theme: "outline",
            size: "large",
            shape: "rectangular",
          });
        }
      } catch (e) {
        // Silent fail: keep email/password login working.
        console.warn(e);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [view]);

  const axiosConfig = () => ({
    headers: { Authorization: `Bearer ${token}` }
  });

  const prettyApiError = (err, fallback) => {
    const status = err?.response?.status;
    const detail = err?.response?.data?.detail;
    if (status === 503) return detail || "Database unavailable (MongoDB not running)";
    return detail || fallback;
  };

  // ========== CRYPTO HELPERS (Share Link) ==========

  const b64ToBytes = (b64) => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };

  const bytesToB64Url = (bytes) => {
    let bin = "";
    bytes.forEach((b) => (bin += String.fromCharCode(b)));
    const b64 = btoa(bin);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  const b64UrlToBytes = (b64url) => {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
    return b64ToBytes(b64);
  };

  const concatBytes = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  };

  const bufferToHex = (buf) =>
    [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

  const pkcs7Unpad = (bytes) => {
    const pad = bytes[bytes.length - 1];
    if (pad < 1 || pad > 16) throw new Error("Invalid padding");
    return bytes.slice(0, bytes.length - pad);
  };

  const importAesKey = async (rawBytes, mode) => {
    const algo = mode === "gcm" ? { name: "AES-GCM" } : { name: "AES-CBC" };
    return window.crypto.subtle.importKey("raw", rawBytes, algo, false, ["decrypt"]);
  };

  const unwrapFileKey = async ({ encryptedFileKey, token: tok, fragmentSecret }) => {
    const iv = b64ToBytes(encryptedFileKey.ivB64);
    const tag = b64ToBytes(encryptedFileKey.tagB64);
    const ciphertext = b64ToBytes(encryptedFileKey.ciphertextB64);

    let wrapKeyBytes;
    if (encryptedFileKey.wrap === "fragment-secret" && fragmentSecret) {
      wrapKeyBytes = b64UrlToBytes(fragmentSecret);
    } else {
      const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(tok));
      wrapKeyBytes = new Uint8Array(digest);
    }

    const key = await window.crypto.subtle.importKey("raw", wrapKeyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const combined = concatBytes(ciphertext, tag);
    const plaintextKey = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      combined
    );
    return new Uint8Array(plaintextKey);
  };

  const decryptSharedFile = async ({ fileKeyBytes, enc }) => {
    const iv = b64ToBytes(enc.ivB64);
    const ciphertext = b64ToBytes(enc.ciphertextB64);

    if (enc.mode === "gcm") {
      const tag = b64ToBytes(enc.tagB64);
      const combined = concatBytes(ciphertext, tag);
      const key = await importAesKey(fileKeyBytes, "gcm");
      const pt = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, combined);
      return new Uint8Array(pt);
    }

    // legacy cbc
    const key = await importAesKey(fileKeyBytes, "cbc");
    const pt = await window.crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
    return pkcs7Unpad(new Uint8Array(pt));
  };

  const downloadBlob = (bytes, filename) => {
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  // ========== AUTH ==========

  const handleRegister = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
      const res = await axios.post(`${API}/auth/register`, {
        email: formData.get("email"),
        password: formData.get("password"),
        full_name: formData.get("full_name"),
        role: formData.get("role") || "user"
      });
      toast.success("Registration successful! Please login.");
      document.getElementById("login-tab-trigger").click();
    } catch (err) {
      toast.error(prettyApiError(err, "Registration failed"));
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get("email");
    try {
      const res = await axios.post(`${API}/auth/login`, {
        email,
        password: formData.get("password")
      });
      setPendingEmail(email);
      setOtpExpiresMinutes(res.data.expires_in_minutes || 5);
      setResendCooldown(res.data.resend_cooldown_seconds || 0);
      toast.success("OTP sent to your email!");
      setView("otp");
    } catch (err) {
      toast.error(prettyApiError(err, "Login failed"));
    }
  };

  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const otp = formData.get("otp");
    try {
      const res = await axios.post(`${API}/auth/verify-otp`, {
        email: pendingEmail,
        otp
      });
      setToken(res.data.access_token);
      setUser(res.data.user);
      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("user", JSON.stringify(res.data.user));
      toast.success("Login successful!");
      setView("dashboard");
    } catch (err) {
      toast.error(prettyApiError(err, "Invalid OTP"));
    }
  };

  const handleResendOTP = async () => {
    try {
      const res = await axios.post(`${API}/auth/resend-otp`, { email: pendingEmail });
      setOtpExpiresMinutes(res.data.expires_in_minutes || 5);
      setResendCooldown(res.data.resend_cooldown_seconds || 0);
      toast.success("A new OTP was sent to your email!");
    } catch (err) {
      toast.error(prettyApiError(err, "Failed to resend OTP"));
    }
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    setPendingEmail("");
    setResendCooldown(0);
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setView("landing");
    toast.success("Logged out successfully");
  };

  // ========== FILES ==========

  const loadFiles = async () => {
    try {
      const res = await axios.get(`${API}/files/list`, axiosConfig());
      setFiles(res.data.files);
    } catch (err) {
      toast.error("Failed to load files");
    }
  };

  const loadExampleData = async () => {
    try {
      const [statusRes, checklistRes] = await Promise.all([
        axios.get(`${API}/examples/status`, axiosConfig()),
        axios.get(`${API}/examples/deploy-checklist`, axiosConfig()),
      ]);
      setExampleStatus(statusRes.data);
      setDeployChecklist(checklistRes.data.steps || []);
    } catch (err) {
      toast.error("Failed to load example module data");
    }
  };

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setPendingUploadFile(file);
    setPendingUploadPassword("");
    setUploadDialog(true);
    e.target.value = "";
  };

  const confirmUpload = async () => {
    const file = pendingUploadFile;
    const accessPassword = pendingUploadPassword;
    if (!file) {
      toast.error("No file selected");
      return;
    }
    if (!accessPassword || accessPassword.length < 4) {
      toast.error("Enter a file password (min 4 chars)");
      return;
    }

    setUploading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("access_password", accessPassword);
      const res = await axios.post(`${API}/files/upload`, formData, axiosConfig());
      toast.success(`File encrypted and uploaded: ${res.data.filename}`);
      setUploadDialog(false);
      setPendingUploadFile(null);
      setPendingUploadPassword("");
      loadFiles();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  const handleDownload = async (fileId, filename, accessCode) => {
    if (!accessCode) {
      toast.error("Access code required");
      return false;
    }
    try {
      setDownloading(true);
      const res = await axios.get(`${API}/files/download/${fileId}`, {
        ...axiosConfig(),
        responseType: "blob",
        headers: {
          ...(axiosConfig()?.headers || {}),
          "X-File-Access-Code": accessCode,
        },
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast.success("File downloaded and decrypted");
      return true;
    } catch (err) {
      toast.error(prettyApiError(err, "Download failed"));
      return false;
    } finally {
      setDownloading(false);
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm("Delete this file?")) return;
    try {
      await axios.delete(`${API}/files/delete/${fileId}`, axiosConfig());
      toast.success("File deleted");
      loadFiles();
    } catch (err) {
      toast.error("Delete failed");
    }
  };

  const handleShare = async () => {
    if (!shareEmail) {
      toast.error("Enter an email");
      return;
    }
    if (!selectedFile) {
      toast.error("No file selected");
      return;
    }
    try {
      await axios.post(
        `${API}/files/share/${selectedFile.id}`,
        { email: shareEmail, role: shareRole },
        axiosConfig()
      );
      toast.success(`File shared with ${shareEmail}`);
      closeShareDialog();
      loadFiles();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Share failed");
    }
  };

  const closeShareDialog = () => {
    setShareDialog(false);
    setShareEmail("");
    setShareRole("viewer");
    setSelectedFile(null);
    setAccessCodeEmail("");
    setAccessCodeTtl("10");
    setAccessCodeCustom("");
    setCreatedAccessCode("");
    setCreatingAccessCode(false);
    setAccessCodes([]);
    setLoadingAccessCodes(false);
    setRevokingAccessCodeId(null);
  };

  const loadAccessCodes = async (fileId) => {
    if (!fileId) return;
    setLoadingAccessCodes(true);
    try {
      const res = await axios.get(`${API}/files/${fileId}/access-codes`, axiosConfig());
      setAccessCodes(res.data.codes || []);
    } catch (err) {
      toast.error(prettyApiError(err, "Failed to load access codes"));
    } finally {
      setLoadingAccessCodes(false);
    }
  };

  const handleRevokeAccessCode = async (codeId) => {
    if (!selectedFile || !codeId) return;
    setRevokingAccessCodeId(codeId);
    try {
      await axios.delete(`${API}/files/${selectedFile.id}/access-codes/${codeId}`, axiosConfig());
      toast.success("Access code revoked");
      await loadAccessCodes(selectedFile.id);
    } catch (err) {
      toast.error(prettyApiError(err, "Failed to revoke access code"));
    } finally {
      setRevokingAccessCodeId(null);
    }
  };

  const handleCreateAccessCode = async () => {
    if (!selectedFile) {
      toast.error("No file selected");
      return;
    }
    const expiresInMinutes = Number(accessCodeTtl);
    if (!Number.isFinite(expiresInMinutes) || expiresInMinutes <= 0) {
      toast.error("Invalid expiry");
      return;
    }

    setCreatingAccessCode(true);
    setCreatedAccessCode("");
    try {
      const trimmedCustomCode = accessCodeCustom.trim();
      const payload = {
        expiresInMinutes,
        allowedEmail: accessCodeEmail ? accessCodeEmail.trim() : null,
        label: accessCodeEmail ? `for:${accessCodeEmail.trim()}` : null,
      };
      if (trimmedCustomCode) payload.accessCode = trimmedCustomCode;
      const res = await axios.post(
        `${API}/files/${selectedFile.id}/access-codes`,
        payload,
        axiosConfig()
      );
      setCreatedAccessCode(res.data.code);
      toast.success("Access code created");
    } catch (err) {
      toast.error(prettyApiError(err, "Create access code failed"));
    } finally {
      setCreatingAccessCode(false);
    }
  };

  const closeRenameDialog = () => {
    setRenameDialog(false);
    setRenameValue("");
    setSelectedFile(null);
    setRenaming(false);
  };

  const closeLinkDialog = () => {
    setLinkDialog(false);
    setSelectedFile(null);
    setCreatedLinkUrl("");
    setCreatedLinkAccessCode("");
    setCreatingLink(false);
    setLinkExpires("10");
    setLinkMaxUses("1");
    setLinkZeroKnowledge(true);
    setLinkAccessCode("");
  };

  const handleCreateLink = async () => {
    if (!selectedFile) {
      toast.error("No file selected");
      return;
    }
    const expiresInMinutes = Number(linkExpires);
    const maxUses = Number(linkMaxUses);
    if (!Number.isFinite(expiresInMinutes) || expiresInMinutes <= 0) {
      toast.error("Invalid expiry");
      return;
    }
    if (!Number.isFinite(maxUses) || maxUses <= 0) {
      toast.error("Invalid max uses");
      return;
    }

    setCreatingLink(true);
    try {
      const trimmedAccessCode = linkAccessCode.trim();
      const createBody = { expiresInMinutes, maxUses, zeroKnowledge: linkZeroKnowledge };
      if (trimmedAccessCode) createBody.accessCode = trimmedAccessCode;
      const res = await axios.post(
        `${API}/files/${selectedFile.id}/share-link`,
        createBody,
        axiosConfig()
      );
      let url = res.data.url;
      setCreatedLinkAccessCode(res.data.accessCode || "");

      if (linkZeroKnowledge) {
        // Setup fragment-secret encrypted file key, without sending the secret to server
        const tokenFromUrl = (url.split("/share/")[1] || "").split("?")[0].split("#")[0];
        const keyRes = await axios.get(`${API}/files/key/${selectedFile.id}`, axiosConfig());
        const fileKeyBytes = b64ToBytes(keyRes.data.aes_key_b64);

        const secretBytes = window.crypto.getRandomValues(new Uint8Array(32));
        const secretB64Url = bytesToB64Url(secretBytes);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const secretKey = await window.crypto.subtle.importKey("raw", secretBytes, { name: "AES-GCM" }, false, ["encrypt"]);
        const encCombined = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, secretKey, fileKeyBytes);
        const encBytes = new Uint8Array(encCombined);
        const tag = encBytes.slice(encBytes.length - 16);
        const ciphertext = encBytes.slice(0, encBytes.length - 16);

        await axios.post(
          `${API}/share/${tokenFromUrl}/zk-setup`,
          {
            encFileKeyB64: btoa(String.fromCharCode(...ciphertext)),
            ivB64: btoa(String.fromCharCode(...iv)),
            tagB64: btoa(String.fromCharCode(...tag)),
          },
          axiosConfig()
        );

        url = `${url}#${secretB64Url}`;
      }

      setCreatedLinkUrl(url);
      try {
        await navigator.clipboard.writeText(url);
        toast.success("Share link created (copied)");
      } catch {
        toast.success("Share link created");
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to create link");
    } finally {
      setCreatingLink(false);
    }
  };

  const handleRevoke = async () => {
    if (!shareEmail) {
      toast.error("Enter an email");
      return;
    }
    if (!selectedFile) {
      toast.error("No file selected");
      return;
    }
    try {
      await axios.delete(`${API}/files/revoke/${selectedFile.id}`, {
        ...axiosConfig(),
        data: { email: shareEmail },
      });
      toast.success(`Access revoked for ${shareEmail}`);
      closeShareDialog();
      loadFiles();
    } catch (err) {
      toast.error(prettyApiError(err, "Revoke failed"));
    }
  };

  const handleRename = async () => {
    if (!selectedFile) {
      toast.error("No file selected");
      return;
    }
    const filename = renameValue.trim();
    if (!filename) {
      toast.error("Enter a filename");
      return;
    }
    setRenaming(true);
    try {
      await axios.patch(
        `${API}/files/rename/${selectedFile.id}`,
        { filename },
        axiosConfig()
      );
      toast.success("Renamed");
      closeRenameDialog();
      loadFiles();
    } catch (err) {
      toast.error(prettyApiError(err, "Rename failed"));
    } finally {
      setRenaming(false);
    }
  };

  const handleUploadNewVersion = async (e) => {
    const file = e.target.files?.[0];
    if (!file || !versionTarget) return;
    setUploadingVersion(true);
    const formData = new FormData();
    formData.append("file", file);
    try {
      await axios.post(`${API}/files/upload-version/${versionTarget.id}`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      toast.success("New version uploaded");
      loadFiles();
    } catch (err) {
      toast.error(prettyApiError(err, "Upload version failed"));
    } finally {
      setUploadingVersion(false);
      setVersionTarget(null);
      e.target.value = "";
    }
  };

  const handleOpenShareLink = async () => {
    if (!shareToken) return;
    if (!shareAccessCode.trim()) {
      toast.error("Enter access code");
      return;
    }
    setShareLoading(true);
    try {
      const fragmentSecret = (window.location.hash || "").replace("#", "") || null;
      const res = await axios.get(`${API}/share/${shareToken}`, {
        headers: { "X-Share-Access-Code": shareAccessCode },
      });
      const payload = res.data;
      const filename = payload.file?.filename || "shared-file";
      setShareFileName(filename);

      const fileKeyBytes = await unwrapFileKey({
        encryptedFileKey: payload.encryptedFileKey,
        token: shareToken,
        fragmentSecret,
      });

      const plaintextBytes = await decryptSharedFile({
        fileKeyBytes,
        enc: payload.encryption,
      });

      const digest = await window.crypto.subtle.digest("SHA-256", plaintextBytes);
      const hex = bufferToHex(digest);
      if (hex !== payload.integrity?.sha256) {
        throw new Error("Integrity check failed");
      }

      downloadBlob(plaintextBytes, filename);
      toast.success("Downloaded (verified)");
    } catch (err) {
      const status = err?.response?.status;
      if (status === 410) {
        toast.error(err.response?.data?.detail || "Link expired/consumed");
      } else {
        toast.error(err.response?.data?.detail || err.message || "Download failed");
      }
    } finally {
      setShareLoading(false);
    }
  };

  // ========== ADMIN ==========

  const loadAdminData = async () => {
    try {
      const [usersRes, logsRes, statsRes] = await Promise.all([
        axios.get(`${API}/admin/users`, axiosConfig()),
        axios.get(`${API}/admin/logs`, axiosConfig()),
        axios.get(`${API}/admin/stats`, axiosConfig())
      ]);
      setUsers(usersRes.data.users);
      setLogs(logsRes.data.logs);
      setStats(statsRes.data);
    } catch (err) {
      console.error("Failed to load admin data", err);
    }
  };

  // ========== VIEWS ==========

  if (view === "share") {
    return (
      <div className="app-container">
        <Toaster position="top-right" richColors />
        <header className="header">
          <div className="header-content">
            <div className="logo">
              <Shield className="logo-icon" />
              <span className="logo-text">SecureShare</span>
            </div>
          </div>
        </header>

        <div className="dashboard-container" style={{ maxWidth: 720, margin: "0 auto" }}>
          <Card>
            <CardHeader>
              <CardTitle>Shared File</CardTitle>
              <CardDescription>
                {shareFileName ? `File: ${shareFileName}` : "This link provides temporary access."}
              </CardDescription>
            </CardHeader>
            <CardContent style={{ display: "grid", gap: 12 }}>
              <div style={{ display: "grid", gap: 6 }}>
                <Label htmlFor="share-access-code">Access code</Label>
                <Input
                  id="share-access-code"
                  type="password"
                  value={shareAccessCode}
                  onChange={(e) => setShareAccessCode(e.target.value)}
                  placeholder="Enter code"
                  autoFocus
                />
              </div>
              <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                <Button onClick={handleOpenShareLink} disabled={shareLoading}>
                  <Download size={16} />
                  {shareLoading ? "Preparing..." : "Download"}
                </Button>
                <Badge variant="secondary">One-time / Expiring link</Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (view === "landing") {
    return (
      <div className="app-container">
        <Toaster position="top-right" richColors />
        
        {/* Header */}
        <header className="header">
          <div className="header-content">
            <div className="logo">
              <Shield className="logo-icon" />
              <span className="logo-text">SecureShare</span>
            </div>
          </div>
        </header>

        {/* Hero */}
        <section className="hero">
          <div className="hero-content">
            <div className="hero-badge">
              <Lock size={16} />
              <span>AES-256 & RSA Encryption</span>
            </div>
            <h1 className="hero-title">
              
              <span className="hero-title-gradient">Secure File Sharing</span>
            </h1>
            <p className="hero-description">
              Military-grade encryption with multi-factor authentication and role-based access control.
              Your files, protected by cryptographic excellence.
            </p>
            <div className="hero-features">
              <div className="feature-item">
                <Key size={20} />
                <span>AES-256 Encryption</span>
              </div>
              <div className="feature-item">
                <Shield size={20} />
                <span>RSA Key Exchange</span>
              </div>
              <div className="feature-item">
                <Activity size={20} />
                <span>Multi-Factor Auth</span>
              </div>
            </div>
          </div>

          <div className="auth-card-container">
            <Card className="auth-card">
              <Tabs defaultValue="login" className="auth-tabs">
                <TabsList className="auth-tabs-list">
                  <TabsTrigger value="login" id="login-tab-trigger" data-testid="login-tab">Login</TabsTrigger>
                  <TabsTrigger value="register" data-testid="register-tab">Register</TabsTrigger>
                </TabsList>
                
                <TabsContent value="login" data-testid="login-form">
                  <CardHeader>
                    <CardTitle>Welcome Back</CardTitle>
                    <CardDescription>Enter your credentials to access your secure vault</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <form onSubmit={handleLogin} className="auth-form">
                      <div className="form-group">
                        <Label htmlFor="login-email">Email</Label>
                        <Input
                          id="login-email"
                          name="email"
                          type="email"
                          placeholder="you@example.com"
                          required
                          data-testid="login-email-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="login-password">Password</Label>
                        <Input
                          id="login-password"
                          name="password"
                          type="password"
                          placeholder="••••••••"
                          required
                          data-testid="login-password-input"
                        />
                      </div>
                      <Button type="submit" className="submit-btn" data-testid="login-submit-btn">
                        Login
                      </Button>
                    </form>

                    {GOOGLE_CLIENT_ID && (
                      <div style={{ marginTop: "1rem", display: "flex", justifyContent: "center" }}>
                        <div id="google-signin-btn" />
                      </div>
                    )}

                    {googleSigningIn && (
                      <div style={{ marginTop: "0.75rem", textAlign: "center" }}>
                        Signing in with Google...
                      </div>
                    )}
                  </CardContent>
                </TabsContent>
                
                <TabsContent value="register" data-testid="register-form">
                  <CardHeader>
                    <CardTitle>Create Account</CardTitle>
                    <CardDescription>Start securing your files today</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <form onSubmit={handleRegister} className="auth-form">
                      <div className="form-group">
                        <Label htmlFor="register-name">Full Name</Label>
                        <Input
                          id="register-name"
                          name="full_name"
                          type="text"
                          placeholder="John Doe"
                          required
                          data-testid="register-name-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="register-email">Email</Label>
                        <Input
                          id="register-email"
                          name="email"
                          type="email"
                          placeholder="you@example.com"
                          required
                          data-testid="register-email-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="register-password">Password</Label>
                        <Input
                          id="register-password"
                          name="password"
                          type="password"
                          placeholder="••••••••"
                          required
                          data-testid="register-password-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="register-role">Role</Label>
                        <select
                          id="register-role"
                          name="role"
                          className="role-select"
                          data-testid="register-role-select"
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                        </select>
                      </div>
                      <Button type="submit" className="submit-btn" data-testid="register-submit-btn">
                        Create Account
                      </Button>
                    </form>
                  </CardContent>
                </TabsContent>
              </Tabs>
            </Card>
          </div>
        </section>
      </div>
    );
  }

  if (view === "otp") {
    return (
      <div className="app-container otp-view">
        <Toaster position="top-right" richColors />
        <div className="otp-container">
          <Card className="otp-card">
            <CardHeader>
              <div className="otp-icon">
                <Shield size={48} />
              </div>
              <CardTitle>Multi-Factor Authentication</CardTitle>
              <CardDescription>
                We sent a 6-digit OTP to {pendingEmail}. Please check your inbox and enter it below.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="otp-message">
                OTP codes expire in {otpExpiresMinutes} minutes and can only be used once.
              </div>
              <form onSubmit={handleVerifyOTP} className="otp-form">
                <div className="form-group">
                  <Label htmlFor="otp-input">OTP Code</Label>
                  <Input
                    id="otp-input"
                    name="otp"
                    type="text"
                    placeholder="000000"
                    maxLength={6}
                    required
                    data-testid="otp-input"
                    className="otp-input"
                  />
                </div>
                <Button type="submit" className="submit-btn" data-testid="verify-otp-btn">
                  Verify & Login
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleResendOTP}
                  disabled={resendCooldown > 0}
                  className="resend-btn"
                  data-testid="resend-otp-btn"
                >
                  {resendCooldown > 0 ? `Resend OTP in ${resendCooldown}s` : "Resend OTP"}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (view === "dashboard") {
    return (
      <div className="dashboard-container">
        <Toaster position="top-right" richColors />
        
        {/* Dashboard Header */}
        <header className="dashboard-header">
          <div className="dashboard-header-content">
            <div className="logo">
              <Shield className="logo-icon" />
              <span className="logo-text">SecureShare</span>
            </div>
            <div className="user-info">
              <Badge variant="outline" className="role-badge" data-testid="user-role-badge">
                {user?.role?.toUpperCase()}
              </Badge>
              <span className="user-email" data-testid="user-email-display">{user?.email}</span>
              <Button variant="ghost" size="sm" onClick={handleLogout} data-testid="logout-btn">
                <LogOut size={16} />
              </Button>
            </div>
          </div>
        </header>

        <div className="dashboard-content">
          <Tabs defaultValue="files" className="dashboard-tabs">
            <TabsList className="dashboard-tabs-list">
              <TabsTrigger value="files" data-testid="files-tab">
                <FileText size={16} />
                My Files
              </TabsTrigger>
              <TabsTrigger value="example" data-testid="example-tab">
                <Activity size={16} />
                Example Module
              </TabsTrigger>
              {user?.role === "admin" && (
                <>
                  <TabsTrigger value="users" data-testid="users-tab">
                    <Users size={16} />
                    Users
                  </TabsTrigger>
                  <TabsTrigger value="logs" data-testid="logs-tab">
                    <Activity size={16} />
                    Activity Logs
                  </TabsTrigger>
                </>
              )}
            </TabsList>

            {/* Files Tab */}
            <TabsContent value="files" className="files-tab-content" data-testid="files-content">
              <input
                type="file"
                id="version-upload"
                onChange={handleUploadNewVersion}
                style={{ display: "none" }}
              />

              <div className="files-header">
                <h2>Encrypted Files</h2>
                <div className="upload-section">
                  <input
                    type="file"
                    id="file-upload"
                    onChange={handleUpload}
                    style={{ display: "none" }}
                    data-testid="file-upload-input"
                  />
                  <Button
                    onClick={() => document.getElementById("file-upload").click()}
                    disabled={uploading}
                    data-testid="upload-btn"
                  >
                    <Upload size={16} />
                    {uploading ? "Encrypting..." : "Upload File"}
                  </Button>
                </div>
              </div>

              <Dialog open={uploadDialog} onOpenChange={(open) => {
                if (!open) {
                  setUploadDialog(false);
                  setPendingUploadFile(null);
                  setPendingUploadPassword("");
                } else {
                  setUploadDialog(true);
                }
              }}>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Set File Password</DialogTitle>
                    <DialogDescription>
                      Set a password for "{pendingUploadFile?.name}". This password is unique to this file.
                    </DialogDescription>
                  </DialogHeader>
                  <div style={{ display: "grid", gap: 12 }}>
                    <div style={{ display: "grid", gap: 6 }}>
                      <Label htmlFor="upload-file-password">File password</Label>
                      <Input
                        id="upload-file-password"
                        type="password"
                        value={pendingUploadPassword}
                        onChange={(e) => setPendingUploadPassword(e.target.value)}
                        placeholder="Enter password (min 4 chars)"
                        autoFocus
                      />
                    </div>
                    <Button onClick={confirmUpload} disabled={uploading}>
                      {uploading ? "Uploading..." : "Upload"}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>

              <div className="files-grid">
                {files.length === 0 ? (
                  <div className="empty-state" data-testid="empty-files-message">
                    <FileText size={48} />
                    <p>No files yet. Upload your first encrypted file!</p>
                  </div>
                ) : (
                  files.map((file) => (
                    <Card key={file.id} className="file-card" data-testid={`file-card-${file.id}`}>
                      <CardHeader>
                        <CardTitle
                          className="file-name"
                          data-testid={`file-name-${file.id}`}
                          onClick={() => {
                            if (file.my_role === "editor" || file.my_role === "owner") {
                              setSelectedFile(file);
                              setRenameValue(file.filename);
                              setRenameDialog(true);
                            }
                          }}
                          style={{ cursor: (file.my_role === "editor" || file.my_role === "owner") ? "pointer" : "default" }}
                          title={(file.my_role === "editor" || file.my_role === "owner") ? "Click to rename" : ""}
                        >
                          {file.filename}
                        </CardTitle>
                        <CardDescription>
                          <div className="file-meta">
                            <span>Owner: {file.owner_email}</span>
                            <span>Size: {(file.size / 1024).toFixed(2)} KB</span>
                          </div>
                        </CardDescription>
                      </CardHeader>

                      <CardContent>
                        {file.original_hash && (
                          <div className="file-hash" data-testid={`file-hash-${file.id}`}>
                            SHA-256: {file.original_hash}
                          </div>
                        )}

                        {file.my_role && (
                          <div className="shared-info">
                            <Badge variant="secondary">Role: {file.my_role}</Badge>
                            {file.access_protected && (
                              <Badge variant="outline" style={{ marginLeft: 8 }}>Protected</Badge>
                            )}
                          </div>
                        )}

                        <div className="file-actions">
                          <Button
                            variant="outline"
                            onClick={() => {
                              setDownloadTarget({ id: file.id, filename: file.filename });
                              setDownloadAccessCode("");
                              setDownloadDialog(true);
                            }}
                            data-testid={`download-btn-${file.id}`}
                          >
                            <Download size={14} />
                            Download
                          </Button>

                          {(file.my_role === "editor" || file.my_role === "owner") && (
                            <Button
                              variant="outline"
                              disabled={uploadingVersion}
                              onClick={() => {
                                setVersionTarget(file);
                                document.getElementById("version-upload").click();
                              }}
                              title="Upload new version"
                            >
                              <Upload size={14} />
                              New Version
                            </Button>
                          )}
                          {file.my_role === "owner" && (
                            <>
                              <Button
                                variant="outline"
                                onClick={() => {
                                  setSelectedFile(file);
                                  setShareDialog(true);
                                }}
                                data-testid={`share-btn-${file.id}`}
                              >
                                <Share2 size={14} />
                                Share
                              </Button>
                              <Button
                                variant="outline"
                                onClick={() => {
                                  setSelectedFile(file);
                                  setLinkDialog(true);
                                }}
                                title="Create temporary link"
                              >
                                <Key size={14} />
                                Link
                              </Button>
                              <Button
                                variant="destructive"
                                onClick={() => handleDelete(file.id)}
                                data-testid={`delete-btn-${file.id}`}
                              >
                                <Trash2 size={14} />
                                Delete
                              </Button>
                            </>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))
                )}
              </div>
            </TabsContent>

            <TabsContent value="example" data-testid="example-content">
              <h2>Example Module + Routes</h2>
              <div className="stats-grid">
                <Card>
                  <CardHeader>
                    <CardTitle>Route Status</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p><strong>Module:</strong> {exampleStatus?.module || "-"}</p>
                    <p><strong>Status:</strong> {exampleStatus?.status || "-"}</p>
                    <p><strong>Environment:</strong> {exampleStatus?.environment || "-"}</p>
                    <p><strong>Timestamp:</strong> {exampleStatus?.timestamp ? new Date(exampleStatus.timestamp).toLocaleString() : "-"}</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Deploy Checklist (API-driven)</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ol style={{ margin: 0, paddingLeft: "1.2rem" }}>
                      {deployChecklist.map((step, idx) => (
                        <li key={idx} style={{ marginBottom: "0.5rem" }}>{step}</li>
                      ))}
                    </ol>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            {/* Admin: Users Tab */}
            {user?.role === "admin" && (
              <TabsContent value="users" data-testid="users-content">
                <h2>System Users</h2>
                <div className="stats-grid">
                  <Card>
                    <CardHeader>
                      <CardTitle>Total Users</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="stat-value" data-testid="total-users-stat">{stats.total_users || 0}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Total Files</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="stat-value" data-testid="total-files-stat">{stats.total_files || 0}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Total Actions</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="stat-value" data-testid="total-logs-stat">{stats.total_logs || 0}</div>
                    </CardContent>
                  </Card>
                </div>
                <ScrollArea className="users-list">
                  {users.map((u) => (
                    <Card key={u.id} className="user-card" data-testid={`user-card-${u.id}`}>
                      <CardContent>
                        <div className="user-card-content">
                          <div>
                            <strong data-testid={`user-name-${u.id}`}>{u.full_name}</strong>
                            <p data-testid={`user-email-${u.id}`}>{u.email}</p>
                          </div>
                          <Badge data-testid={`user-role-${u.id}`}>{u.role}</Badge>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </ScrollArea>
              </TabsContent>
            )}

            {/* Admin: Logs Tab */}
            {user?.role === "admin" && (
              <TabsContent value="logs" data-testid="logs-content">
                <h2>Activity Logs</h2>
                <ScrollArea className="logs-list">
                  {logs.map((log, idx) => (
                    <Card key={log.id || idx} className="log-card" data-testid={`log-card-${idx}`}>
                      <CardContent>
                        <div className="log-card-content">
                          <div>
                            <strong data-testid={`log-action-${idx}`}>{log.action}</strong>
                            <p data-testid={`log-user-${idx}`}>{log.user_email}</p>
                            {log.filename && <p data-testid={`log-filename-${idx}`}>File: {log.filename}</p>}
                          </div>
                          <span className="log-timestamp" data-testid={`log-timestamp-${idx}`}>
                            {new Date(log.timestamp).toLocaleString()}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </ScrollArea>
              </TabsContent>
            )}
          </Tabs>
        </div>

        {/* Share Dialog */}
        <Dialog open={shareDialog} onOpenChange={(open) => {
          if (!open) closeShareDialog();
          else setShareDialog(open);
        }}>
          <DialogContent data-testid="share-dialog">
            <DialogHeader>
              <DialogTitle>Share File</DialogTitle>
              <DialogDescription>
                Share "{selectedFile?.filename}" with another user
              </DialogDescription>
            </DialogHeader>
            <div className="share-form">
              <Label htmlFor="share-email">User Email</Label>
              <Input
                id="share-email"
                type="email"
                placeholder="user@example.com"
                value={shareEmail}
                onChange={(e) => setShareEmail(e.target.value)}
                data-testid="share-email-input"
              />

              <Label>Role</Label>
              <Select value={shareRole} onValueChange={setShareRole}>
                <SelectTrigger>
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="viewer">viewer (download only)</SelectItem>
                  <SelectItem value="editor">editor (edit/rename)</SelectItem>
                </SelectContent>
              </Select>

              <Button onClick={handleShare} className="share-submit-btn" data-testid="share-submit-btn">
                Share File
              </Button>

              <div style={{ margin: "12px 0" }} />

              <Label htmlFor="access-code-email">Create time-limited access code (optional email)</Label>
              <Input
                id="access-code-email"
                type="email"
                placeholder="recipient@example.com (optional)"
                value={accessCodeEmail}
                onChange={(e) => setAccessCodeEmail(e.target.value)}
              />

              <Label htmlFor="access-code-ttl">Expires in (minutes)</Label>
              <Input
                id="access-code-ttl"
                type="number"
                min="1"
                value={accessCodeTtl}
                onChange={(e) => setAccessCodeTtl(e.target.value)}
              />

              <Label htmlFor="access-code-custom">Custom access code (optional)</Label>
              <Input
                id="access-code-custom"
                type="text"
                placeholder="Leave blank to auto-generate"
                value={accessCodeCustom}
                onChange={(e) => setAccessCodeCustom(e.target.value)}
              />

              <Button onClick={handleCreateAccessCode} disabled={creatingAccessCode}>
                {creatingAccessCode ? "Creating..." : "Generate Access Code"}
              </Button>

              {createdAccessCode && (
                <div style={{ display: "grid", gap: 6 }}>
                  <Label>New access code (copy & send to recipient)</Label>
                  <Input value={createdAccessCode} readOnly />
                </div>
              )}

              <Button
                variant="outline"
                onClick={() => selectedFile?.id && loadAccessCodes(selectedFile.id)}
                disabled={loadingAccessCodes}
              >
                {loadingAccessCodes ? "Refreshing..." : "Refresh Access Codes"}
              </Button>

              {accessCodes.length > 0 && (
                <div style={{ display: "grid", gap: 8 }}>
                  <Label>Existing access codes (this file only)</Label>
                  <div style={{ display: "grid", gap: 8 }}>
                    {accessCodes.map((c) => (
                      <div key={c.id} style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                        <div style={{ fontSize: 12 }}>
                          <div><strong>{c.label || "code"}</strong></div>
                          <div>expires: {c.expires_at}</div>
                          {c.allowed_email && <div>only: {c.allowed_email}</div>}
                        </div>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleRevokeAccessCode(c.id)}
                          disabled={revokingAccessCodeId === c.id}
                        >
                          {revokingAccessCodeId === c.id ? "Revoking..." : "Revoke"}
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <Button variant="destructive" onClick={handleRevoke}>
                Revoke Access
              </Button>
            </div>
          </DialogContent>
        </Dialog>

        {/* Download Access Code Dialog */}
        <Dialog open={downloadDialog} onOpenChange={(open) => {
          if (!open) {
            setDownloadDialog(false);
            setDownloadTarget(null);
            setDownloadAccessCode("");
          } else {
            setDownloadDialog(true);
          }
        }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Enter Access Code</DialogTitle>
              <DialogDescription>
                Enter the file password or a time-limited access code.
              </DialogDescription>
            </DialogHeader>
            <div style={{ display: "grid", gap: 12 }}>
              <div style={{ display: "grid", gap: 6 }}>
                <Label htmlFor="download-access-code">Access code</Label>
                <Input
                  id="download-access-code"
                  type="password"
                  value={downloadAccessCode}
                  onChange={(e) => setDownloadAccessCode(e.target.value)}
                  placeholder="Enter code"
                  autoFocus
                />
              </div>
              <Button
                onClick={async () => {
                  if (!downloadTarget) return;
                  const ok = await handleDownload(downloadTarget.id, downloadTarget.filename, downloadAccessCode);
                  if (ok) {
                    setDownloadDialog(false);
                    setDownloadTarget(null);
                    setDownloadAccessCode("");
                  }
                }}
                disabled={downloading}
              >
                {downloading ? "Downloading..." : "Download"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>

        {/* Rename Dialog */}
        <Dialog open={renameDialog} onOpenChange={(open) => {
          if (!open) closeRenameDialog();
          else setRenameDialog(open);
        }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Rename File</DialogTitle>
              <DialogDescription>
                Rename "{selectedFile?.filename}"
              </DialogDescription>
            </DialogHeader>
            <div className="share-form">
              <Label htmlFor="rename">Filename</Label>
              <Input
                id="rename"
                value={renameValue}
                onChange={(e) => setRenameValue(e.target.value)}
              />
              <Button onClick={handleRename} disabled={renaming}>
                {renaming ? "Renaming..." : "Rename"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>

        {/* Create Link Dialog */}
        <Dialog open={linkDialog} onOpenChange={(open) => {
          if (!open) closeLinkDialog();
          else setLinkDialog(open);
        }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Temporary Link</DialogTitle>
              <DialogDescription>
                Create an expiring link for "{selectedFile?.filename}"
              </DialogDescription>
            </DialogHeader>

            <div className="share-form">
              <Label htmlFor="link-expires">Expires in (minutes)</Label>
              <Input
                id="link-expires"
                type="number"
                min="1"
                value={linkExpires}
                onChange={(e) => setLinkExpires(e.target.value)}
              />

              <Label htmlFor="link-maxuses">Max uses</Label>
              <Input
                id="link-maxuses"
                type="number"
                min="1"
                value={linkMaxUses}
                onChange={(e) => setLinkMaxUses(e.target.value)}
              />

              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginTop: 8 }}>
                <div>
                  <Label>Zero-knowledge style link</Label>
                  <div style={{ fontSize: 12, opacity: 0.8 }}>
                    Uses #secret in URL fragment (not sent to server)
                  </div>
                </div>
                <Switch checked={linkZeroKnowledge} onCheckedChange={setLinkZeroKnowledge} />
              </div>

              <Label htmlFor="link-access-code">Access code (optional)</Label>
              <Input
                id="link-access-code"
                type="text"
                value={linkAccessCode}
                onChange={(e) => setLinkAccessCode(e.target.value)}
                placeholder="Leave blank to auto-generate"
              />

              <Button onClick={handleCreateLink} disabled={creatingLink}>
                <Key size={16} />
                {creatingLink ? "Creating..." : "Create Link"}
              </Button>

              {createdLinkUrl && (
                <>
                  <Label>Link</Label>
                  <Input value={createdLinkUrl} readOnly />

                  {!!createdLinkAccessCode && (
                    <>
                      <Label>Access code</Label>
                      <Input value={createdLinkAccessCode} readOnly />
                    </>
                  )}
                </>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  return null;
}

export default App;
