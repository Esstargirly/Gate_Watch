import {
  createUserWithEmailAndPassword, onAuthStateChanged, sendPasswordResetEmail,
  signInWithEmailAndPassword, signOut, updateProfile,
} from "firebase/auth";
import { auth } from "./firebase.js";
import { notify, startData, state, stopData } from "./store.js";

let pendingName = null; // name typed on the sign-up form

const profileOf = (user) => ({
  uid: user.uid,
  email: user.email,
  displayName: user.displayName || pendingName || (user.email || "you").split("@")[0],
  role: "owner",
});

export function watchAuth() {
  onAuthStateChanged(auth, (user) => {
    stopData();
    state.user = user;
    if (!user) {
      pendingName = null;
      state.profile = null;
      state.workspaceId = null;
      state.authStatus = "signedOut";
      notify();
      return;
    }
    state.profile = profileOf(user);
    state.workspaceId = user.uid;
    state.authStatus = "ready";
    startData();
    notify();
  });
}

export const signIn = (email, password) => signInWithEmailAndPassword(auth, email, password);

export async function signUp(name, email, password) {
  pendingName = name || null;
  const cred = await createUserWithEmailAndPassword(auth, email, password);
  if (name) {
    await updateProfile(cred.user, { displayName: name }).catch(() => {});
    if (state.profile) { state.profile.displayName = name; notify(); }
  }
}

export const resetPassword = (email) => sendPasswordResetEmail(auth, email);
export const logout = () => signOut(auth);

export function authMessage(err) {
  const code = err?.code || "";
  if (["auth/invalid-credential", "auth/wrong-password", "auth/user-not-found", "auth/invalid-login-credentials"].includes(code)) return "Wrong email or password.";
  if (code === "auth/email-already-in-use") return "That email already has an account. Sign in instead.";
  if (code === "auth/weak-password") return "Password needs at least 6 characters.";
  if (code === "auth/invalid-email") return "That email address doesn't look right.";
  if (code === "auth/too-many-requests") return "Too many attempts. Wait a minute and try again.";
  if (code === "auth/network-request-failed") return "Can't reach Firebase. Check your connection.";
  if (code === "auth/operation-not-allowed") return "Email/password sign-in isn't switched on in Firebase Authentication yet.";
  return err?.message || "Something went wrong. Try again.";
}