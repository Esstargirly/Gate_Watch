import {
  createUserWithEmailAndPassword, onAuthStateChanged, sendPasswordResetEmail,
  signInWithEmailAndPassword, signOut, updateProfile,
} from "firebase/auth";
import { doc, onSnapshot, serverTimestamp, setDoc, updateDoc } from "firebase/firestore";
import { auth, db } from "./firebase.js";
import { fromDoc, isStaff, notify, startData, state, stopData } from "./store.js";

let pendingName = null; // name typed on the sign-up form

export function watchAuth() {
  let unProfile = null;
  let lastRole = null;

  onAuthStateChanged(auth, (user) => {
    if (unProfile) unProfile();
    unProfile = null;
    stopData();
    lastRole = null;
    state.user = user;
    state.profile = null;

    if (!user) {
      state.authStatus = "signedOut";
      notify();
      return;
    }
    state.authStatus = "loading";
    notify();

    const ref = doc(db, "users", user.uid);
    let creating = false;
    unProfile = onSnapshot(
      ref,
      async (snap) => {
        if (!snap.exists()) {
          if (!creating) {
            creating = true;
            try {
              await setDoc(ref, {
                email: user.email,
                displayName: pendingName || user.displayName || (user.email || "user").split("@")[0],
                role: "pending",
                mfaEnabled: false,
                createdAt: serverTimestamp(),
              });
            } catch (e) {
              console.error("Could not create profile", e);
            }
          }
          state.profile = null;
          state.authStatus = "pending";
          notify();
          return;
        }
        const profile = { uid: user.uid, ...fromDoc(snap) };
        state.profile = profile;
        if (isStaff(profile)) {
          state.authStatus = "ready";
          if (profile.role !== lastRole) startData(profile.role);
        } else {
          state.authStatus = "pending";
          stopData();
        }
        lastRole = profile.role;
        notify();
      },
      (err) => {
        console.error("profile listener", err);
        state.authError = err;
        state.authStatus = "pending";
        notify();
      }
    );
    updateDoc(ref, { lastLoginAt: serverTimestamp() }).catch(() => {});
  });
}

export const signIn = (email, password) => signInWithEmailAndPassword(auth, email, password);

export async function signUp(name, email, password) {
  pendingName = name || null;
  const cred = await createUserWithEmailAndPassword(auth, email, password);
  if (name) await updateProfile(cred.user, { displayName: name }).catch(() => {});
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