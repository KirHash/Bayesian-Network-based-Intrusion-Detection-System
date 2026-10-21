import { createContext, useContext } from "react";

export const RANK = { viewer: 0, analyst: 1, admin: 2 };

export const AuthContext = createContext({
  user: "local",
  role: "admin",
  open: true
});

/** Who is signed in, and what they may do. */
export function useAuth() {
  const auth = useContext(AuthContext);

  return {
    ...auth,
    canHandle: RANK[auth.role] >= RANK.analyst,
    isAdmin: auth.role === "admin"
  };
}
