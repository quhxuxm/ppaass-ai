export const REMEMBERED_AGENT_LOGIN_KEY = "ppaass-agent-login";

export type RememberedAgentLogin = {
  username: string;
  password: string;
};

export function loadRememberedAgentLogin(): RememberedAgentLogin | null {
  try {
    const raw = localStorage.getItem(REMEMBERED_AGENT_LOGIN_KEY);
    if (!raw) return null;
    const saved = JSON.parse(raw) as Partial<RememberedAgentLogin>;
    if (
      typeof saved.username !== "string" ||
      !saved.username.trim() ||
      typeof saved.password !== "string" ||
      saved.password.length < 8
    ) {
      return null;
    }
    return {
      username: saved.username,
      password: saved.password
    };
  } catch {
    return null;
  }
}

export function saveRememberedAgentLogin(login: RememberedAgentLogin) {
  localStorage.setItem(REMEMBERED_AGENT_LOGIN_KEY, JSON.stringify(login));
}

export function clearRememberedAgentLogin() {
  localStorage.removeItem(REMEMBERED_AGENT_LOGIN_KEY);
}
