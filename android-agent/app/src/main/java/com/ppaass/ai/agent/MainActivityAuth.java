package com.ppaass.ai.agent;

import android.content.Intent;
import android.net.Uri;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;

abstract class MainActivityAuth extends MainActivityScreens {
    private EditText loginUsername;
    private EditText loginPassword;
    private CheckBox rememberCredentials;
    private Button loginButton;
    private Button registrationButton;
    private TextView loginError;
    private boolean authenticationInProgress;
    private boolean loginUiVisible;
    private long authenticationAttempt;

    protected void showAgentEntry() {
        if (AgentAuthSession.isActive(this)) {
            loginUiVisible = false;
            buildUi();
        } else {
            AgentAuthenticationCoordinator.cancelAll();
            AgentAuthSession.clear();
            boolean credentialsCleared = ManagedCredentials.clear(this);
            buildLoginUi();
            if (!credentialsCleared) {
                showLoginError("无法完全清理旧的 Agent 私钥，请重试登录");
            }
        }
        UiLanguage.watch(this);
    }

    protected boolean hasAuthenticatedAgentSession() {
        return AgentAuthSession.isActive(this);
    }

    protected boolean isAgentAuthenticationInProgress() {
        return authenticationInProgress;
    }

    private void buildLoginUi() {
        loginUiVisible = true;
        authenticationInProgress = false;
        editableControls.clear();

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setBackground(appBackground());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_VERTICAL);
        int horizontalPadding = dp(20);
        int topPadding = dp(24);
        int bottomPadding = dp(24);
        root.setPadding(
                horizontalPadding,
                topPadding + systemBarInsetFallback("status_bar_height"),
                horizontalPadding,
                bottomPadding + systemBarInsetFallback("navigation_bar_height"));
        applySystemBarPadding(
                root,
                horizontalPadding,
                topPadding,
                horizontalPadding,
                bottomPadding);
        scroll.addView(root, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        LinearLayout card = panel(root);
        card.setPadding(dp(22), dp(24), dp(22), dp(24));
        card.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);

        TextView brand = titleText("PPAASS Android Agent", 14f);
        brand.setTextColor(COLOR_ACCENT);
        card.addView(brand, matchWrap());

        TextView title = titleText("连接你的代理账户", 25f);
        LinearLayout.LayoutParams titleParams = matchWrap();
        titleParams.setMargins(0, dp(12), 0, 0);
        card.addView(title, titleParams);

        TextView subtitle = mutedText(
                "登录后自动下载并应用当前账户获批的代理凭据。",
                14f);
        LinearLayout.LayoutParams subtitleParams = matchWrap();
        subtitleParams.setMargins(0, dp(6), 0, dp(8));
        card.addView(subtitle, subtitleParams);

        RememberedLoginStore.Login remembered = RememberedLoginStore.load(this);
        loginUsername = loginField(
                card,
                "用户名",
                remembered == null ? "" : remembered.username,
                false);
        loginUsername.setHint(tr("输入 Proxy Web 用户名"));
        loginUsername.setImeOptions(EditorInfo.IME_ACTION_NEXT);

        loginPassword = loginField(
                card,
                "密码",
                remembered == null ? "" : remembered.password,
                true);
        loginPassword.setHint(tr("至少 8 位"));
        loginPassword.setImeOptions(EditorInfo.IME_ACTION_DONE);
        loginPassword.setOnEditorActionListener((view, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                authenticateFromForm();
                return true;
            }
            return false;
        });

        rememberCredentials = new CheckBox(this);
        rememberCredentials.setText(tr("记住用户名和密码"));
        rememberCredentials.setTextColor(COLOR_TEXT);
        rememberCredentials.setTextSize(14f);
        rememberCredentials.setChecked(remembered != null);
        rememberCredentials.setOnCheckedChangeListener((button, checked) -> {
            if (!checked && !RememberedLoginStore.clear(this)) {
                showLoginError("无法清除已记住的登录信息");
            }
        });
        LinearLayout.LayoutParams rememberParams = matchWrap();
        rememberParams.setMargins(0, dp(10), 0, 0);
        card.addView(rememberCredentials, rememberParams);

        loginError = mutedText("", 13f);
        loginError.setTextColor(COLOR_ACTION_STOP);
        loginError.setVisibility(View.GONE);
        loginError.setGravity(Gravity.START);
        LinearLayout.LayoutParams errorParams = matchWrap();
        errorParams.setMargins(0, dp(10), 0, 0);
        card.addView(loginError, errorParams);

        loginButton = actionButton("登录并配置 Agent", COLOR_ACTION_START);
        loginButton.setOnClickListener(view -> authenticateFromForm());
        LinearLayout.LayoutParams loginParams = matchWrap();
        loginParams.height = dp(50);
        loginParams.setMargins(0, dp(16), 0, 0);
        card.addView(loginButton, loginParams);

        registrationButton = secondaryButton("新用户注册");
        registrationButton.setOnClickListener(view -> openRegistrationPage());
        LinearLayout.LayoutParams registrationParams = matchWrap();
        registrationParams.height = dp(48);
        registrationParams.setMargins(0, dp(10), 0, 0);
        card.addView(registrationButton, registrationParams);

        TextView securityNote = mutedText(
                "私钥会从 Proxy Web 自动下载到应用私有目录，不会显示在界面中。",
                12.5f);
        securityNote.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams noteParams = matchWrap();
        noteParams.setMargins(0, dp(16), 0, 0);
        card.addView(securityNote, noteParams);

        setContentView(scroll);
        loginUsername.requestFocus();
        root.requestApplyInsets();
    }

    private EditText loginField(
            LinearLayout root,
            String title,
            String value,
            boolean password) {
        root.addView(controlLabel(title), labelParams());
        EditText field = new EditText(this);
        field.setText(value);
        field.setSingleLine(true);
        field.setTextSize(16f);
        field.setTextColor(COLOR_TEXT);
        field.setHintTextColor(COLOR_MUTED);
        field.setPadding(dp(12), 0, dp(12), 0);
        field.setMinHeight(dp(48));
        field.setInputType(password
                ? InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD
                : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_NORMAL);
        if (password) {
            field.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
        styleInput(field);
        root.addView(field, matchWrap());
        return field;
    }

    private void authenticateFromForm() {
        if (authenticationInProgress) {
            return;
        }
        String username = loginUsername.getText().toString().trim();
        String password = loginPassword.getText().toString();
        boolean rememberLogin = rememberCredentials.isChecked();
        if (username.isEmpty()) {
            showLoginError("请输入用户名");
            return;
        }
        if (password.length() < 8) {
            showLoginError("密码至少需要 8 位");
            return;
        }
        if (!rememberLogin && !RememberedLoginStore.clear(this)) {
            showLoginError("无法清除已记住的登录信息");
            return;
        }

        long attempt = AgentAuthenticationCoordinator.begin();
        authenticationAttempt = attempt;
        setAuthenticationBusy(true);
        new Thread(() -> {
            try {
                String proxyWebUrl = AgentAuthConfig.proxyWebUrl(this);
                AgentAuthClient.LoginResult result =
                        new AgentAuthClient(this, proxyWebUrl).authenticate(username, password);
                boolean committed = AgentAuthenticationCoordinator.commitIfCurrent(
                        attempt,
                        () -> commitAuthenticatedResult(
                                result,
                                username,
                                password,
                                rememberLogin));
                if (!committed) {
                    return;
                }

                runOnUiThread(() -> completeAuthenticationUi(attempt));
            } catch (AgentAuthClient.AuthException | IOException | RuntimeException error) {
                AgentAuthenticationCoordinator.cancel(attempt);
                runOnUiThread(() -> {
                    if (attempt != authenticationAttempt
                            || !AgentAuthenticationCoordinator.isLatest(attempt)
                            || isFinishing()
                            || isDestroyed()) {
                        return;
                    }
                    authenticationAttempt = 0;
                    setAuthenticationBusy(false);
                    String message = error instanceof RuntimeException
                            ? "登录或应用 Agent 凭据失败"
                            : error.getMessage();
                    showLoginError(message == null ? "登录或应用 Agent 凭据失败" : message);
                });
            }
        }, "ppaass-agent-auth").start();
    }

    private boolean isCurrentAuthenticationAttempt(long attempt) {
        return attempt == authenticationAttempt
                && AgentAuthenticationCoordinator.isLatest(attempt);
    }

    private void completeAuthenticationUi(long attempt) {
        if (!isCurrentAuthenticationAttempt(attempt)
                || isFinishing()
                || isDestroyed()) {
            return;
        }
        authenticationAttempt = 0;
        stopAgentsForCredentialReplacement();
        setAuthenticationBusy(false);
        loginUiVisible = false;
        buildUi();
        UiLanguage.watch(this);
        if (activityResumed) {
            startStatusRefresh();
        }
    }

    private void commitAuthenticatedResult(
            AgentAuthClient.LoginResult result,
            String username,
            String password,
            boolean rememberLogin) throws IOException {
        try {
            ManagedCredentials.install(
                    this,
                    result.username,
                    result.keyVersion,
                    result.expiresAt,
                    result.privateKeyPem,
                    result.proxyIdentityPublicKeyPem);
            if (rememberLogin) {
                if (!RememberedLoginStore.save(this, username, password)) {
                    throw new IOException("无法保存已记住的登录信息");
                }
            } else if (!RememberedLoginStore.clear(this)) {
                throw new IOException("无法清除已记住的登录信息");
            }
            AgentAuthSession.authenticate(
                    result.username,
                    result.keyVersion,
                    result.expiresAt);
            AgentAuthSession.applyVerifiedServerStatus(
                    this,
                    NativeAgent.AUTHENTICATION_VERIFIED_ACTIVE);
        } catch (IOException | RuntimeException error) {
            AgentAuthSession.clear();
            boolean credentialsCleared = ManagedCredentials.clear(this);
            if (rememberLogin) {
                RememberedLoginStore.clear(this);
            }
            if (!credentialsCleared) {
                error.addSuppressed(new IOException("无法清理失败登录遗留的 Agent 私钥"));
            }
            throw error;
        }
    }

    private void stopAgentsForCredentialReplacement() {
        if (PpaassVpnService.isRunningInProcess()
                || prefs.getBoolean(PpaassVpnService.PREF_RUNNING, false)) {
            stopVpnService();
        }
        if (PpaassHttpProxyService.isRunningInProcess()
                || prefs.getBoolean(PpaassHttpProxyService.PREF_RUNNING, false)
                || prefs.getBoolean(PpaassHttpProxyService.PREF_ENABLED, false)) {
            stopHttpProxyService();
        }
        if (PpaassVpnService.isMockGeoRunningInProcess()
                || prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_REQUESTED, false)
                || prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_ACTIVE, false)
                || prefs.getBoolean(PpaassVpnService.PREF_MOCK_GEO_DIRTY, false)) {
            stopMockGeoService();
        }
    }

    private void setAuthenticationBusy(boolean busy) {
        authenticationInProgress = busy;
        loginUsername.setEnabled(!busy);
        loginPassword.setEnabled(!busy);
        rememberCredentials.setEnabled(!busy);
        registrationButton.setEnabled(!busy);
        loginButton.setEnabled(!busy);
        loginButton.setText(tr(busy ? "正在登录" : "登录并配置 Agent"));
        if (busy) {
            loginError.setVisibility(View.GONE);
        }
    }

    private void showLoginError(String message) {
        loginError.setText(tr(message));
        loginError.setVisibility(View.VISIBLE);
    }

    private void openRegistrationPage() {
        try {
            Intent intent = new Intent(
                    Intent.ACTION_VIEW,
                    Uri.parse(AgentAuthConfig.registrationUrl(this)));
            startActivity(intent);
        } catch (IOException | RuntimeException error) {
            showLoginError("无法打开新用户注册页面");
        }
    }

    @Override
    protected void logoutAgentAccount() {
        AgentAuthenticationCoordinator.cancelAll();
        authenticationAttempt = 0;
        authenticationInProgress = false;
        stopAgentsForCredentialReplacement();
        prefs.edit()
                .putBoolean(PpaassHttpProxyService.PREF_ENABLED, false)
                .apply();
        AgentAuthSession.clear();
        boolean credentialsCleared = ManagedCredentials.clear(this);
        statusHandler.removeCallbacks(statusRefresh);
        buildLoginUi();
        if (!credentialsCleared) {
            showLoginError("无法完全删除 Agent 私钥；代理已停止，请重试登录以再次清理");
        }
        UiLanguage.watch(this);
        Toast.makeText(this, tr("已退出 Agent"), Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onAgentSessionInvalidated() {
        statusHandler.removeCallbacks(statusRefresh);
        AgentAuthenticationCoordinator.cancelAll();
        authenticationAttempt = 0;
        authenticationInProgress = false;
        AgentAuthSession.clear();
        boolean credentialsCleared = ManagedCredentials.clear(this);
        stopAgentsForCredentialReplacement();
        if (loginUiVisible || isFinishing()) {
            if (!credentialsCleared && loginError != null) {
                showLoginError("无法完全删除已失效的 Agent 私钥");
            }
            return;
        }
        buildLoginUi();
        if (!credentialsCleared) {
            showLoginError("无法完全删除已失效的 Agent 私钥");
        }
        UiLanguage.watch(this);
        Toast.makeText(
                this,
                tr("登录状态或代理凭据已过期，请重新登录"),
                Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        AgentAuthenticationCoordinator.cancel(authenticationAttempt);
        authenticationAttempt = 0;
        super.onDestroy();
    }
}
