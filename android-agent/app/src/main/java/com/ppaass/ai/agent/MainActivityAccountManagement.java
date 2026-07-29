package com.ppaass.ai.agent;

import android.content.Intent;
import android.net.Uri;
import android.widget.Toast;

import java.io.IOException;

abstract class MainActivityAccountManagement extends MainActivityAuth {
    private long accountManagementRequestGeneration;
    private AgentWebSessionHandoffClient accountManagementClient;

    @Override
    protected void openAccountManagementPage() {
        if (accountManagementInProgress) {
            return;
        }
        if (!AgentAuthSession.isActive(this)) {
            showAccountManagementMessage("请先登录 Agent");
            return;
        }
        AgentSessionStore.StoredSession stored = AgentSessionStore.load(this);
        if (stored.needsRelogin || stored.accessToken.isEmpty()) {
            showAccountManagementMessage(
                    "账户管理登录凭据已失效，请重新登录 Agent");
            return;
        }

        setAccountManagementBusy(true);
        long requestGeneration = ++accountManagementRequestGeneration;
        new Thread(
                () -> createAccountManagementHandoff(
                        requestGeneration,
                        stored.accessToken),
                "ppaass-account-management").start();
    }

    private void createAccountManagementHandoff(
            long requestGeneration,
            String accessToken) {
        try {
            String baseUrl = AgentAuthConfig.proxyWebUrl(this);
            AgentWebSessionHandoffClient client =
                    new AgentWebSessionHandoffClient(this, baseUrl);
            synchronized (this) {
                if (requestGeneration != accountManagementRequestGeneration) {
                    client.cancel();
                    return;
                }
                accountManagementClient = client;
            }
            AgentWebSessionHandoffClient.Handoff handoff =
                    client.create(accessToken);
            runOnUiThread(() -> openAccountManagementHandoff(
                    requestGeneration,
                    handoff));
        } catch (AgentAuthClient.AuthException | IOException error) {
            runOnUiThread(() -> finishAccountManagementWithError(
                    requestGeneration,
                    error.getMessage()));
        } catch (RuntimeException error) {
            runOnUiThread(() -> finishAccountManagementWithError(
                    requestGeneration,
                    "无法打开账户管理页面"));
        }
    }

    private void openAccountManagementHandoff(
            long requestGeneration,
            AgentWebSessionHandoffClient.Handoff handoff) {
        if (!finishAccountManagementRequest(requestGeneration)
                || !AgentAuthSession.isActive(this)
                || isFinishing()
                || isDestroyed()) {
            return;
        }
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(handoff.url));
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            startActivity(intent);
        } catch (RuntimeException error) {
            showAccountManagementMessage("无法打开账户管理页面");
        }
    }

    private void finishAccountManagementWithError(
            long requestGeneration,
            String message) {
        if (!finishAccountManagementRequest(requestGeneration)
                || isFinishing()
                || isDestroyed()) {
            return;
        }
        showAccountManagementMessage(
                message == null || message.isEmpty()
                        ? "无法打开账户管理页面"
                        : message);
    }

    private synchronized boolean finishAccountManagementRequest(long generation) {
        if (generation != accountManagementRequestGeneration) {
            return false;
        }
        accountManagementClient = null;
        setAccountManagementBusy(false);
        return true;
    }

    private void setAccountManagementBusy(boolean busy) {
        accountManagementInProgress = busy;
        if (accountManagementButton != null) {
            accountManagementButton.setEnabled(!busy);
            accountManagementButton.setText(tr(busy ? "正在打开" : "账户管理"));
        }
    }

    private void showAccountManagementMessage(String message) {
        Toast.makeText(this, tr(message), Toast.LENGTH_LONG).show();
    }

    private synchronized void cancelAccountManagementRequest() {
        accountManagementRequestGeneration++;
        if (accountManagementClient != null) {
            accountManagementClient.cancel();
            accountManagementClient = null;
        }
        setAccountManagementBusy(false);
    }

    @Override
    protected void logoutAgentAccount() {
        cancelAccountManagementRequest();
        super.logoutAgentAccount();
    }

    @Override
    protected void onAgentSessionInvalidated() {
        cancelAccountManagementRequest();
        super.onAgentSessionInvalidated();
    }

    @Override
    protected void onDestroy() {
        cancelAccountManagementRequest();
        super.onDestroy();
    }
}
