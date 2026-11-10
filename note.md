# Passkey-Native Distributed Access Platform
**Architecture Concept — Draft v0.1**

**Status:** Early Concept / Discussion Draft

## 1. Overview

本プロジェクトは、Passkeyを人間の認証の中心に据え、分散型Trust Domainと短命Credentialによって、インフラへの安全なアクセスを実現するIdentity & Access Platformである。

既存のZero Trustの原則を尊重しつつ、中央集権的なIdPやZTNA Gatewayへの過度な依存を減らし、各Nodeが自律的に信頼を検証できるアーキテクチャを目指す。

WireGuard、OpenSSH、mTLSなどの成熟した技術を組み合わせ、既存プロトコルを再実装することなく統一的なアクセス体験を提供する。

## 2. Design Philosophy

### 2.1 Passkey-Centric Identity

Passkey / WebAuthnを人間の認証の起点とする。

- ユーザーは長期SSH鍵やVPN認証情報を直接管理しない。
- 認証結果に基づいて短命Credentialを発行する。
- Device IdentityはUser Identityとは独立した暗号鍵で管理する。
- 権限の行使時にはリスクに応じて追加認証を要求する。

Passkey自体はアクセス権限を表現せず、認証の根拠として使用する。

### 2.2 Default No Authority

新たなIdentity、Device、Domainは、原則として権限を持たない。

**Identity ≠ Membership ≠ Authority**

- Domainへの参加は他Nodeへのアクセスを意味しない。
- リソースの発見と通信は明示的に認可する。
- 権限の暗黙的な継承を禁止する。
- 権限は対象・操作・期間を限定して付与する。

初期設定に必要なBootstrap権限は、用途と有効期間を厳格に制限する。

### 2.3 Distributed Trust

単一のグローバルCAへの依存を避け、独立したTrust Domainを基本単位とする。

- 各Domainが自身のCA、信頼設定、認可ポリシーを管理する。
- Domain間の信頼関係は明示的かつ非推移的とする。
- Federationでは相手DomainのIdentity Assertionを評価し、リソース側Domainが最終的に認可する。
- 一つのDomainの侵害が他Domainに自動的に波及しない設計を目指す。

### 2.4 Local Verification

**Authenticate when necessary. Authorize precisely. Verify locally.**

- Control PlaneはCredential発行とポリシー管理を担当する。
- Nodeは署名済みCredentialとローカルポリシーを検証する。
- 通常のP2P通信にControl Planeを介在させない。
- 失効通知はPush、整合性確認はPullを基本とする。
- 短命CredentialとPolicy Leaseで、中央障害時の信頼期間を制限する。

## 3. High-Level Architecture

```text
               Passkey / WebAuthn
                       |
                       v
              Identity Verification
                       |
        Device Identity + Policy
                       |
                       v
             Domain Authorization
                       |
             Credential Issuance
                       |
          +------------+------------+
          |            |            |
          v            v            v
     SSH Cert       mTLS Cert    Access Grant
          |            |            |
       OpenSSH      Services     Network Policy
          |            |            |
          +------------+------------+
                       |
                P2P Data Plane
                (e.g. WireGuard)
```

### Main Components

| Component | Responsibility |
|---|---|
| Identity Service | Passkey登録・WebAuthn検証 |
| Domain Authority | Trust Domain管理、CA、Federation |
| Policy Engine | 認可判断、短命Grant発行 |
| Node Agent | Device認証、Mesh参加、Policy Enforcement |
| Data Plane | WireGuard等による暗号化通信 |
| Credential Issuer | SSH Certificate、X.509等の発行 |

User、Device、WorkloadのIdentityは独立して管理し、認可時に必要な関係を評価する。

## 4. Trust & Credential Model

### Human Identity
Passkey / WebAuthnを使用する。

### Device Identity
独立したDevice KeyおよびmTLS証明書を使用する。

### Workload Identity
サービスごとの鍵と証明書を使用する。

### Authorization
認証された主体に対して、Resource Domainが用途を限定した短命Credentialを発行する。

WebAuthnによる認証と発行対象の公開鍵は、同一の認可トランザクションに結びつける。

CAの署名権限とポリシー変更権限は分離し、Domain間で無制限に委譲しない。

## 5. Network & Infrastructure Access

Nodeは常時Meshに参加できるが、参加自体は通信権限を与えない。

WireGuardは通信の暗号化とP2P接続を担当し、アクセス制御は独立したAuthorization Layerで強制する。

SSHについては既存OpenSSHを使用する。

想定するアクセスフロー：

1. ユーザーがPasskeyで認証する。
2. Deviceが独立した鍵で自身を証明する。
3. Resource Domainがポリシーを評価する。
4. 短命SSH CertificateまたはAccess Grantを発行する。
5. Node間で暗号化通信を確立する。
6. 接続先がCredentialと権限をローカルに検証する。

将来的にはsudo、Database、Kubernetes、内部WebサービスへのJIT認可へ拡張する。

## 6. Enterprise & Deployment Model

Trust Domainの独立性を維持したまま、複数の提供形態をサポート可能な設計とする。

- **Cloud:** マルチテナントSaaS
- **Enterprise Cloud:** 専用環境や顧客専用CA
- **Enterprise Self-Hosted:** 顧客管理のControl Plane、CA、Policy
- **Federation:** 異なる企業・環境間での限定的な信頼関係

Self-Hostedはアーキテクチャ上可能にするが、初期商用リリースで提供するかは別途判断する。

## 7. Security Invariants

1. Domain Membershipはアクセス権限を付与しない。
2. 権限はデフォルトで拒否される。
3. TrustはDomain間で自動的に推移しない。
4. UserとDeviceは独立したCredentialを持つ。
5. CredentialはAudience、Scope、有効期限を持つ。
6. Resource Domainが最終的な認可権限を保持する。
7. Private Keyは原則として発行元端末から移動させない。
8. Control Planeを通常のData Plane通信の必須経路にしない。
9. ポリシー失効・更新の遅延は明確な上限を持つ。
10. 高権限操作は明示的な追加認可を要求できる。

## 8. Initial MVP

**Scope**

- Passkeyによるユーザー認証
- 独立したDevice Identity
- 単一Trust DomainとDefault Deny
- WireGuardベースのMesh
- 短命SSH Certificate発行
- OpenSSHを利用したSSHアクセス
- 基本的なPolicy管理とアクセス監査

**Out of Scope**

- 完全なCross-Domain Federation
- 汎用sudo認可
- 高度なDevice Posture管理
- 複雑なEnterprise承認ワークフロー
- 完全分散型CA

MVPでは、独立したTrust Domainへ拡張可能なデータモデルと信頼境界を保ちつつ、単一DomainでEnd-to-Endのアクセス体験を検証する。

## 9. Open Questions

- Trust Domainの粒度と階層構造
- Domain AuthorityのBootstrapとRecovery
- CA鍵のローテーションと侵害時の復旧
- Offline時のCredential発行・失効ポリシー
- Push / Pull / GossipによるPolicy Distribution
- FederationにおけるIdentity Assertionの受け入れ条件
- WebAuthn認証結果とDevice Keyの暗号学的バインディング
- SaaSとSelf-Hosted間でのTrust Domain移行

## 10. Product Vision

**A passkey-native, distributed trust platform for secure infrastructure access.**

ネットワークの所在や中央の認証サービスへの常時接続ではなく、検証可能なIdentity、明示的な認可、短命Credentialによってアクセスを成立させる。

目指すのは、Zero Trustの原則を維持しながら、信頼の集中と侵害時の影響範囲を最小化するインフラアクセス基盤である。
