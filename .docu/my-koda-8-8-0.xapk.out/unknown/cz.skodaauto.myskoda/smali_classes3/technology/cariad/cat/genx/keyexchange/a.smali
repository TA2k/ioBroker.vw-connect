.class public final synthetic Ltechnology/cariad/cat/genx/keyexchange/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

.field public final synthetic e:[B

.field public final synthetic f:B

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:I

.field public final synthetic i:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

.field public final synthetic j:S

.field public final synthetic k:S

.field public final synthetic l:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;[BBLjava/lang/String;ILtechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->d:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->e:[B

    .line 7
    .line 8
    iput-byte p3, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->f:B

    .line 9
    .line 10
    iput-object p4, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput p5, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->h:I

    .line 13
    .line 14
    iput-object p6, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->i:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 15
    .line 16
    iput-short p7, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->j:S

    .line 17
    .line 18
    iput-short p8, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->k:S

    .line 19
    .line 20
    iput-object p9, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->l:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget-short v7, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->k:S

    .line 2
    .line 3
    iget-object v8, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->l:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->d:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 6
    .line 7
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->e:[B

    .line 8
    .line 9
    iget-byte v2, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->f:B

    .line 10
    .line 11
    iget-object v3, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->g:Ljava/lang/String;

    .line 12
    .line 13
    iget v4, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->h:I

    .line 14
    .line 15
    iget-object v5, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->i:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 16
    .line 17
    iget-short v6, p0, Ltechnology/cariad/cat/genx/keyexchange/a;->j:S

    .line 18
    .line 19
    invoke-static/range {v0 .. v8}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->k0(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;[BBLjava/lang/String;ILtechnology/cariad/cat/genx/crypto/RemoteCredentials;SSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
