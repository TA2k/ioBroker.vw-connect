.class public abstract Ltechnology/cariad/cat/genx/crypto/CredentialStore;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0005\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0002\u0008 \u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0018\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\tH!J\"\u0010\n\u001a\u0004\u0018\u00010\u00072\u0006\u0010\u000b\u001a\u00020\u000c2\u0006\u0010\r\u001a\u00020\u000c2\u0006\u0010\u0008\u001a\u00020\tH!\u00a8\u0006\u000e"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "",
        "<init>",
        "()V",
        "storeSessionCredentials",
        "",
        "sessionCredentialsEntry",
        "Ltechnology/cariad/cat/genx/crypto/SessionCredentials;",
        "cgxTransportType",
        "",
        "retrieveSessionCredentials",
        "localIdentifier",
        "",
        "remoteIdentifier",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public abstract retrieveSessionCredentials([B[BB)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;
.end method

.method public abstract storeSessionCredentials(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;B)I
.end method
