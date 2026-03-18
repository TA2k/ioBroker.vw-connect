.class public interface abstract Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$DefaultImpls;,
        Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$RSE_DIAGNOSIS;,
        Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials$VKMS;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008f\u0018\u00002\u00020\u0001:\u0002\u000b\u000cJ\'\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\'\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\t\u0010\u0007\u00a8\u0006\r\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;",
        "",
        "",
        "data",
        "initializationVector",
        "Llx0/o;",
        "encrypt-gIAlu-s",
        "([B[B)Ljava/lang/Object;",
        "encrypt",
        "decrypt-gIAlu-s",
        "decrypt",
        "VKMS",
        "RSE_DIAGNOSIS",
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
.method public static synthetic decrypt-gIAlu-s$default(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;[B[BILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p4, :cond_1

    .line 2
    .line 3
    and-int/lit8 p3, p3, 0x2

    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    new-array p2, p2, [B

    .line 9
    .line 10
    :cond_0
    invoke-interface {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;->decrypt-gIAlu-s([B[B)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 16
    .line 17
    const-string p1, "Super calls with default arguments not supported in this target, function: decrypt-gIAlu-s"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0
.end method

.method public static synthetic encrypt-gIAlu-s$default(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;[B[BILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p4, :cond_1

    .line 2
    .line 3
    and-int/lit8 p3, p3, 0x2

    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    new-array p2, p2, [B

    .line 9
    .line 10
    :cond_0
    invoke-interface {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;->encrypt-gIAlu-s([B[B)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 16
    .line 17
    const-string p1, "Super calls with default arguments not supported in this target, function: encrypt-gIAlu-s"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0
.end method


# virtual methods
.method public abstract decrypt-gIAlu-s([B[B)Ljava/lang/Object;
.end method

.method public abstract encrypt-gIAlu-s([B[B)Ljava/lang/Object;
.end method
