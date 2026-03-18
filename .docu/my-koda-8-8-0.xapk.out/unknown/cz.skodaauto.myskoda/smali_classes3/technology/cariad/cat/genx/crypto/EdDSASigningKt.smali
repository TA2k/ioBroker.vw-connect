.class public final Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0008\u001a\u001f\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00010\u0003*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u0001\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\u001a!\u0010\u0008\u001a\u00020\u0007*\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0001\u00a2\u0006\u0004\u0008\u0008\u0010\t\u001a \u0010\r\u001a\u00020\u000c2\u0006\u0010\n\u001a\u00020\u00012\u0006\u0010\u000b\u001a\u00020\u0001H\u0082 \u00a2\u0006\u0004\u0008\r\u0010\u000e\u001a0\u0010\u0010\u001a\u00020\u000c2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u000f\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\u0006\u0010\u000b\u001a\u00020\u0001H\u0082 \u00a2\u0006\u0004\u0008\u0010\u0010\u0011\u001a(\u0010\u0012\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\u00012\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u000f\u001a\u00020\u0001H\u0082 \u00a2\u0006\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u0014"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "",
        "data",
        "Llx0/o;",
        "signature",
        "(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;[B)Ljava/lang/Object;",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;",
        "",
        "isValidSignature",
        "(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[B)Z",
        "privateKey",
        "publicKey",
        "",
        "nativeCreateED25519SigningKeyPair",
        "([B[B)I",
        "message",
        "nativeCreateEdDSAED25519Signature",
        "([B[B[B[B)I",
        "nativeValidateEdDSAED25519Signature",
        "([B[B[B)Z",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->signature$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final synthetic access$nativeCreateED25519SigningKeyPair([B[B)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->nativeCreateED25519SigningKeyPair([B[B)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;[B[B)I
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->signature$lambda$0(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;[B[B)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final isValidSignature(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[B)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "signature"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "data"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->getRawValue()[B

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->nativeValidateEdDSAED25519Signature([B[B[B)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0
.end method

.method private static final native nativeCreateED25519SigningKeyPair([B[B)I
.end method

.method private static final native nativeCreateEdDSAED25519Signature([B[B[B[B)I
.end method

.method private static final native nativeValidateEdDSAED25519Signature([B[B[B)Z
.end method

.method public static final signature(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;[B)Ljava/lang/Object;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "data"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;

    .line 12
    .line 13
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->getSignatureLength()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    new-array v1, v0, [B

    .line 18
    .line 19
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    invoke-direct {v2, p0, v1, p1, v3}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {v2}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :cond_0
    if-nez v0, :cond_1

    .line 37
    .line 38
    new-instance p1, Lt61/d;

    .line 39
    .line 40
    const/16 v0, 0x11

    .line 41
    .line 42
    invoke-direct {p1, v0}, Lt61/d;-><init>(I)V

    .line 43
    .line 44
    .line 45
    const/4 v0, 0x0

    .line 46
    const-string v1, "GenX"

    .line 47
    .line 48
    invoke-static {p0, v1, v0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 49
    .line 50
    .line 51
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Signing;

    .line 52
    .line 53
    sget-object p1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error$CannotCreateSignature;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error$CannotCreateSignature;

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$Signing;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error;)V

    .line 56
    .line 57
    .line 58
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0

    .line 63
    :cond_1
    return-object v1
.end method

.method private static final signature$lambda$0(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;[B[B)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->getPublicKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->getRawValue()[B

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->getPrivateKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->getRawValue()[B

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-static {p1, p2, p0, v0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->nativeCreateEdDSAED25519Signature([B[B[B[B)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method private static final signature$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "signature(): Failed to create a valid signature. The created signature was empty or had an invalid length."

    .line 2
    .line 3
    return-object v0
.end method
