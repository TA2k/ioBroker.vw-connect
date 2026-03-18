.class public final Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0008\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0012\u0010\u0005\u001a\u0004\u0018\u00010\u0004H\u0086\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\"\u0010\u0005\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0008\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u0007H\u0086\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\nJ\u0013\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000b\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0013\u0010\u0010\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u000f\u00a2\u0006\u0004\u0008\u0010\u0010\u0011R\u0011\u0010\u0015\u001a\u00020\u00128F\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0014R\u0011\u0010\u0017\u001a\u00020\u00128F\u00a2\u0006\u0006\u001a\u0004\u0008\u0016\u0010\u0014R\u0011\u0010\u0019\u001a\u00020\u00128F\u00a2\u0006\u0006\u001a\u0004\u0008\u0018\u0010\u0014\u00a8\u0006\u001a"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;",
        "",
        "<init>",
        "()V",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "invoke",
        "()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "",
        "publicKeyHexString",
        "privateKeyHexString",
        "(Ljava/lang/String;Ljava/lang/String;)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "Llx0/o;",
        "generate-d1pmJ48",
        "()Ljava/lang/Object;",
        "generate",
        "Lqz0/a;",
        "serializer",
        "()Lqz0/a;",
        "",
        "getPublicKeyLength",
        "()I",
        "publicKeyLength",
        "getPrivateKeyLength",
        "privateKeyLength",
        "getSignatureLength",
        "signatureLength",
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
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;-><init>()V

    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->generate_d1pmJ48$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->generate_d1pmJ48$lambda$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->invoke$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d([B[B)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->generate_d1pmJ48$lambda$0([B[B)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final generate_d1pmJ48$lambda$0([B[B)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigningKt;->access$nativeCreateED25519SigningKeyPair([B[B)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final generate_d1pmJ48$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "createED25519KeyPair(): Failed to create a key pair. At least one of the generated keys had an invalid length."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final generate_d1pmJ48$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "createED25519KeyPair(): Failed to create a key pair. At least one of the generated keys was empty."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invoke$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "invoke(): Failed to generate KeyPair"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final generate-d1pmJ48()Ljava/lang/Object;
    .locals 6

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->getPrivateKeyLength()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-array v1, v0, [B

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->getPublicKeyLength()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    new-array v3, v2, [B

    .line 12
    .line 13
    new-instance v4, Ltechnology/cariad/cat/genx/crypto/a;

    .line 14
    .line 15
    const/4 v5, 0x1

    .line 16
    invoke-direct {v4, v1, v3, v5}, Ltechnology/cariad/cat/genx/crypto/a;-><init>(Ljava/lang/Object;Ljava/io/Serializable;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {v4}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    if-eqz v4, :cond_0

    .line 24
    .line 25
    invoke-static {v4}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    const-string v4, "GenX"

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    if-nez v0, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    if-nez v2, :cond_2

    .line 37
    .line 38
    :goto_0
    new-instance v0, Lt61/d;

    .line 39
    .line 40
    const/16 v1, 0x10

    .line 41
    .line 42
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 43
    .line 44
    .line 45
    invoke-static {p0, v4, v5, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 46
    .line 47
    .line 48
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Signing;

    .line 49
    .line 50
    sget-object v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error$KeyPairGenerationFailed;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error$KeyPairGenerationFailed;

    .line 51
    .line 52
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError$Signing;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error;)V

    .line 53
    .line 54
    .line 55
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :cond_2
    sget-object v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;

    .line 61
    .line 62
    invoke-virtual {v0, v3}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;->invoke([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    sget-object v2, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;

    .line 67
    .line 68
    invoke-virtual {v2, v1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;->invoke([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    if-eqz v0, :cond_3

    .line 73
    .line 74
    if-eqz v1, :cond_3

    .line 75
    .line 76
    new-instance p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 77
    .line 78
    invoke-direct {p0, v0, v1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;)V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :cond_3
    new-instance v0, Lt61/d;

    .line 83
    .line 84
    const/16 v1, 0xf

    .line 85
    .line 86
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-static {p0, v4, v5, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 90
    .line 91
    .line 92
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Signing;

    .line 93
    .line 94
    sget-object v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error$KeyPairGenerationFailed;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error$KeyPairGenerationFailed;

    .line 95
    .line 96
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError$Signing;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$Error;)V

    .line 97
    .line 98
    .line 99
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0
.end method

.method public final getPrivateKeyLength()I
    .locals 0

    .line 1
    const/16 p0, 0x20

    .line 2
    .line 3
    return p0
.end method

.method public final getPublicKeyLength()I
    .locals 0

    .line 1
    const/16 p0, 0x20

    .line 2
    .line 3
    return p0
.end method

.method public final getSignatureLength()I
    .locals 0

    .line 1
    const/16 p0, 0x40

    .line 2
    .line 3
    return p0
.end method

.method public final invoke()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->generate-d1pmJ48()Ljava/lang/Object;

    move-result-object p0

    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    sget-object v1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;

    new-instance v2, Lt61/d;

    const/16 v3, 0xe

    invoke-direct {v2, v3}, Lt61/d;-><init>(I)V

    .line 2
    const-string v3, "GenX"

    invoke-static {v1, v3, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 3
    :cond_0
    instance-of v0, p0, Llx0/n;

    if-eqz v0, :cond_1

    const/4 p0, 0x0

    .line 4
    :cond_1
    check-cast p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    return-object p0
.end method

.method public final invoke(Ljava/lang/String;Ljava/lang/String;)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;
    .locals 0

    const-string p0, "publicKeyHexString"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "privateKeyHexString"

    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey$Companion;->invoke(Ljava/lang/String;)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    move-result-object p0

    .line 6
    sget-object p1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;

    invoke-virtual {p1, p2}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;->invoke(Ljava/lang/String;)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    move-result-object p1

    if-eqz p0, :cond_0

    if-eqz p1, :cond_0

    .line 7
    new-instance p2, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    invoke-direct {p2, p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;)V

    return-object p2

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public final serializer()Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$$serializer;

    .line 2
    .line 3
    return-object p0
.end method
