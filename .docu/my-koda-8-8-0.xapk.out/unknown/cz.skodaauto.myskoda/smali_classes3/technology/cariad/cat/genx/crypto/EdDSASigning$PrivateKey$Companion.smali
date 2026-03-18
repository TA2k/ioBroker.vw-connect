.class public final Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u001a\u0010\u0007\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0086\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001a\u0010\u0007\u001a\u0004\u0018\u00010\u00062\u0006\u0010\n\u001a\u00020\tH\u0086\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u000bJ\u0013\u0010\r\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u000c\u00a2\u0006\u0004\u0008\r\u0010\u000e\u00a8\u0006\u000f"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;",
        "",
        "<init>",
        "()V",
        "",
        "byteArray",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;",
        "invoke",
        "([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;",
        "",
        "hexString",
        "(Ljava/lang/String;)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;",
        "Lqz0/a;",
        "serializer",
        "()Lqz0/a;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/String;)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;
    .locals 3

    const-string v0, "hexString"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    const-string v0, ""

    const/4 v1, 0x0

    .line 4
    const-string v2, " "

    invoke-static {v1, p1, v2, v0}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 5
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    rem-int/lit8 v0, v0, 0x2

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    return-object p0

    .line 6
    :cond_0
    invoke-static {p1}, Lly0/d;->d(Ljava/lang/String;)[B

    move-result-object p1

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;->invoke([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    move-result-object p0

    return-object p0
.end method

.method public final invoke([B)Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;
    .locals 2

    const-string p0, "byteArray"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    array-length p0, p1

    sget-object v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->getPrivateKeyLength()I

    move-result v0

    const/4 v1, 0x0

    if-eq p0, v0, :cond_0

    return-object v1

    .line 2
    :cond_0
    new-instance p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    invoke-direct {p0, p1, v1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;-><init>([BLkotlin/jvm/internal/g;)V

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
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$$serializer;

    .line 2
    .line 3
    return-object p0
.end method
