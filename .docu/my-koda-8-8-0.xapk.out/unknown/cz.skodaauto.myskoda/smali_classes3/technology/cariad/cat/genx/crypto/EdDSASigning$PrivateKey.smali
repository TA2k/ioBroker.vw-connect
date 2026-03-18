.class public final Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/crypto/EdDSASigning;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "PrivateKey"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$$serializer;,
        Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000B\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0010\u000e\n\u0002\u0008\u0008\u0008\u0007\u0018\u0000  2\u00020\u0001:\u0002 !B\u0011\u0008\u0002\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005B%\u0008\u0010\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u0002\u0012\u0008\u0010\t\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\u0004\u0010\nJ\'\u0010\u0013\u001a\u00020\u00102\u0006\u0010\u000b\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\u000c2\u0006\u0010\u000f\u001a\u00020\u000eH\u0001\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\u001a\u0010\u0016\u001a\u00020\u00152\u0008\u0010\u0014\u001a\u0004\u0018\u00010\u0001H\u0096\u0002\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u000f\u0010\u0018\u001a\u00020\u0006H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u000f\u0010\u001b\u001a\u00020\u001aH\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u001d\u001a\u0004\u0008\u001e\u0010\u001f\u00a8\u0006\""
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;",
        "",
        "",
        "rawValue",
        "<init>",
        "([B)V",
        "",
        "seen0",
        "Luz0/l1;",
        "serializationConstructorMarker",
        "(I[BLuz0/l1;)V",
        "self",
        "Ltz0/b;",
        "output",
        "Lsz0/g;",
        "serialDesc",
        "Llx0/b0;",
        "write$Self$genx_release",
        "(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;Ltz0/b;Lsz0/g;)V",
        "write$Self",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "hashCode",
        "()I",
        "",
        "toString",
        "()Ljava/lang/String;",
        "[B",
        "getRawValue",
        "()[B",
        "Companion",
        "$serializer",
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

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;


# instance fields
.field private final rawValue:[B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public synthetic constructor <init>(I[BLuz0/l1;)V
    .locals 1

    and-int/lit8 p3, p1, 0x1

    const/4 v0, 0x1

    if-ne v0, p3, :cond_0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    return-void

    :cond_0
    sget-object p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$$serializer;

    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey$$serializer;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v0, p0}, Luz0/b1;->l(IILsz0/g;)V

    const/4 p0, 0x0

    throw p0
.end method

.method private constructor <init>([B)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    return-void
.end method

.method public synthetic constructor <init>([BLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;-><init>([B)V

    return-void
.end method

.method public static final synthetic write$Self$genx_release(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;Ltz0/b;Lsz0/g;)V
    .locals 2

    .line 1
    sget-object v0, Luz0/i;->c:Luz0/i;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-interface {p1, p2, v1, v0, p0}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    .line 12
    .line 13
    check-cast p1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;

    .line 14
    .line 15
    iget-object p1, p1, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    .line 16
    .line 17
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public final getRawValue()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PrivateKey;->rawValue:[B

    .line 2
    .line 3
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "PrivateKey(rawValue="

    .line 8
    .line 9
    const-string v1, ")"

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
