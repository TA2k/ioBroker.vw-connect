.class public final Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\r\n\u0002\u0010\u0008\n\u0002\u0008\u0005\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0080\u0008\u0018\u0000 \u001c2\u00020\u0001:\u0001\u001cB\u001f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0013\u0010\u0012\u001a\u00020\u00072\u0008\u0010\u0013\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\u0008\u0010\u0014\u001a\u00020\u0015H\u0016J\t\u0010\u0016\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0007H\u00c6\u0003J\'\u0010\u0019\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0007H\u00c6\u0001J\t\u0010\u001a\u001a\u00020\u001bH\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\rR\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\u000fR\u0011\u0010\u0010\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u000b\u00a8\u0006\u001d"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;",
        "",
        "keyExchangeServiceVersion",
        "",
        "platform",
        "",
        "areOuterAntennaKeysRequired",
        "",
        "<init>",
        "([BBZ)V",
        "getKeyExchangeServiceVersion",
        "()[B",
        "getPlatform",
        "()B",
        "getAreOuterAntennaKeysRequired",
        "()Z",
        "byteArray",
        "getByteArray",
        "equals",
        "other",
        "hashCode",
        "",
        "component1",
        "component2",
        "component3",
        "copy",
        "toString",
        "",
        "Companion",
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


# static fields
.field public static final Companion:Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;

.field public static final EXPECTED_SIZE:I = 0x5


# instance fields
.field private final areOuterAntennaKeysRequired:Z

.field private final byteArray:[B

.field private final keyExchangeServiceVersion:[B

.field private final platform:B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->Companion:Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>([BBZ)V
    .locals 1

    .line 1
    const-string v0, "keyExchangeServiceVersion"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 10
    .line 11
    iput-byte p2, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 12
    .line 13
    iput-boolean p3, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 14
    .line 15
    invoke-static {p2, p1}, Lmx0/n;->L(B[B)[B

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-static {p3}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeMessageKt;->toByte(Z)B

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    invoke-static {p2, p1}, Lmx0/n;->L(B[B)[B

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->byteArray:[B

    .line 28
    .line 29
    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;[BBZILjava/lang/Object;)Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-byte p2, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->copy([BBZ)Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public final component1()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy([BBZ)Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;
    .locals 0

    .line 1
    const-string p0, "keyExchangeServiceVersion"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;-><init>([BBZ)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

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
    iget-byte v1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 12
    .line 13
    check-cast p1, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

    .line 14
    .line 15
    iget-byte v3, p1, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 28
    .line 29
    iget-object v3, p1, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 30
    .line 31
    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([B[B)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-nez v1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->byteArray:[B

    .line 39
    .line 40
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->byteArray:[B

    .line 41
    .line 42
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-nez p0, :cond_5

    .line 47
    .line 48
    return v2

    .line 49
    :cond_5
    return v0
.end method

.method public final getAreOuterAntennaKeysRequired()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getByteArray()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->byteArray:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final getKeyExchangeServiceVersion()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPlatform()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-byte v0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Byte;->hashCode(B)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 17
    .line 18
    invoke-static {v2}, Ljava/util/Arrays;->hashCode([B)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->byteArray:[B

    .line 25
    .line 26
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    add-int/2addr p0, v2

    .line 31
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->keyExchangeServiceVersion:[B

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-byte v1, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->platform:B

    .line 8
    .line 9
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->areOuterAntennaKeysRequired:Z

    .line 10
    .line 11
    const-string v2, ", platform="

    .line 12
    .line 13
    const-string v3, ", areOuterAntennaKeysRequired="

    .line 14
    .line 15
    const-string v4, "StaticInformationResponse(keyExchangeServiceVersion="

    .line 16
    .line 17
    invoke-static {v4, v1, v0, v2, v3}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, ")"

    .line 22
    .line 23
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
