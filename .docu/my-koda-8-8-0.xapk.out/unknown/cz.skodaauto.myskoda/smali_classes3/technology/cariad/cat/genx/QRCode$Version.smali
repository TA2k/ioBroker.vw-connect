.class public final Ltechnology/cariad/cat/genx/QRCode$Version;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/QRCode;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Version"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000f\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0007\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0004\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u0010\u0010\n\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0010\u0010\u000c\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u000b\u0010\tJ\u0010\u0010\u000e\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\r\u0010\tJ.\u0010\u0011\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0010\u0010\u0013\u001a\u00020\u0012H\u00d6\u0001\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J\u0010\u0010\u0016\u001a\u00020\u0015H\u00d6\u0001\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u001a\u0010\u001a\u001a\u00020\u00192\u0008\u0010\u0018\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u0008\u001a\u0010\u001bR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u001c\u001a\u0004\u0008\u001d\u0010\tR\u0017\u0010\u0004\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0004\u0010\u001c\u001a\u0004\u0008\u001e\u0010\tR\u0017\u0010\u0005\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010\u001c\u001a\u0004\u0008\u001f\u0010\t\u00a8\u0006 "
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/QRCode$Version;",
        "",
        "Llx0/z;",
        "major",
        "minor",
        "patch",
        "<init>",
        "(SSSLkotlin/jvm/internal/g;)V",
        "component1-Mh2AYeg",
        "()S",
        "component1",
        "component2-Mh2AYeg",
        "component2",
        "component3-Mh2AYeg",
        "component3",
        "copy-Ut6C-W8",
        "(SSS)Ltechnology/cariad/cat/genx/QRCode$Version;",
        "copy",
        "",
        "toString",
        "()Ljava/lang/String;",
        "",
        "hashCode",
        "()I",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "S",
        "getMajor-Mh2AYeg",
        "getMinor-Mh2AYeg",
        "getPatch-Mh2AYeg",
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


# instance fields
.field private final major:S

.field private final minor:S

.field private final patch:S


# direct methods
.method private constructor <init>(SSS)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-short p1, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    iput-short p2, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    iput-short p3, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    return-void
.end method

.method public synthetic constructor <init>(SSSLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/QRCode$Version;-><init>(SSS)V

    return-void
.end method

.method public static synthetic copy-Ut6C-W8$default(Ltechnology/cariad/cat/genx/QRCode$Version;SSSILjava/lang/Object;)Ltechnology/cariad/cat/genx/QRCode$Version;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-short p1, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-short p2, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-short p3, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/QRCode$Version;->copy-Ut6C-W8(SSS)Ltechnology/cariad/cat/genx/QRCode$Version;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public final component1-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 2
    .line 3
    return p0
.end method

.method public final component2-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 2
    .line 3
    return p0
.end method

.method public final component3-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 2
    .line 3
    return p0
.end method

.method public final copy-Ut6C-W8(SSS)Ltechnology/cariad/cat/genx/QRCode$Version;
    .locals 1

    .line 1
    new-instance p0, Ltechnology/cariad/cat/genx/QRCode$Version;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, p1, p2, p3, v0}, Ltechnology/cariad/cat/genx/QRCode$Version;-><init>(SSSLkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
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
    instance-of v1, p1, Ltechnology/cariad/cat/genx/QRCode$Version;

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
    check-cast p1, Ltechnology/cariad/cat/genx/QRCode$Version;

    .line 12
    .line 13
    iget-short v1, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 14
    .line 15
    iget-short v3, p1, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-short v1, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 21
    .line 22
    iget-short v3, p1, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 28
    .line 29
    iget-short p1, p1, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 30
    .line 31
    if-eq p0, p1, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    return v0
.end method

.method public final getMajor-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 2
    .line 3
    return p0
.end method

.method public final getMinor-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 2
    .line 3
    return p0
.end method

.method public final getPatch-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-short v0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Short;->hashCode(S)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-short v1, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 10
    .line 11
    invoke-static {v1}, Ljava/lang/Short;->hashCode(S)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 19
    .line 20
    invoke-static {p0}, Ljava/lang/Short;->hashCode(S)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-short v0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->major:S

    .line 2
    .line 3
    invoke-static {v0}, Llx0/z;->a(S)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-short v1, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->minor:S

    .line 8
    .line 9
    invoke-static {v1}, Llx0/z;->a(S)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-short p0, p0, Ltechnology/cariad/cat/genx/QRCode$Version;->patch:S

    .line 14
    .line 15
    invoke-static {p0}, Llx0/z;->a(S)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string v2, ", minor="

    .line 20
    .line 21
    const-string v3, ", patch="

    .line 22
    .line 23
    const-string v4, "Version(major="

    .line 24
    .line 25
    invoke-static {v4, v0, v2, v1, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v1, ")"

    .line 30
    .line 31
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method
