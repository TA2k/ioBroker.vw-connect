.class public final Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\t\u0008\u0080\u0008\u0018\u00002\u00020\u0001:\u0001\"B\u001f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0004\u001a\u00020\u0002\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0010\u0010\u000b\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0010\u0010\r\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u000c\u0010\nJ\u0010\u0010\u000e\u001a\u00020\u0005H\u00c6\u0003\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ.\u0010\u0012\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0005H\u00c6\u0001\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0010\u0010\u0014\u001a\u00020\u0013H\u00d6\u0001\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u0010\u0010\u0017\u001a\u00020\u0016H\u00d6\u0001\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u001a\u0010\u001b\u001a\u00020\u001a2\u0008\u0010\u0019\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u001d\u001a\u0004\u0008\u001e\u0010\nR\u0017\u0010\u0004\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0004\u0010\u001d\u001a\u0004\u0008\u001f\u0010\nR\u0017\u0010\u0006\u001a\u00020\u00058\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010 \u001a\u0004\u0008!\u0010\u000f\u00a8\u0006#"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
        "",
        "Llx0/z;",
        "major",
        "minor",
        "Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;",
        "source",
        "<init>",
        "(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;Lkotlin/jvm/internal/g;)V",
        "component1-Mh2AYeg",
        "()S",
        "component1",
        "component2-Mh2AYeg",
        "component2",
        "component3",
        "()Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;",
        "copy-Y_-6-A0",
        "(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
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
        "Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;",
        "getSource",
        "Source",
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

.field private final source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;


# direct methods
.method private constructor <init>(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;)V
    .locals 1

    const-string v0, "source"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-short p1, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    iput-short p2, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    iput-object p3, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    return-void
.end method

.method public synthetic constructor <init>(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;-><init>(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;)V

    return-void
.end method

.method public static synthetic copy-Y_-6-A0$default(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-short p1, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-short p2, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->copy-Y_-6-A0(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

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
    iget-short p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    .line 2
    .line 3
    return p0
.end method

.method public final component2-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy-Y_-6-A0(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;
    .locals 1

    .line 1
    const-string p0, "source"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {p0, p1, p2, p3, v0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;-><init>(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;Lkotlin/jvm/internal/g;)V

    .line 10
    .line 11
    .line 12
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
    instance-of v1, p1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

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
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 12
    .line 13
    iget-short v1, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    .line 14
    .line 15
    iget-short v3, p1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-short v1, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    .line 21
    .line 22
    iget-short v3, p1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 28
    .line 29
    iget-object p1, p1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

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
    iget-short p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    .line 2
    .line 3
    return p0
.end method

.method public final getMinor-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    .line 2
    .line 3
    return p0
.end method

.method public final getSource()Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-short v0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

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
    iget-short v1, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

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
    iget-short v0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->major:S

    .line 2
    .line 3
    invoke-static {v0}, Llx0/z;->a(S)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-short v1, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->minor:S

    .line 8
    .line 9
    invoke-static {v1}, Llx0/z;->a(S)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->source:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 14
    .line 15
    const-string v2, ", minor="

    .line 16
    .line 17
    const-string v3, ", source="

    .line 18
    .line 19
    const-string v4, "BeaconInformation(major="

    .line 20
    .line 21
    invoke-static {v4, v0, v2, v1, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p0, ")"

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
