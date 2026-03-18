.class public final Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0007\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\u0008\u0080\u0008\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\t\u0010\u0008\u001a\u00020\u0003H\u00c6\u0003J\u0013\u0010\t\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\n\u001a\u00020\u000b2\u0008\u0010\u000c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\r\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u000e\u001a\u00020\u000fH\u00d6\u0001R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;",
        "",
        "version",
        "",
        "<init>",
        "(I)V",
        "getVersion",
        "()I",
        "component1",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "",
        "async-event_release"
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
.field private final version:I
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "version"
    .end annotation
.end field


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 5
    .line 6
    return-void
.end method

.method public static synthetic copy$default(Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;IILjava/lang/Object;)Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->copy(I)Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 2
    .line 3
    return p0
.end method

.method public final copy(I)Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;
    .locals 0

    .line 1
    new-instance p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

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
    instance-of v1, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

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
    check-cast p1, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;

    .line 12
    .line 13
    iget p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 14
    .line 15
    iget p1, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public final getVersion()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

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
    iget p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/VersionDto;->version:I

    .line 2
    .line 3
    const-string v0, "VersionDto(version="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
