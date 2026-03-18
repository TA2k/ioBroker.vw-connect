.class public final Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = true
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u000f\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0081\u0008\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000f\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0010\u001a\u00020\u0005H\u00c6\u0003J\'\u0010\u0011\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0005H\u00c6\u0001J\u0013\u0010\u0012\u001a\u00020\u00052\u0008\u0010\u0013\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0014\u001a\u00020\u0015H\u00d6\u0001J\t\u0010\u0016\u001a\u00020\u0003H\u00d6\u0001R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\nR\u0016\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\u000cR\u0016\u0010\u0006\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000c\u00a8\u0006\u0017"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;",
        "",
        "linkUrl",
        "",
        "bannerEnabled",
        "",
        "fullScreenEnabled",
        "<init>",
        "(Ljava/lang/String;ZZ)V",
        "getLinkUrl",
        "()Ljava/lang/String;",
        "getBannerEnabled",
        "()Z",
        "getFullScreenEnabled",
        "component1",
        "component2",
        "component3",
        "copy",
        "equals",
        "other",
        "hashCode",
        "",
        "toString",
        "connectivity-sunset_release"
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
.field public static final $stable:I


# instance fields
.field private final bannerEnabled:Z
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "bannerEnabled"
    .end annotation
.end field

.field private final fullScreenEnabled:Z
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "fullScreenEnabled"
    .end annotation
.end field

.field private final linkUrl:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "linkUrl"
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;ZZ)V
    .locals 1

    .line 1
    const-string v0, "linkUrl"

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
    iput-object p1, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 10
    .line 11
    iput-boolean p2, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 12
    .line 13
    iput-boolean p3, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 14
    .line 15
    return-void
.end method

.method public static synthetic copy$default(Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;Ljava/lang/String;ZZILjava/lang/Object;)Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->copy(Ljava/lang/String;ZZ)Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(Ljava/lang/String;ZZ)Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;
    .locals 0

    .line 1
    const-string p0, "linkUrl"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;-><init>(Ljava/lang/String;ZZ)V

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
    instance-of v1, p1, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;

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
    check-cast p1, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-boolean v1, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 32
    .line 33
    iget-boolean p1, p1, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 34
    .line 35
    if-eq p0, p1, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    return v0
.end method

.method public final getBannerEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getFullScreenEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getLinkUrl()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-boolean v2, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 17
    .line 18
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/2addr p0, v0

    .line 23
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->linkUrl:Ljava/lang/String;

    .line 2
    .line 3
    iget-boolean v1, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->bannerEnabled:Z

    .line 4
    .line 5
    iget-boolean p0, p0, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->fullScreenEnabled:Z

    .line 6
    .line 7
    const-string v2, ", bannerEnabled="

    .line 8
    .line 9
    const-string v3, ", fullScreenEnabled="

    .line 10
    .line 11
    const-string v4, "ConnectivitySunsetConfigDto(linkUrl="

    .line 12
    .line 13
    invoke-static {v4, v0, v2, v3, v1}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, ")"

    .line 18
    .line 19
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
