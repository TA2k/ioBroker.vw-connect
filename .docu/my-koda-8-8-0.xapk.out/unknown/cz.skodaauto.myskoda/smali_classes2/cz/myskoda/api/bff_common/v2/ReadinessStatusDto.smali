.class public final Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0010\u000e\n\u0002\u0008\u0018\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B;\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0018\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001b\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\u001c\u001a\u0004\u0018\u00010\u0008H\u00c6\u0003J=\u0010\u001d\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00032\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008H\u00c6\u0001J\u0013\u0010\u001e\u001a\u00020\u00032\u0008\u0010\u001f\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010 \u001a\u00020!H\u00d6\u0001J\t\u0010\"\u001a\u00020\u0008H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u000eR\u001c\u0010\u0005\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0011\u0010\u000c\u001a\u0004\u0008\u0012\u0010\u000eR\u001c\u0010\u0006\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\u000c\u001a\u0004\u0008\u0014\u0010\u000eR\u001e\u0010\u0007\u001a\u0004\u0018\u00010\u00088\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0015\u0010\u000c\u001a\u0004\u0008\u0016\u0010\u0017\u00a8\u0006#"
    }
    d2 = {
        "Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;",
        "",
        "unreachable",
        "",
        "inMotion",
        "ignitionOn",
        "batteryProtectionLimitOn",
        "softwareUpdateStatus",
        "",
        "<init>",
        "(ZZZZLjava/lang/String;)V",
        "getUnreachable$annotations",
        "()V",
        "getUnreachable",
        "()Z",
        "getInMotion$annotations",
        "getInMotion",
        "getIgnitionOn$annotations",
        "getIgnitionOn",
        "getBatteryProtectionLimitOn$annotations",
        "getBatteryProtectionLimitOn",
        "getSoftwareUpdateStatus$annotations",
        "getSoftwareUpdateStatus",
        "()Ljava/lang/String;",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "copy",
        "equals",
        "other",
        "hashCode",
        "",
        "toString",
        "bff-api_release"
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
.field private final batteryProtectionLimitOn:Z

.field private final ignitionOn:Z

.field private final inMotion:Z

.field private final softwareUpdateStatus:Ljava/lang/String;

.field private final unreachable:Z


# direct methods
.method public constructor <init>(ZZZZLjava/lang/String;)V
    .locals 0
    .param p1    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "unreachable"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "inMotion"
        .end annotation
    .end param
    .param p3    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "ignitionOn"
        .end annotation
    .end param
    .param p4    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryProtectionLimitOn"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "softwareUpdateStatus"
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 3
    iput-boolean p2, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 4
    iput-boolean p3, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 5
    iput-boolean p4, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(ZZZZLjava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p6, p6, 0x10

    if-eqz p6, :cond_0

    const/4 p5, 0x0

    :cond_0
    move-object v0, p0

    move v1, p1

    move v2, p2

    move v3, p3

    move v4, p4

    move-object v5, p5

    .line 7
    invoke-direct/range {v0 .. v5}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;-><init>(ZZZZLjava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;ZZZZLjava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;
    .locals 0

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p7, p6, 0x2

    .line 8
    .line 9
    if-eqz p7, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p7, p6, 0x4

    .line 14
    .line 15
    if-eqz p7, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p7, p6, 0x8

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    iget-boolean p4, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p6, p6, 0x10

    .line 26
    .line 27
    if-eqz p6, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    move p6, p4

    .line 32
    move-object p7, p5

    .line 33
    move p4, p2

    .line 34
    move p5, p3

    .line 35
    move-object p2, p0

    .line 36
    move p3, p1

    .line 37
    invoke-virtual/range {p2 .. p7}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->copy(ZZZZLjava/lang/String;)Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public static synthetic getBatteryProtectionLimitOn$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "batteryProtectionLimitOn"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getIgnitionOn$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "ignitionOn"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getInMotion$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "inMotion"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getSoftwareUpdateStatus$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "softwareUpdateStatus"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUnreachable$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "unreachable"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(ZZZZLjava/lang/String;)Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;
    .locals 0
    .param p1    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "unreachable"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "inMotion"
        .end annotation
    .end param
    .param p3    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "ignitionOn"
        .end annotation
    .end param
    .param p4    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryProtectionLimitOn"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "softwareUpdateStatus"
        .end annotation
    .end param

    .line 1
    new-instance p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;

    .line 2
    .line 3
    invoke-direct/range {p0 .. p5}, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;-><init>(ZZZZLjava/lang/String;)V

    .line 4
    .line 5
    .line 6
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
    instance-of v1, p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;

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
    check-cast p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;

    .line 12
    .line 13
    iget-boolean v1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 42
    .line 43
    iget-object p1, p1, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-nez p0, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    return v0
.end method

.method public final getBatteryProtectionLimitOn()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getIgnitionOn()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getInMotion()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getSoftwareUpdateStatus()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUnreachable()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 29
    .line 30
    if-nez p0, :cond_0

    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    :goto_0
    add-int/2addr v0, p0

    .line 39
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-boolean v0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->unreachable:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->inMotion:Z

    .line 4
    .line 5
    iget-boolean v2, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->ignitionOn:Z

    .line 6
    .line 7
    iget-boolean v3, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->batteryProtectionLimitOn:Z

    .line 8
    .line 9
    iget-object p0, p0, Lcz/myskoda/api/bff_common/v2/ReadinessStatusDto;->softwareUpdateStatus:Ljava/lang/String;

    .line 10
    .line 11
    const-string v4, ", inMotion="

    .line 12
    .line 13
    const-string v5, ", ignitionOn="

    .line 14
    .line 15
    const-string v6, "ReadinessStatusDto(unreachable="

    .line 16
    .line 17
    invoke-static {v6, v4, v5, v0, v1}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, ", batteryProtectionLimitOn="

    .line 22
    .line 23
    const-string v4, ", softwareUpdateStatus="

    .line 24
    .line 25
    invoke-static {v0, v2, v1, v3, v4}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v1, ")"

    .line 29
    .line 30
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
