.class public final Lcz/myskoda/api/bff/v1/ChargingTimeDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0017\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B/\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0001\u0010\u0008\u001a\u00020\u0007\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0017\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0007H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0007H\u00c6\u0003J1\u0010\u001b\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0003\u0010\u0008\u001a\u00020\u0007H\u00c6\u0001J\u0013\u0010\u001c\u001a\u00020\u00052\u0008\u0010\u001d\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001e\u001a\u00020\u001fH\u00d6\u0001J\t\u0010 \u001a\u00020\u0007H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R\u001c\u0010\u0006\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u0014R\u001c\u0010\u0008\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0015\u0010\u000c\u001a\u0004\u0008\u0016\u0010\u0014\u00a8\u0006!"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
        "",
        "id",
        "",
        "enabled",
        "",
        "startTime",
        "",
        "endTime",
        "<init>",
        "(JZLjava/lang/String;Ljava/lang/String;)V",
        "getId$annotations",
        "()V",
        "getId",
        "()J",
        "getEnabled$annotations",
        "getEnabled",
        "()Z",
        "getStartTime$annotations",
        "getStartTime",
        "()Ljava/lang/String;",
        "getEndTime$annotations",
        "getEndTime",
        "component1",
        "component2",
        "component3",
        "component4",
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
.field private final enabled:Z

.field private final endTime:Ljava/lang/String;

.field private final id:J

.field private final startTime:Ljava/lang/String;


# direct methods
.method public constructor <init>(JZLjava/lang/String;Ljava/lang/String;)V
    .locals 1
    .param p1    # J
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p3    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "enabled"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "startTime"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "endTime"
        .end annotation
    .end param

    .line 1
    const-string v0, "startTime"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "endTime"

    .line 7
    .line 8
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-wide p1, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 15
    .line 16
    iput-boolean p3, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 17
    .line 18
    iput-object p4, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p5, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 21
    .line 22
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/ChargingTimeDto;JZLjava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/ChargingTimeDto;
    .locals 6

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 6
    .line 7
    :cond_0
    move-wide v1, p1

    .line 8
    and-int/lit8 p1, p6, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p3, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 13
    .line 14
    :cond_1
    move v3, p3

    .line 15
    and-int/lit8 p1, p6, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-object p4, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 20
    .line 21
    :cond_2
    move-object v4, p4

    .line 22
    and-int/lit8 p1, p6, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-object p5, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 27
    .line 28
    :cond_3
    move-object v0, p0

    .line 29
    move-object v5, p5

    .line 30
    invoke-virtual/range {v0 .. v5}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->copy(JZLjava/lang/String;Ljava/lang/String;)Lcz/myskoda/api/bff/v1/ChargingTimeDto;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static synthetic getEnabled$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "enabled"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getEndTime$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "endTime"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "id"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getStartTime$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "startTime"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(JZLjava/lang/String;Ljava/lang/String;)Lcz/myskoda/api/bff/v1/ChargingTimeDto;
    .locals 6
    .param p1    # J
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p3    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "enabled"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "startTime"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "endTime"
        .end annotation
    .end param

    .line 1
    const-string p0, "startTime"

    .line 2
    .line 3
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "endTime"

    .line 7
    .line 8
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;

    .line 12
    .line 13
    move-wide v1, p1

    .line 14
    move v3, p3

    .line 15
    move-object v4, p4

    .line 16
    move-object v5, p5

    .line 17
    invoke-direct/range {v0 .. v5}, Lcz/myskoda/api/bff/v1/ChargingTimeDto;-><init>(JZLjava/lang/String;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;

    .line 12
    .line 13
    iget-wide v3, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 14
    .line 15
    iget-wide v5, p1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 16
    .line 17
    cmp-long v1, v3, v5

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    return v2

    .line 22
    :cond_2
    iget-boolean v1, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 23
    .line 24
    iget-boolean v3, p1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 25
    .line 26
    if-eq v1, v3, :cond_3

    .line 27
    .line 28
    return v2

    .line 29
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 32
    .line 33
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-nez v1, :cond_4

    .line 38
    .line 39
    return v2

    .line 40
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 41
    .line 42
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-nez p0, :cond_5

    .line 49
    .line 50
    return v2

    .line 51
    :cond_5
    return v0
.end method

.method public final getEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getEndTime()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getId()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getStartTime()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

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
    iget-boolean v2, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->id:J

    .line 2
    .line 3
    iget-boolean v2, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->enabled:Z

    .line 4
    .line 5
    iget-object v3, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->startTime:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingTimeDto;->endTime:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v4, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v5, "ChargingTimeDto(id="

    .line 12
    .line 13
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v4, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", enabled="

    .line 20
    .line 21
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", startTime="

    .line 28
    .line 29
    const-string v1, ", endTime="

    .line 30
    .line 31
    invoke-static {v4, v0, v3, v1, p0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string p0, ")"

    .line 35
    .line 36
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
