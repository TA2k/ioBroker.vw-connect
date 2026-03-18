.class public final Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0017\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B3\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0018\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0005H\u00c6\u0003J\u0010\u0010\u001a\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0014J\u000b\u0010\u001b\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J:\u0010\u001c\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0005H\u00c6\u0001\u00a2\u0006\u0002\u0010\u001dJ\u0013\u0010\u001e\u001a\u00020\u001f2\u0008\u0010 \u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010!\u001a\u00020\u0007H\u00d6\u0001J\t\u0010\"\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R \u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0015\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u0014R\u001e\u0010\u0008\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0016\u0010\u000c\u001a\u0004\u0008\u0017\u0010\u0011\u00a8\u0006#"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;",
        "",
        "id",
        "",
        "name",
        "",
        "targetStateOfChargeInPercent",
        "",
        "nextChargingTime",
        "<init>",
        "(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V",
        "getId$annotations",
        "()V",
        "getId",
        "()J",
        "getName$annotations",
        "getName",
        "()Ljava/lang/String;",
        "getTargetStateOfChargeInPercent$annotations",
        "getTargetStateOfChargeInPercent",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "getNextChargingTime$annotations",
        "getNextChargingTime",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;",
        "equals",
        "",
        "other",
        "hashCode",
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
.field private final id:J

.field private final name:Ljava/lang/String;

.field private final nextChargingTime:Ljava/lang/String;

.field private final targetStateOfChargeInPercent:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V
    .locals 1
    .param p1    # J
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "targetStateOfChargeInPercent"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "nextChargingTime"
        .end annotation
    .end param

    const-string v0, "name"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-wide p1, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

    .line 3
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 4
    iput-object p4, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 5
    iput-object p5, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p7, p6, 0x4

    const/4 v0, 0x0

    if-eqz p7, :cond_0

    move-object p4, v0

    :cond_0
    and-int/lit8 p6, p6, 0x8

    if-eqz p6, :cond_1

    move-object p5, v0

    .line 6
    :cond_1
    invoke-direct/range {p0 .. p5}, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;-><init>(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;
    .locals 6

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

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
    iget-object p3, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 13
    .line 14
    :cond_1
    move-object v3, p3

    .line 15
    and-int/lit8 p1, p6, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-object p4, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

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
    iget-object p5, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 27
    .line 28
    :cond_3
    move-object v0, p0

    .line 29
    move-object v5, p5

    .line 30
    invoke-virtual/range {v0 .. v5}, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->copy(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static synthetic getId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "id"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getName$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "name"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getNextChargingTime$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "nextChargingTime"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTargetStateOfChargeInPercent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "targetStateOfChargeInPercent"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;
    .locals 6
    .param p1    # J
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "targetStateOfChargeInPercent"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "nextChargingTime"
        .end annotation
    .end param

    .line 1
    const-string p0, "name"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;

    .line 7
    .line 8
    move-wide v1, p1

    .line 9
    move-object v3, p3

    .line 10
    move-object v4, p4

    .line 11
    move-object v5, p5

    .line 12
    invoke-direct/range {v0 .. v5}, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;-><init>(JLjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;

    .line 12
    .line 13
    iget-wide v3, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

    .line 14
    .line 15
    iget-wide v5, p1, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_3

    .line 31
    .line 32
    return v2

    .line 33
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 34
    .line 35
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 36
    .line 37
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_4

    .line 42
    .line 43
    return v2

    .line 44
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 45
    .line 46
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-nez p0, :cond_5

    .line 53
    .line 54
    return v2

    .line 55
    :cond_5
    return v0
.end method

.method public final getId()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNextChargingTime()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTargetStateOfChargeInPercent()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

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
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    move v2, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    :goto_0
    add-int/2addr v0, v2

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 30
    .line 31
    if-nez p0, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    :goto_1
    add-int/2addr v0, v3

    .line 39
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->id:J

    .line 2
    .line 3
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->name:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v3, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->targetStateOfChargeInPercent:Ljava/lang/Integer;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/CurrentVehiclePositionProfileDto;->nextChargingTime:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v4, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v5, "CurrentVehiclePositionProfileDto(id="

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
    const-string v0, ", name="

    .line 20
    .line 21
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", targetStateOfChargeInPercent="

    .line 28
    .line 29
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", nextChargingTime="

    .line 36
    .line 37
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
