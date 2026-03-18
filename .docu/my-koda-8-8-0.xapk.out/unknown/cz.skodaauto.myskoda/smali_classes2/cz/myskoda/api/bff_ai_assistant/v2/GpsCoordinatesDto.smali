.class public final Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0006\n\u0002\u0008\r\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u001b\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\t\u0010\r\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J\u001d\u0010\u000f\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u0010\u001a\u00020\u00112\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0013\u001a\u00020\u0014H\u00d6\u0001J\t\u0010\u0015\u001a\u00020\u0016H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0007\u0010\u0008\u001a\u0004\u0008\t\u0010\nR\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u0008\u001a\u0004\u0008\u000c\u0010\n\u00a8\u0006\u0017"
    }
    d2 = {
        "Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;",
        "",
        "latitude",
        "",
        "longitude",
        "<init>",
        "(DD)V",
        "getLatitude$annotations",
        "()V",
        "getLatitude",
        "()D",
        "getLongitude$annotations",
        "getLongitude",
        "component1",
        "component2",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
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
.field private final latitude:D

.field private final longitude:D


# direct methods
.method public constructor <init>(DD)V
    .locals 0
    .param p1    # D
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "latitude"
        .end annotation
    .end param
    .param p3    # D
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "longitude"
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 5
    .line 6
    iput-wide p3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 7
    .line 8
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;DDILjava/lang/Object;)Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p5, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-wide p3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->copy(DD)Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static synthetic getLatitude$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "latitude"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLongitude$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "longitude"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final copy(DD)Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
    .locals 0
    .param p1    # D
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "latitude"
        .end annotation
    .end param
    .param p3    # D
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "longitude"
        .end annotation
    .end param

    .line 1
    new-instance p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;-><init>(DD)V

    .line 4
    .line 5
    .line 6
    return-object p0
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
    instance-of v1, p1, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

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
    check-cast p1, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 12
    .line 13
    iget-wide v3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 14
    .line 15
    iget-wide v5, p1, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 16
    .line 17
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-wide v3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 25
    .line 26
    iget-wide p0, p1, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 27
    .line 28
    invoke-static {v3, v4, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public final getLatitude()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getLongitude()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-wide v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/lang/Double;->hashCode(D)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->latitude:D

    .line 2
    .line 3
    iget-wide v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->longitude:D

    .line 4
    .line 5
    const-string p0, "GpsCoordinatesDto(latitude="

    .line 6
    .line 7
    const-string v4, ", longitude="

    .line 8
    .line 9
    invoke-static {p0, v4, v0, v1}, Lp3/m;->r(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string v0, ")"

    .line 14
    .line 15
    invoke-static {p0, v2, v3, v0}, Lp3/m;->n(Ljava/lang/StringBuilder;DLjava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
