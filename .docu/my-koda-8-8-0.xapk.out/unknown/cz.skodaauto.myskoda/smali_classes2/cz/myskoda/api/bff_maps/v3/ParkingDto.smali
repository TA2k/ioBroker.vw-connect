.class public final Lcz/myskoda/api/bff_maps/v3/ParkingDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0006\n\u0002\u0008\u0017\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B5\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0018\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\u0019\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u0010\u0010\u001a\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0014J\u000b\u0010\u001b\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J<\u0010\u001c\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001\u00a2\u0006\u0002\u0010\u001dJ\u0013\u0010\u001e\u001a\u00020\u001f2\u0008\u0010 \u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010!\u001a\u00020\"H\u00d6\u0001J\t\u0010#\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001e\u0010\u0004\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R \u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0015\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u0014R\u001e\u0010\u0008\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0016\u0010\u000c\u001a\u0004\u0008\u0017\u0010\u000e\u00a8\u0006$"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/ParkingDto;",
        "",
        "parkingType",
        "",
        "geometry",
        "Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;",
        "pricePerHour",
        "",
        "currencyCode",
        "<init>",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)V",
        "getParkingType$annotations",
        "()V",
        "getParkingType",
        "()Ljava/lang/String;",
        "getGeometry$annotations",
        "getGeometry",
        "()Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;",
        "getPricePerHour$annotations",
        "getPricePerHour",
        "()Ljava/lang/Double;",
        "Ljava/lang/Double;",
        "getCurrencyCode$annotations",
        "getCurrencyCode",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)Lcz/myskoda/api/bff_maps/v3/ParkingDto;",
        "equals",
        "",
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
.field private final currencyCode:Ljava/lang/String;

.field private final geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

.field private final parkingType:Ljava/lang/String;

.field private final pricePerHour:Ljava/lang/Double;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "parkingType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "geometry"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pricePerHour"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currencyCode"
        .end annotation
    .end param

    const-string v0, "parkingType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x2

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_1

    move-object p3, v0

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    move-object p4, v0

    .line 6
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/ParkingDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v3/ParkingDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v3/ParkingDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->copy(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)Lcz/myskoda/api/bff_maps/v3/ParkingDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getCurrencyCode$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "currencyCode"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getGeometry$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "geometry"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getParkingType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "parkingType"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPricePerHour$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "pricePerHour"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)Lcz/myskoda/api/bff_maps/v3/ParkingDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "parkingType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "geometry"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pricePerHour"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currencyCode"
        .end annotation
    .end param

    .line 1
    const-string p0, "parkingType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/ParkingDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;Ljava/lang/Double;Ljava/lang/String;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v3/ParkingDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/ParkingDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 47
    .line 48
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-nez p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public final getCurrencyCode()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getGeometry()Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParkingType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPricePerHour()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    move v1, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    :goto_0
    add-int/2addr v0, v1

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 24
    .line 25
    if-nez v1, :cond_1

    .line 26
    .line 27
    move v1, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    :goto_1
    add-int/2addr v0, v1

    .line 34
    mul-int/lit8 v0, v0, 0x1f

    .line 35
    .line 36
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 37
    .line 38
    if-nez p0, :cond_2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_2
    add-int/2addr v0, v2

    .line 46
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->parkingType:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->geometry:Lcz/myskoda/api/bff_maps/v3/ParkingGeometryDto;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->pricePerHour:Ljava/lang/Double;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ParkingDto;->currencyCode:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "ParkingDto(parkingType="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", geometry="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", pricePerHour="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", currencyCode="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
