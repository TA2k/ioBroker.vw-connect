.class public final Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0013\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B)\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\u0016\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u0010\u0010\u0017\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0013J0\u0010\u0018\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007H\u00c6\u0001\u00a2\u0006\u0002\u0010\u0019J\u0013\u0010\u001a\u001a\u00020\u001b2\u0008\u0010\u001c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001d\u001a\u00020\u0007H\u00d6\u0001J\t\u0010\u001e\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001e\u0010\u0004\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\u0010R \u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0014\u0012\u0004\u0008\u0011\u0010\u000b\u001a\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u001f"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;",
        "",
        "gpsCoordinates",
        "Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;",
        "formattedAddress",
        "",
        "distanceInMeters",
        "",
        "<init>",
        "(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)V",
        "getGpsCoordinates$annotations",
        "()V",
        "getGpsCoordinates",
        "()Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;",
        "getFormattedAddress$annotations",
        "getFormattedAddress",
        "()Ljava/lang/String;",
        "getDistanceInMeters$annotations",
        "getDistanceInMeters",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "component1",
        "component2",
        "component3",
        "copy",
        "(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;",
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
.field private final distanceInMeters:Ljava/lang/Integer;

.field private final formattedAddress:Ljava/lang/String;

.field private final gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;


# direct methods
.method public constructor <init>(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)V
    .locals 1
    .param p1    # Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "gpsCoordinates"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "formattedAddress"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "distanceInMeters"
        .end annotation
    .end param

    const-string v0, "gpsCoordinates"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    return-void
.end method

.method public synthetic constructor <init>(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p5, p4, 0x2

    const/4 v0, 0x0

    if-eqz p5, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    move-object p3, v0

    .line 5
    :cond_1
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;-><init>(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->copy(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getDistanceInMeters$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "distanceInMeters"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getFormattedAddress$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "formattedAddress"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getGpsCoordinates$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "gpsCoordinates"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;
    .locals 0
    .param p1    # Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "gpsCoordinates"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "formattedAddress"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "distanceInMeters"
        .end annotation
    .end param

    .line 1
    const-string p0, "gpsCoordinates"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;-><init>(Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;Ljava/lang/String;Ljava/lang/Integer;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    return v0
.end method

.method public final getDistanceInMeters()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFormattedAddress()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getGpsCoordinates()Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

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
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 24
    .line 25
    if-nez p0, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    :goto_1
    add-int/2addr v0, v2

    .line 33
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->gpsCoordinates:Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->formattedAddress:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionDto;->distanceInMeters:Ljava/lang/Integer;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "VehicleParkingPositionDto(gpsCoordinates="

    .line 10
    .line 11
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", formattedAddress="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", distanceInMeters="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, ")"

    .line 31
    .line 32
    invoke-static {v2, p0, v0}, Lkx/a;->l(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
