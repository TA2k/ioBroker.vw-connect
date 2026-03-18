.class public final Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0015\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B1\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0007\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0017\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u0019\u001a\u00020\u0007H\u00c6\u0003J\u000b\u0010\u001a\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J3\u0010\u001b\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00072\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0007H\u00c6\u0001J\u0013\u0010\u001c\u001a\u00020\u001d2\u0008\u0010\u001e\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001f\u001a\u00020 H\u00d6\u0001J\t\u0010!\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R\u001c\u0010\u0006\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u0014R\u001e\u0010\u0008\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0015\u0010\u000c\u001a\u0004\u0008\u0016\u0010\u0014\u00a8\u0006\""
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;",
        "",
        "placeType",
        "",
        "requirements",
        "Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;",
        "location",
        "Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;",
        "currentLocation",
        "<init>",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;)V",
        "getPlaceType$annotations",
        "()V",
        "getPlaceType",
        "()Ljava/lang/String;",
        "getRequirements$annotations",
        "getRequirements",
        "()Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;",
        "getLocation$annotations",
        "getLocation",
        "()Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;",
        "getCurrentLocation$annotations",
        "getCurrentLocation",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
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
.field private final currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

.field private final location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

.field private final placeType:Ljava/lang/String;

.field private final requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "placeType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "requirements"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "location"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currentLocation"
        .end annotation
    .end param

    const-string v0, "placeType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "requirements"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->copy(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;)Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getCurrentLocation$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "currentLocation"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLocation$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "location"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPlaceType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "placeType"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getRequirements$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "requirements"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;)Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "placeType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "requirements"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "location"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currentLocation"
        .end annotation
    .end param

    .line 1
    const-string p0, "placeType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "requirements"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "location"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;)V

    .line 19
    .line 20
    .line 21
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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 47
    .line 48
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

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

.method public final getCurrentLocation()Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLocation()Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPlaceType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRequirements()Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;->hashCode()I

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
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 19
    .line 20
    invoke-virtual {v0}, Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v1

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 28
    .line 29
    if-nez p0, :cond_0

    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    :goto_0
    add-int/2addr v0, p0

    .line 38
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->placeType:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->requirements:Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequirementsDto;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->location:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;->currentLocation:Lcz/myskoda/api/bff_maps/v2/GpsCoordinatesDto;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "NearbyPlacesRequestDto(placeType="

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
    const-string v0, ", requirements="

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
    const-string v0, ", location="

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
    const-string v0, ", currentLocation="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

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
