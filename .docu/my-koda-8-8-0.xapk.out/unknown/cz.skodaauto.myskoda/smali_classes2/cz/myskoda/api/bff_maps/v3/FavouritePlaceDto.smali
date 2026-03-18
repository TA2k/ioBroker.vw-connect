.class public final Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0014\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B3\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0017\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u0005H\u00c6\u0003J\u000b\u0010\u0019\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u001a\u001a\u0004\u0018\u00010\u0008H\u00c6\u0003J5\u0010\u001b\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008H\u00c6\u0001J\u0013\u0010\u001c\u001a\u00020\u001d2\u0008\u0010\u001e\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001f\u001a\u00020 H\u00d6\u0001J\t\u0010!\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R\u001e\u0010\u0006\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u000eR\u001e\u0010\u0007\u001a\u0004\u0018\u00010\u00088\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0014\u0010\u000c\u001a\u0004\u0008\u0015\u0010\u0016\u00a8\u0006\""
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;",
        "",
        "type",
        "",
        "placeDetail",
        "Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;",
        "id",
        "travelData",
        "Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;",
        "<init>",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)V",
        "getType$annotations",
        "()V",
        "getType",
        "()Ljava/lang/String;",
        "getPlaceDetail$annotations",
        "getPlaceDetail",
        "()Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;",
        "getId$annotations",
        "getId",
        "getTravelData$annotations",
        "getTravelData",
        "()Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;",
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
.field private final id:Ljava/lang/String;

.field private final placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

.field private final travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

.field private final type:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "placeDetail"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "travelData"
        .end annotation
    .end param

    const-string v0, "type"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "placeDetail"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x4

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move-object p3, v0

    :cond_0
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_1

    move-object p4, v0

    .line 6
    :cond_1
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->copy(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
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

.method public static synthetic getPlaceDetail$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "placeDetail"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTravelData$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "travelData"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "type"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "placeDetail"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "travelData"
        .end annotation
    .end param

    .line 1
    const-string p0, "type"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "placeDetail"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;)V

    .line 14
    .line 15
    .line 16
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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 47
    .line 48
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

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

.method public final getId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPlaceDetail()Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTravelData()Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;->hashCode()I

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
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    move v0, v2

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    :goto_0
    add-int/2addr v1, v0

    .line 30
    mul-int/lit8 v1, v1, 0x1f

    .line 31
    .line 32
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 33
    .line 34
    if-nez p0, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    :goto_1
    add-int/2addr v1, v2

    .line 42
    return v1
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->placeDetail:Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDetailDto;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->id:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/FavouritePlaceDto;->travelData:Lcz/myskoda/api/bff_maps/v3/MapPlaceTravelDataDto;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "FavouritePlaceDto(type="

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
    const-string v0, ", placeDetail="

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
    const-string v0, ", id="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", travelData="

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
