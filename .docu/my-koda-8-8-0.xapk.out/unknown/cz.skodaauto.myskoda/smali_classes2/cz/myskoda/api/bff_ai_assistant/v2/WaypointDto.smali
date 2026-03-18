.class public final Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008<\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u00a3\u0001\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0007\u0012\u0008\u0008\u0001\u0010\u0008\u001a\u00020\t\u0012\u0008\u0008\u0001\u0010\n\u001a\u00020\u0007\u0012\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u000c\u0012\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u000e\u0012\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u0010\u0012\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u0010\u0012\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u0010\u0012\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u0010\u0012\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\u0010\u0012\n\u0008\u0003\u0010\u0015\u001a\u0004\u0018\u00010\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\t\u0010>\u001a\u00020\u0003H\u00c6\u0003J\t\u0010?\u001a\u00020\u0003H\u00c6\u0003J\t\u0010@\u001a\u00020\u0003H\u00c6\u0003J\t\u0010A\u001a\u00020\u0007H\u00c6\u0003J\t\u0010B\u001a\u00020\tH\u00c6\u0003J\t\u0010C\u001a\u00020\u0007H\u00c6\u0003J\u000b\u0010D\u001a\u0004\u0018\u00010\u000cH\u00c6\u0003J\u000b\u0010E\u001a\u0004\u0018\u00010\u000eH\u00c6\u0003J\u0010\u0010F\u001a\u0004\u0018\u00010\u0010H\u00c6\u0003\u00a2\u0006\u0002\u00101J\u0010\u0010G\u001a\u0004\u0018\u00010\u0010H\u00c6\u0003\u00a2\u0006\u0002\u00101J\u0010\u0010H\u001a\u0004\u0018\u00010\u0010H\u00c6\u0003\u00a2\u0006\u0002\u00101J\u0010\u0010I\u001a\u0004\u0018\u00010\u0010H\u00c6\u0003\u00a2\u0006\u0002\u00101J\u0010\u0010J\u001a\u0004\u0018\u00010\u0010H\u00c6\u0003\u00a2\u0006\u0002\u00101J\u000b\u0010K\u001a\u0004\u0018\u00010\u0016H\u00c6\u0003J\u00aa\u0001\u0010L\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0003\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0003\u0010\n\u001a\u00020\u00072\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u000c2\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u000e2\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0015\u001a\u0004\u0018\u00010\u0016H\u00c6\u0001\u00a2\u0006\u0002\u0010MJ\u0013\u0010N\u001a\u00020\u00072\u0008\u0010O\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010P\u001a\u00020\u0010H\u00d6\u0001J\t\u0010Q\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0019\u0010\u001a\u001a\u0004\u0008\u001b\u0010\u001cR\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001d\u0010\u001a\u001a\u0004\u0008\u001e\u0010\u001cR\u001c\u0010\u0005\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001f\u0010\u001a\u001a\u0004\u0008 \u0010\u001cR\u001c\u0010\u0006\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008!\u0010\u001a\u001a\u0004\u0008\"\u0010#R\u001c\u0010\u0008\u001a\u00020\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008$\u0010\u001a\u001a\u0004\u0008%\u0010&R\u001c\u0010\n\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\'\u0010\u001a\u001a\u0004\u0008(\u0010#R\u001e\u0010\u000b\u001a\u0004\u0018\u00010\u000c8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008)\u0010\u001a\u001a\u0004\u0008*\u0010+R\u001e\u0010\r\u001a\u0004\u0018\u00010\u000e8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008,\u0010\u001a\u001a\u0004\u0008-\u0010.R \u0010\u000f\u001a\u0004\u0018\u00010\u00108\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u00102\u0012\u0004\u0008/\u0010\u001a\u001a\u0004\u00080\u00101R \u0010\u0011\u001a\u0004\u0018\u00010\u00108\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u00102\u0012\u0004\u00083\u0010\u001a\u001a\u0004\u00084\u00101R \u0010\u0012\u001a\u0004\u0018\u00010\u00108\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u00102\u0012\u0004\u00085\u0010\u001a\u001a\u0004\u00086\u00101R \u0010\u0013\u001a\u0004\u0018\u00010\u00108\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u00102\u0012\u0004\u00087\u0010\u001a\u001a\u0004\u00088\u00101R \u0010\u0014\u001a\u0004\u0018\u00010\u00108\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u00102\u0012\u0004\u00089\u0010\u001a\u001a\u0004\u0008:\u00101R\u001e\u0010\u0015\u001a\u0004\u0018\u00010\u00168\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008;\u0010\u001a\u001a\u0004\u0008<\u0010=\u00a8\u0006R"
    }
    d2 = {
        "Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;",
        "",
        "id",
        "",
        "name",
        "type",
        "aiGenerated",
        "",
        "coordinates",
        "Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;",
        "nextWaypointInWalkingDistance",
        "address",
        "Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;",
        "chargingStation",
        "Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;",
        "distanceToNextWaypointInMeters",
        "",
        "durationToNextWaypointInSeconds",
        "batteryChargeStatusAtArrivalInPercent",
        "batteryChargeStatusAtDepartureInPercent",
        "durationOfChargingInSeconds",
        "placeReview",
        "Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)V",
        "getId$annotations",
        "()V",
        "getId",
        "()Ljava/lang/String;",
        "getName$annotations",
        "getName",
        "getType$annotations",
        "getType",
        "getAiGenerated$annotations",
        "getAiGenerated",
        "()Z",
        "getCoordinates$annotations",
        "getCoordinates",
        "()Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;",
        "getNextWaypointInWalkingDistance$annotations",
        "getNextWaypointInWalkingDistance",
        "getAddress$annotations",
        "getAddress",
        "()Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;",
        "getChargingStation$annotations",
        "getChargingStation",
        "()Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;",
        "getDistanceToNextWaypointInMeters$annotations",
        "getDistanceToNextWaypointInMeters",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "getDurationToNextWaypointInSeconds$annotations",
        "getDurationToNextWaypointInSeconds",
        "getBatteryChargeStatusAtArrivalInPercent$annotations",
        "getBatteryChargeStatusAtArrivalInPercent",
        "getBatteryChargeStatusAtDepartureInPercent$annotations",
        "getBatteryChargeStatusAtDepartureInPercent",
        "getDurationOfChargingInSeconds$annotations",
        "getDurationOfChargingInSeconds",
        "getPlaceReview$annotations",
        "getPlaceReview",
        "()Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "component8",
        "component9",
        "component10",
        "component11",
        "component12",
        "component13",
        "component14",
        "copy",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;",
        "equals",
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
.field private final address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

.field private final aiGenerated:Z

.field private final batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

.field private final batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

.field private final chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

.field private final coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

.field private final distanceToNextWaypointInMeters:Ljava/lang/Integer;

.field private final durationOfChargingInSeconds:Ljava/lang/Integer;

.field private final durationToNextWaypointInSeconds:Ljava/lang/Integer;

.field private final id:Ljava/lang/String;

.field private final name:Ljava/lang/String;

.field private final nextWaypointInWalkingDistance:Z

.field private final placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

.field private final type:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p4    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "aiGenerated"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "coordinates"
        .end annotation
    .end param
    .param p6    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "nextWaypointInWalkingDistance"
        .end annotation
    .end param
    .param p7    # Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "address"
        .end annotation
    .end param
    .param p8    # Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "chargingStation"
        .end annotation
    .end param
    .param p9    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "distanceToNextWaypointInMeters"
        .end annotation
    .end param
    .param p10    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "durationToNextWaypointInSeconds"
        .end annotation
    .end param
    .param p11    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryChargeStatusAtArrivalInPercent"
        .end annotation
    .end param
    .param p12    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryChargeStatusAtDepartureInPercent"
        .end annotation
    .end param
    .param p13    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "durationOfChargingInSeconds"
        .end annotation
    .end param
    .param p14    # Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "placeReview"
        .end annotation
    .end param

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "type"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "coordinates"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 5
    iput-boolean p4, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 7
    iput-boolean p6, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 8
    iput-object p7, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 9
    iput-object p8, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 10
    iput-object p9, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 11
    iput-object p10, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 12
    iput-object p11, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 13
    iput-object p12, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 14
    iput-object p13, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 15
    iput-object p14, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;ILkotlin/jvm/internal/g;)V
    .locals 18

    move/from16 v0, p15

    and-int/lit8 v1, v0, 0x40

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move-object v10, v2

    goto :goto_0

    :cond_0
    move-object/from16 v10, p7

    :goto_0
    and-int/lit16 v1, v0, 0x80

    if-eqz v1, :cond_1

    move-object v11, v2

    goto :goto_1

    :cond_1
    move-object/from16 v11, p8

    :goto_1
    and-int/lit16 v1, v0, 0x100

    if-eqz v1, :cond_2

    move-object v12, v2

    goto :goto_2

    :cond_2
    move-object/from16 v12, p9

    :goto_2
    and-int/lit16 v1, v0, 0x200

    if-eqz v1, :cond_3

    move-object v13, v2

    goto :goto_3

    :cond_3
    move-object/from16 v13, p10

    :goto_3
    and-int/lit16 v1, v0, 0x400

    if-eqz v1, :cond_4

    move-object v14, v2

    goto :goto_4

    :cond_4
    move-object/from16 v14, p11

    :goto_4
    and-int/lit16 v1, v0, 0x800

    if-eqz v1, :cond_5

    move-object v15, v2

    goto :goto_5

    :cond_5
    move-object/from16 v15, p12

    :goto_5
    and-int/lit16 v1, v0, 0x1000

    if-eqz v1, :cond_6

    move-object/from16 v16, v2

    goto :goto_6

    :cond_6
    move-object/from16 v16, p13

    :goto_6
    and-int/lit16 v0, v0, 0x2000

    if-eqz v0, :cond_7

    move-object/from16 v17, v2

    :goto_7
    move-object/from16 v3, p0

    move-object/from16 v4, p1

    move-object/from16 v5, p2

    move-object/from16 v6, p3

    move/from16 v7, p4

    move-object/from16 v8, p5

    move/from16 v9, p6

    goto :goto_8

    :cond_7
    move-object/from16 v17, p14

    goto :goto_7

    .line 16
    :goto_8
    invoke-direct/range {v3 .. v17}, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;
    .locals 14

    .line 1
    move/from16 v0, p15

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v1, p1

    .line 11
    :goto_0
    and-int/lit8 v2, v0, 0x2

    .line 12
    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    move-object/from16 v2, p2

    .line 19
    .line 20
    :goto_1
    and-int/lit8 v3, v0, 0x4

    .line 21
    .line 22
    if-eqz v3, :cond_2

    .line 23
    .line 24
    iget-object v3, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_2
    move-object/from16 v3, p3

    .line 28
    .line 29
    :goto_2
    and-int/lit8 v4, v0, 0x8

    .line 30
    .line 31
    if-eqz v4, :cond_3

    .line 32
    .line 33
    iget-boolean v4, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 34
    .line 35
    goto :goto_3

    .line 36
    :cond_3
    move/from16 v4, p4

    .line 37
    .line 38
    :goto_3
    and-int/lit8 v5, v0, 0x10

    .line 39
    .line 40
    if-eqz v5, :cond_4

    .line 41
    .line 42
    iget-object v5, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 43
    .line 44
    goto :goto_4

    .line 45
    :cond_4
    move-object/from16 v5, p5

    .line 46
    .line 47
    :goto_4
    and-int/lit8 v6, v0, 0x20

    .line 48
    .line 49
    if-eqz v6, :cond_5

    .line 50
    .line 51
    iget-boolean v6, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 52
    .line 53
    goto :goto_5

    .line 54
    :cond_5
    move/from16 v6, p6

    .line 55
    .line 56
    :goto_5
    and-int/lit8 v7, v0, 0x40

    .line 57
    .line 58
    if-eqz v7, :cond_6

    .line 59
    .line 60
    iget-object v7, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 61
    .line 62
    goto :goto_6

    .line 63
    :cond_6
    move-object/from16 v7, p7

    .line 64
    .line 65
    :goto_6
    and-int/lit16 v8, v0, 0x80

    .line 66
    .line 67
    if-eqz v8, :cond_7

    .line 68
    .line 69
    iget-object v8, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 70
    .line 71
    goto :goto_7

    .line 72
    :cond_7
    move-object/from16 v8, p8

    .line 73
    .line 74
    :goto_7
    and-int/lit16 v9, v0, 0x100

    .line 75
    .line 76
    if-eqz v9, :cond_8

    .line 77
    .line 78
    iget-object v9, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 79
    .line 80
    goto :goto_8

    .line 81
    :cond_8
    move-object/from16 v9, p9

    .line 82
    .line 83
    :goto_8
    and-int/lit16 v10, v0, 0x200

    .line 84
    .line 85
    if-eqz v10, :cond_9

    .line 86
    .line 87
    iget-object v10, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 88
    .line 89
    goto :goto_9

    .line 90
    :cond_9
    move-object/from16 v10, p10

    .line 91
    .line 92
    :goto_9
    and-int/lit16 v11, v0, 0x400

    .line 93
    .line 94
    if-eqz v11, :cond_a

    .line 95
    .line 96
    iget-object v11, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 97
    .line 98
    goto :goto_a

    .line 99
    :cond_a
    move-object/from16 v11, p11

    .line 100
    .line 101
    :goto_a
    and-int/lit16 v12, v0, 0x800

    .line 102
    .line 103
    if-eqz v12, :cond_b

    .line 104
    .line 105
    iget-object v12, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 106
    .line 107
    goto :goto_b

    .line 108
    :cond_b
    move-object/from16 v12, p12

    .line 109
    .line 110
    :goto_b
    and-int/lit16 v13, v0, 0x1000

    .line 111
    .line 112
    if-eqz v13, :cond_c

    .line 113
    .line 114
    iget-object v13, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 115
    .line 116
    goto :goto_c

    .line 117
    :cond_c
    move-object/from16 v13, p13

    .line 118
    .line 119
    :goto_c
    and-int/lit16 v0, v0, 0x2000

    .line 120
    .line 121
    if-eqz v0, :cond_d

    .line 122
    .line 123
    iget-object v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 124
    .line 125
    move-object/from16 p15, v0

    .line 126
    .line 127
    :goto_d
    move-object p1, p0

    .line 128
    move-object/from16 p2, v1

    .line 129
    .line 130
    move-object/from16 p3, v2

    .line 131
    .line 132
    move-object/from16 p4, v3

    .line 133
    .line 134
    move/from16 p5, v4

    .line 135
    .line 136
    move-object/from16 p6, v5

    .line 137
    .line 138
    move/from16 p7, v6

    .line 139
    .line 140
    move-object/from16 p8, v7

    .line 141
    .line 142
    move-object/from16 p9, v8

    .line 143
    .line 144
    move-object/from16 p10, v9

    .line 145
    .line 146
    move-object/from16 p11, v10

    .line 147
    .line 148
    move-object/from16 p12, v11

    .line 149
    .line 150
    move-object/from16 p13, v12

    .line 151
    .line 152
    move-object/from16 p14, v13

    .line 153
    .line 154
    goto :goto_e

    .line 155
    :cond_d
    move-object/from16 p15, p14

    .line 156
    .line 157
    goto :goto_d

    .line 158
    :goto_e
    invoke-virtual/range {p1 .. p15}, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    return-object p0
.end method

.method public static synthetic getAddress$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "address"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getAiGenerated$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "aiGenerated"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getBatteryChargeStatusAtArrivalInPercent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "batteryChargeStatusAtArrivalInPercent"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getBatteryChargeStatusAtDepartureInPercent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "batteryChargeStatusAtDepartureInPercent"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getChargingStation$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "chargingStation"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCoordinates$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "coordinates"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getDistanceToNextWaypointInMeters$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "distanceToNextWaypointInMeters"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getDurationOfChargingInSeconds$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "durationOfChargingInSeconds"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getDurationToNextWaypointInSeconds$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "durationToNextWaypointInSeconds"
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

.method public static synthetic getName$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "name"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getNextWaypointInWalkingDistance$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "nextWaypointInWalkingDistance"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPlaceReview$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "placeReview"
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
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component12()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component13()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component14()Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component5()Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component7()Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;
    .locals 16
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p4    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "aiGenerated"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "coordinates"
        .end annotation
    .end param
    .param p6    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "nextWaypointInWalkingDistance"
        .end annotation
    .end param
    .param p7    # Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "address"
        .end annotation
    .end param
    .param p8    # Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "chargingStation"
        .end annotation
    .end param
    .param p9    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "distanceToNextWaypointInMeters"
        .end annotation
    .end param
    .param p10    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "durationToNextWaypointInSeconds"
        .end annotation
    .end param
    .param p11    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryChargeStatusAtArrivalInPercent"
        .end annotation
    .end param
    .param p12    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryChargeStatusAtDepartureInPercent"
        .end annotation
    .end param
    .param p13    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "durationOfChargingInSeconds"
        .end annotation
    .end param
    .param p14    # Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "placeReview"
        .end annotation
    .end param

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "name"

    .line 9
    .line 10
    move-object/from16 v3, p2

    .line 11
    .line 12
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "type"

    .line 16
    .line 17
    move-object/from16 v4, p3

    .line 18
    .line 19
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "coordinates"

    .line 23
    .line 24
    move-object/from16 v6, p5

    .line 25
    .line 26
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;

    .line 30
    .line 31
    move/from16 v5, p4

    .line 32
    .line 33
    move/from16 v7, p6

    .line 34
    .line 35
    move-object/from16 v8, p7

    .line 36
    .line 37
    move-object/from16 v9, p8

    .line 38
    .line 39
    move-object/from16 v10, p9

    .line 40
    .line 41
    move-object/from16 v11, p10

    .line 42
    .line 43
    move-object/from16 v12, p11

    .line 44
    .line 45
    move-object/from16 v13, p12

    .line 46
    .line 47
    move-object/from16 v14, p13

    .line 48
    .line 49
    move-object/from16 v15, p14

    .line 50
    .line 51
    invoke-direct/range {v1 .. v15}, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;ZLcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;)V

    .line 52
    .line 53
    .line 54
    return-object v1
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
    instance-of v1, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;

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
    check-cast p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

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
    iget-boolean v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 47
    .line 48
    iget-boolean v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 49
    .line 50
    if-eq v1, v3, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 54
    .line 55
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-boolean v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 65
    .line 66
    iget-boolean v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 67
    .line 68
    if-eq v1, v3, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 72
    .line 73
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 74
    .line 75
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-nez v1, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 83
    .line 84
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 85
    .line 86
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-nez v1, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 94
    .line 95
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 96
    .line 97
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 105
    .line 106
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 107
    .line 108
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_b

    .line 113
    .line 114
    return v2

    .line 115
    :cond_b
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 116
    .line 117
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 118
    .line 119
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    if-nez v1, :cond_c

    .line 124
    .line 125
    return v2

    .line 126
    :cond_c
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 127
    .line 128
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 129
    .line 130
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-nez v1, :cond_d

    .line 135
    .line 136
    return v2

    .line 137
    :cond_d
    iget-object v1, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 138
    .line 139
    iget-object v3, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 140
    .line 141
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    if-nez v1, :cond_e

    .line 146
    .line 147
    return v2

    .line 148
    :cond_e
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 149
    .line 150
    iget-object p1, p1, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 151
    .line 152
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result p0

    .line 156
    if-nez p0, :cond_f

    .line 157
    .line 158
    return v2

    .line 159
    :cond_f
    return v0
.end method

.method public final getAddress()Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAiGenerated()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getBatteryChargeStatusAtArrivalInPercent()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getBatteryChargeStatusAtDepartureInPercent()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getChargingStation()Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCoordinates()Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDistanceToNextWaypointInMeters()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDurationOfChargingInSeconds()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDurationToNextWaypointInSeconds()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNextWaypointInWalkingDistance()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getPlaceReview()Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

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
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 29
    .line 30
    invoke-virtual {v2}, Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    add-int/2addr v2, v0

    .line 35
    mul-int/2addr v2, v1

    .line 36
    iget-boolean v0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 37
    .line 38
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    if-nez v2, :cond_0

    .line 46
    .line 47
    move v2, v3

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {v2}, Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    :goto_0
    add-int/2addr v0, v2

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 56
    .line 57
    if-nez v2, :cond_1

    .line 58
    .line 59
    move v2, v3

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {v2}, Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    :goto_1
    add-int/2addr v0, v2

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 68
    .line 69
    if-nez v2, :cond_2

    .line 70
    .line 71
    move v2, v3

    .line 72
    goto :goto_2

    .line 73
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    :goto_2
    add-int/2addr v0, v2

    .line 78
    mul-int/2addr v0, v1

    .line 79
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 80
    .line 81
    if-nez v2, :cond_3

    .line 82
    .line 83
    move v2, v3

    .line 84
    goto :goto_3

    .line 85
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    :goto_3
    add-int/2addr v0, v2

    .line 90
    mul-int/2addr v0, v1

    .line 91
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 92
    .line 93
    if-nez v2, :cond_4

    .line 94
    .line 95
    move v2, v3

    .line 96
    goto :goto_4

    .line 97
    :cond_4
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    :goto_4
    add-int/2addr v0, v2

    .line 102
    mul-int/2addr v0, v1

    .line 103
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 104
    .line 105
    if-nez v2, :cond_5

    .line 106
    .line 107
    move v2, v3

    .line 108
    goto :goto_5

    .line 109
    :cond_5
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    :goto_5
    add-int/2addr v0, v2

    .line 114
    mul-int/2addr v0, v1

    .line 115
    iget-object v2, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 116
    .line 117
    if-nez v2, :cond_6

    .line 118
    .line 119
    move v2, v3

    .line 120
    goto :goto_6

    .line 121
    :cond_6
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    :goto_6
    add-int/2addr v0, v2

    .line 126
    mul-int/2addr v0, v1

    .line 127
    iget-object p0, p0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 128
    .line 129
    if-nez p0, :cond_7

    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_7
    invoke-virtual {p0}, Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;->hashCode()I

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    :goto_7
    add-int/2addr v0, v3

    .line 137
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->id:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->name:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->type:Ljava/lang/String;

    .line 8
    .line 9
    iget-boolean v4, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->aiGenerated:Z

    .line 10
    .line 11
    iget-object v5, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->coordinates:Lcz/myskoda/api/bff_ai_assistant/v2/GpsCoordinatesDto;

    .line 12
    .line 13
    iget-boolean v6, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->nextWaypointInWalkingDistance:Z

    .line 14
    .line 15
    iget-object v7, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->address:Lcz/myskoda/api/bff_ai_assistant/v2/MapPositionAddressDto;

    .line 16
    .line 17
    iget-object v8, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->chargingStation:Lcz/myskoda/api/bff_ai_assistant/v2/ChargingStationDto;

    .line 18
    .line 19
    iget-object v9, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->distanceToNextWaypointInMeters:Ljava/lang/Integer;

    .line 20
    .line 21
    iget-object v10, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationToNextWaypointInSeconds:Ljava/lang/Integer;

    .line 22
    .line 23
    iget-object v11, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtArrivalInPercent:Ljava/lang/Integer;

    .line 24
    .line 25
    iget-object v12, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->batteryChargeStatusAtDepartureInPercent:Ljava/lang/Integer;

    .line 26
    .line 27
    iget-object v13, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->durationOfChargingInSeconds:Ljava/lang/Integer;

    .line 28
    .line 29
    iget-object v0, v0, Lcz/myskoda/api/bff_ai_assistant/v2/WaypointDto;->placeReview:Lcz/myskoda/api/bff_ai_assistant/v2/PlaceReviewDto;

    .line 30
    .line 31
    const-string v14, ", name="

    .line 32
    .line 33
    const-string v15, ", type="

    .line 34
    .line 35
    move-object/from16 p0, v0

    .line 36
    .line 37
    const-string v0, "WaypointDto(id="

    .line 38
    .line 39
    invoke-static {v0, v1, v14, v2, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    const-string v1, ", aiGenerated="

    .line 44
    .line 45
    const-string v2, ", coordinates="

    .line 46
    .line 47
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", nextWaypointInWalkingDistance="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", address="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v1, ", chargingStation="

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ", distanceToNextWaypointInMeters="

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v1, ", durationToNextWaypointInSeconds="

    .line 83
    .line 84
    const-string v2, ", batteryChargeStatusAtArrivalInPercent="

    .line 85
    .line 86
    invoke-static {v0, v9, v1, v10, v2}, Lia/b;->t(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string v1, ", batteryChargeStatusAtDepartureInPercent="

    .line 90
    .line 91
    const-string v2, ", durationOfChargingInSeconds="

    .line 92
    .line 93
    invoke-static {v0, v11, v1, v12, v2}, Lia/b;->t(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v1, ", placeReview="

    .line 100
    .line 101
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    move-object/from16 v1, p0

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v1, ")"

    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    return-object v0
.end method
