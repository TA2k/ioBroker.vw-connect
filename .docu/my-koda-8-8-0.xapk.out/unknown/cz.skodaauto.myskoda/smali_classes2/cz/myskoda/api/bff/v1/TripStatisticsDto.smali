.class public final Lcz/myskoda/api/bff/v1/TripStatisticsDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u0004\n\u0002\u0010\u0006\n\u0002\u0008\u0004\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008.\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u008f\u0001\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\n\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u000c\u0012\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u000c\u0012\n\u0008\u0003\u0010\u000e\u001a\u0004\u0018\u00010\u000c\u0012\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u0007\u0012\u0010\u0008\u0003\u0010\u0010\u001a\n\u0012\u0004\u0012\u00020\u0012\u0018\u00010\u0011\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J\t\u00103\u001a\u00020\u0003H\u00c6\u0003J\u000b\u00104\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u0010\u00105\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001eJ\u0010\u00106\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001eJ\u0010\u00107\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001eJ\u0010\u00108\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001eJ\u0010\u00109\u001a\u0004\u0018\u00010\u000cH\u00c6\u0003\u00a2\u0006\u0002\u0010(J\u0010\u0010:\u001a\u0004\u0018\u00010\u000cH\u00c6\u0003\u00a2\u0006\u0002\u0010(J\u0010\u0010;\u001a\u0004\u0018\u00010\u000cH\u00c6\u0003\u00a2\u0006\u0002\u0010(J\u0010\u0010<\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u001eJ\u0011\u0010=\u001a\n\u0012\u0004\u0012\u00020\u0012\u0018\u00010\u0011H\u00c6\u0003J\u0096\u0001\u0010>\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\n\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u000c2\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u000c2\n\u0008\u0003\u0010\u000e\u001a\u0004\u0018\u00010\u000c2\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u00072\u0010\u0008\u0003\u0010\u0010\u001a\n\u0012\u0004\u0012\u00020\u0012\u0018\u00010\u0011H\u00c6\u0001\u00a2\u0006\u0002\u0010?J\u0013\u0010@\u001a\u00020A2\u0008\u0010B\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010C\u001a\u00020DH\u00d6\u0001J\t\u0010E\u001a\u00020FH\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0015\u0010\u0016\u001a\u0004\u0008\u0017\u0010\u0018R\u001e\u0010\u0004\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0019\u0010\u0016\u001a\u0004\u0008\u001a\u0010\u001bR \u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u001f\u0012\u0004\u0008\u001c\u0010\u0016\u001a\u0004\u0008\u001d\u0010\u001eR \u0010\u0008\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u001f\u0012\u0004\u0008 \u0010\u0016\u001a\u0004\u0008!\u0010\u001eR \u0010\t\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u001f\u0012\u0004\u0008\"\u0010\u0016\u001a\u0004\u0008#\u0010\u001eR \u0010\n\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u001f\u0012\u0004\u0008$\u0010\u0016\u001a\u0004\u0008%\u0010\u001eR \u0010\u000b\u001a\u0004\u0018\u00010\u000c8\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010)\u0012\u0004\u0008&\u0010\u0016\u001a\u0004\u0008\'\u0010(R \u0010\r\u001a\u0004\u0018\u00010\u000c8\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010)\u0012\u0004\u0008*\u0010\u0016\u001a\u0004\u0008+\u0010(R \u0010\u000e\u001a\u0004\u0018\u00010\u000c8\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010)\u0012\u0004\u0008,\u0010\u0016\u001a\u0004\u0008-\u0010(R \u0010\u000f\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u001f\u0012\u0004\u0008.\u0010\u0016\u001a\u0004\u0008/\u0010\u001eR$\u0010\u0010\u001a\n\u0012\u0004\u0012\u00020\u0012\u0018\u00010\u00118\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u00080\u0010\u0016\u001a\u0004\u00081\u00102\u00a8\u0006G"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/TripStatisticsDto;",
        "",
        "vehicleType",
        "Lcz/myskoda/api/bff/v1/VehicleTypeDto;",
        "overallCost",
        "Lcz/myskoda/api/bff/v1/FuelCostDto;",
        "overallMileageInKm",
        "",
        "overallTravelTimeInMin",
        "overallAverageMileageInKm",
        "overallAverageTravelTimeInMin",
        "overallAverageFuelConsumption",
        "",
        "overallAverageElectricConsumption",
        "overallAverageGasConsumption",
        "overallAverageSpeedInKmph",
        "detailedStatistics",
        "",
        "Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;",
        "<init>",
        "(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)V",
        "getVehicleType$annotations",
        "()V",
        "getVehicleType",
        "()Lcz/myskoda/api/bff/v1/VehicleTypeDto;",
        "getOverallCost$annotations",
        "getOverallCost",
        "()Lcz/myskoda/api/bff/v1/FuelCostDto;",
        "getOverallMileageInKm$annotations",
        "getOverallMileageInKm",
        "()Ljava/lang/Long;",
        "Ljava/lang/Long;",
        "getOverallTravelTimeInMin$annotations",
        "getOverallTravelTimeInMin",
        "getOverallAverageMileageInKm$annotations",
        "getOverallAverageMileageInKm",
        "getOverallAverageTravelTimeInMin$annotations",
        "getOverallAverageTravelTimeInMin",
        "getOverallAverageFuelConsumption$annotations",
        "getOverallAverageFuelConsumption",
        "()Ljava/lang/Double;",
        "Ljava/lang/Double;",
        "getOverallAverageElectricConsumption$annotations",
        "getOverallAverageElectricConsumption",
        "getOverallAverageGasConsumption$annotations",
        "getOverallAverageGasConsumption",
        "getOverallAverageSpeedInKmph$annotations",
        "getOverallAverageSpeedInKmph",
        "getDetailedStatistics$annotations",
        "getDetailedStatistics",
        "()Ljava/util/List;",
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
        "copy",
        "(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)Lcz/myskoda/api/bff/v1/TripStatisticsDto;",
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
.field private final detailedStatistics:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;",
            ">;"
        }
    .end annotation
.end field

.field private final overallAverageElectricConsumption:Ljava/lang/Double;

.field private final overallAverageFuelConsumption:Ljava/lang/Double;

.field private final overallAverageGasConsumption:Ljava/lang/Double;

.field private final overallAverageMileageInKm:Ljava/lang/Long;

.field private final overallAverageSpeedInKmph:Ljava/lang/Long;

.field private final overallAverageTravelTimeInMin:Ljava/lang/Long;

.field private final overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

.field private final overallMileageInKm:Ljava/lang/Long;

.field private final overallTravelTimeInMin:Ljava/lang/Long;

.field private final vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;


# direct methods
.method public constructor <init>(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)V
    .locals 1
    .param p1    # Lcz/myskoda/api/bff/v1/VehicleTypeDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehicleType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/FuelCostDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallCost"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallMileageInKm"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallTravelTimeInMin"
        .end annotation
    .end param
    .param p5    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageMileageInKm"
        .end annotation
    .end param
    .param p6    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageTravelTimeInMin"
        .end annotation
    .end param
    .param p7    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageFuelConsumption"
        .end annotation
    .end param
    .param p8    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageElectricConsumption"
        .end annotation
    .end param
    .param p9    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageGasConsumption"
        .end annotation
    .end param
    .param p10    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageSpeedInKmph"
        .end annotation
    .end param
    .param p11    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "detailedStatistics"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/VehicleTypeDto;",
            "Lcz/myskoda/api/bff/v1/FuelCostDto;",
            "Ljava/lang/Long;",
            "Ljava/lang/Long;",
            "Ljava/lang/Long;",
            "Ljava/lang/Long;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/lang/Long;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;",
            ">;)V"
        }
    .end annotation

    const-string v0, "vehicleType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 7
    iput-object p6, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 8
    iput-object p7, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 9
    iput-object p8, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 10
    iput-object p9, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 11
    iput-object p10, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 12
    iput-object p11, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    return-void
.end method

.method public synthetic constructor <init>(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p13, p12, 0x2

    const/4 v0, 0x0

    if-eqz p13, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p13, p12, 0x4

    if-eqz p13, :cond_1

    move-object p3, v0

    :cond_1
    and-int/lit8 p13, p12, 0x8

    if-eqz p13, :cond_2

    move-object p4, v0

    :cond_2
    and-int/lit8 p13, p12, 0x10

    if-eqz p13, :cond_3

    move-object p5, v0

    :cond_3
    and-int/lit8 p13, p12, 0x20

    if-eqz p13, :cond_4

    move-object p6, v0

    :cond_4
    and-int/lit8 p13, p12, 0x40

    if-eqz p13, :cond_5

    move-object p7, v0

    :cond_5
    and-int/lit16 p13, p12, 0x80

    if-eqz p13, :cond_6

    move-object p8, v0

    :cond_6
    and-int/lit16 p13, p12, 0x100

    if-eqz p13, :cond_7

    move-object p9, v0

    :cond_7
    and-int/lit16 p13, p12, 0x200

    if-eqz p13, :cond_8

    move-object p10, v0

    :cond_8
    and-int/lit16 p12, p12, 0x400

    if-eqz p12, :cond_9

    move-object p11, v0

    .line 13
    :cond_9
    invoke-direct/range {p0 .. p11}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;-><init>(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/TripStatisticsDto;Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/TripStatisticsDto;
    .locals 0

    .line 1
    and-int/lit8 p13, p12, 0x1

    .line 2
    .line 3
    if-eqz p13, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p13, p12, 0x2

    .line 8
    .line 9
    if-eqz p13, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p13, p12, 0x4

    .line 14
    .line 15
    if-eqz p13, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p13, p12, 0x8

    .line 20
    .line 21
    if-eqz p13, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p13, p12, 0x10

    .line 26
    .line 27
    if-eqz p13, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p13, p12, 0x20

    .line 32
    .line 33
    if-eqz p13, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p13, p12, 0x40

    .line 38
    .line 39
    if-eqz p13, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p13, p12, 0x80

    .line 44
    .line 45
    if-eqz p13, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p13, p12, 0x100

    .line 50
    .line 51
    if-eqz p13, :cond_8

    .line 52
    .line 53
    iget-object p9, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p13, p12, 0x200

    .line 56
    .line 57
    if-eqz p13, :cond_9

    .line 58
    .line 59
    iget-object p10, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 60
    .line 61
    :cond_9
    and-int/lit16 p12, p12, 0x400

    .line 62
    .line 63
    if-eqz p12, :cond_a

    .line 64
    .line 65
    iget-object p11, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 66
    .line 67
    :cond_a
    move-object p12, p10

    .line 68
    move-object p13, p11

    .line 69
    move-object p10, p8

    .line 70
    move-object p11, p9

    .line 71
    move-object p8, p6

    .line 72
    move-object p9, p7

    .line 73
    move-object p6, p4

    .line 74
    move-object p7, p5

    .line 75
    move-object p4, p2

    .line 76
    move-object p5, p3

    .line 77
    move-object p2, p0

    .line 78
    move-object p3, p1

    .line 79
    invoke-virtual/range {p2 .. p13}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->copy(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)Lcz/myskoda/api/bff/v1/TripStatisticsDto;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method

.method public static synthetic getDetailedStatistics$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "detailedStatistics"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallAverageElectricConsumption$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallAverageElectricConsumption"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallAverageFuelConsumption$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallAverageFuelConsumption"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallAverageGasConsumption$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallAverageGasConsumption"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallAverageMileageInKm$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallAverageMileageInKm"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallAverageSpeedInKmph$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallAverageSpeedInKmph"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallAverageTravelTimeInMin$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallAverageTravelTimeInMin"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallCost$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallCost"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallMileageInKm$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallMileageInKm"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallTravelTimeInMin$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallTravelTimeInMin"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVehicleType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vehicleType"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component11()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/bff/v1/FuelCostDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)Lcz/myskoda/api/bff/v1/TripStatisticsDto;
    .locals 12
    .param p1    # Lcz/myskoda/api/bff/v1/VehicleTypeDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehicleType"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/FuelCostDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallCost"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallMileageInKm"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallTravelTimeInMin"
        .end annotation
    .end param
    .param p5    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageMileageInKm"
        .end annotation
    .end param
    .param p6    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageTravelTimeInMin"
        .end annotation
    .end param
    .param p7    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageFuelConsumption"
        .end annotation
    .end param
    .param p8    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageElectricConsumption"
        .end annotation
    .end param
    .param p9    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageGasConsumption"
        .end annotation
    .end param
    .param p10    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallAverageSpeedInKmph"
        .end annotation
    .end param
    .param p11    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "detailedStatistics"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/VehicleTypeDto;",
            "Lcz/myskoda/api/bff/v1/FuelCostDto;",
            "Ljava/lang/Long;",
            "Ljava/lang/Long;",
            "Ljava/lang/Long;",
            "Ljava/lang/Long;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/lang/Long;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;",
            ">;)",
            "Lcz/myskoda/api/bff/v1/TripStatisticsDto;"
        }
    .end annotation

    .line 1
    const-string p0, "vehicleType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;

    .line 7
    .line 8
    move-object v1, p1

    .line 9
    move-object v2, p2

    .line 10
    move-object v3, p3

    .line 11
    move-object/from16 v4, p4

    .line 12
    .line 13
    move-object/from16 v5, p5

    .line 14
    .line 15
    move-object/from16 v6, p6

    .line 16
    .line 17
    move-object/from16 v7, p7

    .line 18
    .line 19
    move-object/from16 v8, p8

    .line 20
    .line 21
    move-object/from16 v9, p9

    .line 22
    .line 23
    move-object/from16 v10, p10

    .line 24
    .line 25
    move-object/from16 v11, p11

    .line 26
    .line 27
    invoke-direct/range {v0 .. v11}, Lcz/myskoda/api/bff/v1/TripStatisticsDto;-><init>(Lcz/myskoda/api/bff/v1/VehicleTypeDto;Lcz/myskoda/api/bff/v1/FuelCostDto;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Long;Ljava/util/List;)V

    .line 28
    .line 29
    .line 30
    return-object v0
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 21
    .line 22
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 32
    .line 33
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 43
    .line 44
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 54
    .line 55
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 65
    .line 66
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 76
    .line 77
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 87
    .line 88
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 89
    .line 90
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 98
    .line 99
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 100
    .line 101
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-nez v1, :cond_a

    .line 106
    .line 107
    return v2

    .line 108
    :cond_a
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 109
    .line 110
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 111
    .line 112
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-nez v1, :cond_b

    .line 117
    .line 118
    return v2

    .line 119
    :cond_b
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 120
    .line 121
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 122
    .line 123
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-nez p0, :cond_c

    .line 128
    .line 129
    return v2

    .line 130
    :cond_c
    return v0
.end method

.method public final getDetailedStatistics()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/AggregatedTripStatisticsDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallAverageElectricConsumption()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallAverageFuelConsumption()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallAverageGasConsumption()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallAverageMileageInKm()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallAverageSpeedInKmph()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallAverageTravelTimeInMin()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallCost()Lcz/myskoda/api/bff/v1/FuelCostDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallMileageInKm()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallTravelTimeInMin()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicleType()Lcz/myskoda/api/bff/v1/VehicleTypeDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

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
    invoke-virtual {v1}, Lcz/myskoda/api/bff/v1/FuelCostDto;->hashCode()I

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 37
    .line 38
    if-nez v1, :cond_2

    .line 39
    .line 40
    move v1, v2

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    :goto_2
    add-int/2addr v0, v1

    .line 47
    mul-int/lit8 v0, v0, 0x1f

    .line 48
    .line 49
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 50
    .line 51
    if-nez v1, :cond_3

    .line 52
    .line 53
    move v1, v2

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    :goto_3
    add-int/2addr v0, v1

    .line 60
    mul-int/lit8 v0, v0, 0x1f

    .line 61
    .line 62
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 63
    .line 64
    if-nez v1, :cond_4

    .line 65
    .line 66
    move v1, v2

    .line 67
    goto :goto_4

    .line 68
    :cond_4
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    :goto_4
    add-int/2addr v0, v1

    .line 73
    mul-int/lit8 v0, v0, 0x1f

    .line 74
    .line 75
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 76
    .line 77
    if-nez v1, :cond_5

    .line 78
    .line 79
    move v1, v2

    .line 80
    goto :goto_5

    .line 81
    :cond_5
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    :goto_5
    add-int/2addr v0, v1

    .line 86
    mul-int/lit8 v0, v0, 0x1f

    .line 87
    .line 88
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 89
    .line 90
    if-nez v1, :cond_6

    .line 91
    .line 92
    move v1, v2

    .line 93
    goto :goto_6

    .line 94
    :cond_6
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    :goto_6
    add-int/2addr v0, v1

    .line 99
    mul-int/lit8 v0, v0, 0x1f

    .line 100
    .line 101
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 102
    .line 103
    if-nez v1, :cond_7

    .line 104
    .line 105
    move v1, v2

    .line 106
    goto :goto_7

    .line 107
    :cond_7
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    :goto_7
    add-int/2addr v0, v1

    .line 112
    mul-int/lit8 v0, v0, 0x1f

    .line 113
    .line 114
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 115
    .line 116
    if-nez v1, :cond_8

    .line 117
    .line 118
    move v1, v2

    .line 119
    goto :goto_8

    .line 120
    :cond_8
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    :goto_8
    add-int/2addr v0, v1

    .line 125
    mul-int/lit8 v0, v0, 0x1f

    .line 126
    .line 127
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 128
    .line 129
    if-nez p0, :cond_9

    .line 130
    .line 131
    goto :goto_9

    .line 132
    :cond_9
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    :goto_9
    add-int/2addr v0, v2

    .line 137
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 12

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->vehicleType:Lcz/myskoda/api/bff/v1/VehicleTypeDto;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallMileageInKm:Ljava/lang/Long;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallTravelTimeInMin:Ljava/lang/Long;

    .line 8
    .line 9
    iget-object v4, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageMileageInKm:Ljava/lang/Long;

    .line 10
    .line 11
    iget-object v5, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageTravelTimeInMin:Ljava/lang/Long;

    .line 12
    .line 13
    iget-object v6, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageFuelConsumption:Ljava/lang/Double;

    .line 14
    .line 15
    iget-object v7, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageElectricConsumption:Ljava/lang/Double;

    .line 16
    .line 17
    iget-object v8, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageGasConsumption:Ljava/lang/Double;

    .line 18
    .line 19
    iget-object v9, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->overallAverageSpeedInKmph:Ljava/lang/Long;

    .line 20
    .line 21
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/TripStatisticsDto;->detailedStatistics:Ljava/util/List;

    .line 22
    .line 23
    new-instance v10, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v11, "TripStatisticsDto(vehicleType="

    .line 26
    .line 27
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v0, ", overallCost="

    .line 34
    .line 35
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v10, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v0, ", overallMileageInKm="

    .line 42
    .line 43
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v10, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v0, ", overallTravelTimeInMin="

    .line 50
    .line 51
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v0, ", overallAverageMileageInKm="

    .line 58
    .line 59
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string v0, ", overallAverageTravelTimeInMin="

    .line 66
    .line 67
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v10, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v0, ", overallAverageFuelConsumption="

    .line 74
    .line 75
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v0, ", overallAverageElectricConsumption="

    .line 82
    .line 83
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v10, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v0, ", overallAverageGasConsumption="

    .line 90
    .line 91
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v0, ", overallAverageSpeedInKmph="

    .line 98
    .line 99
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v0, ", detailedStatistics="

    .line 106
    .line 107
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    const-string v0, ")"

    .line 111
    .line 112
    invoke-static {v10, p0, v0}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    return-object p0
.end method
