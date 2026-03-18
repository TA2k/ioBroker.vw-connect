.class public final Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008)\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001Bw\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\t\u0012\n\u0008\u0003\u0010\n\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u000c\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\t\u0010\'\u001a\u00020\u0003H\u00c6\u0003J\t\u0010(\u001a\u00020\u0003H\u00c6\u0003J\t\u0010)\u001a\u00020\u0003H\u00c6\u0003J\t\u0010*\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010+\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010,\u001a\u0004\u0018\u00010\tH\u00c6\u0003J\u000b\u0010-\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010.\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010/\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u00100\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003Jy\u00101\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00032\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\t2\n\u0008\u0003\u0010\n\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u000c\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001J\u0013\u00102\u001a\u0002032\u0008\u00104\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u00105\u001a\u000206H\u00d6\u0001J\t\u00107\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\u0011\u001a\u0004\u0008\u0012\u0010\u0013R\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0014\u0010\u0011\u001a\u0004\u0008\u0015\u0010\u0013R\u001c\u0010\u0005\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0016\u0010\u0011\u001a\u0004\u0008\u0017\u0010\u0013R\u001c\u0010\u0006\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0018\u0010\u0011\u001a\u0004\u0008\u0019\u0010\u0013R\u001e\u0010\u0007\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001a\u0010\u0011\u001a\u0004\u0008\u001b\u0010\u0013R\u001e\u0010\u0008\u001a\u0004\u0018\u00010\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001c\u0010\u0011\u001a\u0004\u0008\u001d\u0010\u001eR\u001e\u0010\n\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001f\u0010\u0011\u001a\u0004\u0008 \u0010\u0013R\u001e\u0010\u000b\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008!\u0010\u0011\u001a\u0004\u0008\"\u0010\u0013R\u001e\u0010\u000c\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008#\u0010\u0011\u001a\u0004\u0008$\u0010\u0013R\u001e\u0010\r\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008%\u0010\u0011\u001a\u0004\u0008&\u0010\u0013\u00a8\u00068"
    }
    d2 = {
        "Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;",
        "",
        "locationId",
        "",
        "pumpId",
        "paymentType",
        "countryCode",
        "currencyCode",
        "fuel",
        "Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;",
        "licensePlate",
        "cardId",
        "vehicleId",
        "vin",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "getLocationId$annotations",
        "()V",
        "getLocationId",
        "()Ljava/lang/String;",
        "getPumpId$annotations",
        "getPumpId",
        "getPaymentType$annotations",
        "getPaymentType",
        "getCountryCode$annotations",
        "getCountryCode",
        "getCurrencyCode$annotations",
        "getCurrencyCode",
        "getFuel$annotations",
        "getFuel",
        "()Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;",
        "getLicensePlate$annotations",
        "getLicensePlate",
        "getCardId$annotations",
        "getCardId",
        "getVehicleId$annotations",
        "getVehicleId",
        "getVin$annotations",
        "getVin",
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
.field private final cardId:Ljava/lang/String;

.field private final countryCode:Ljava/lang/String;

.field private final currencyCode:Ljava/lang/String;

.field private final fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

.field private final licensePlate:Ljava/lang/String;

.field private final locationId:Ljava/lang/String;

.field private final paymentType:Ljava/lang/String;

.field private final pumpId:Ljava/lang/String;

.field private final vehicleId:Ljava/lang/String;

.field private final vin:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "locationId"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pumpId"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "paymentType"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "countryCode"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currencyCode"
        .end annotation
    .end param
    .param p6    # Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "fuel"
        .end annotation
    .end param
    .param p7    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "licensePlate"
        .end annotation
    .end param
    .param p8    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "cardId"
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehicleId"
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vin"
        .end annotation
    .end param

    const-string v0, "locationId"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "pumpId"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "paymentType"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "countryCode"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 7
    iput-object p6, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 8
    iput-object p7, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 9
    iput-object p8, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 10
    iput-object p9, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 11
    iput-object p10, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p12, p11, 0x10

    const/4 v0, 0x0

    if-eqz p12, :cond_0

    move-object p5, v0

    :cond_0
    and-int/lit8 p12, p11, 0x20

    if-eqz p12, :cond_1

    move-object p6, v0

    :cond_1
    and-int/lit8 p12, p11, 0x40

    if-eqz p12, :cond_2

    move-object p7, v0

    :cond_2
    and-int/lit16 p12, p11, 0x80

    if-eqz p12, :cond_3

    move-object p8, v0

    :cond_3
    and-int/lit16 p12, p11, 0x100

    if-eqz p12, :cond_4

    move-object p9, v0

    :cond_4
    and-int/lit16 p11, p11, 0x200

    if-eqz p11, :cond_5

    move-object p10, v0

    .line 12
    :cond_5
    invoke-direct/range {p0 .. p10}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;
    .locals 0

    .line 1
    and-int/lit8 p12, p11, 0x1

    .line 2
    .line 3
    if-eqz p12, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p12, p11, 0x2

    .line 8
    .line 9
    if-eqz p12, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p12, p11, 0x4

    .line 14
    .line 15
    if-eqz p12, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p12, p11, 0x8

    .line 20
    .line 21
    if-eqz p12, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p12, p11, 0x10

    .line 26
    .line 27
    if-eqz p12, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p12, p11, 0x20

    .line 32
    .line 33
    if-eqz p12, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p12, p11, 0x40

    .line 38
    .line 39
    if-eqz p12, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 42
    .line 43
    :cond_6
    and-int/lit16 p12, p11, 0x80

    .line 44
    .line 45
    if-eqz p12, :cond_7

    .line 46
    .line 47
    iget-object p8, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 48
    .line 49
    :cond_7
    and-int/lit16 p12, p11, 0x100

    .line 50
    .line 51
    if-eqz p12, :cond_8

    .line 52
    .line 53
    iget-object p9, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 54
    .line 55
    :cond_8
    and-int/lit16 p11, p11, 0x200

    .line 56
    .line 57
    if-eqz p11, :cond_9

    .line 58
    .line 59
    iget-object p10, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 60
    .line 61
    :cond_9
    move-object p11, p9

    .line 62
    move-object p12, p10

    .line 63
    move-object p9, p7

    .line 64
    move-object p10, p8

    .line 65
    move-object p7, p5

    .line 66
    move-object p8, p6

    .line 67
    move-object p5, p3

    .line 68
    move-object p6, p4

    .line 69
    move-object p3, p1

    .line 70
    move-object p4, p2

    .line 71
    move-object p2, p0

    .line 72
    invoke-virtual/range {p2 .. p12}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public static synthetic getCardId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "cardId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCountryCode$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "countryCode"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCurrencyCode$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "currencyCode"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getFuel$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "fuel"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLicensePlate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "licensePlate"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLocationId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "locationId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPaymentType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "paymentType"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPumpId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "pumpId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVehicleId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vehicleId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVin$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vin"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component8()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component9()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;
    .locals 11
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "locationId"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pumpId"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "paymentType"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "countryCode"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currencyCode"
        .end annotation
    .end param
    .param p6    # Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "fuel"
        .end annotation
    .end param
    .param p7    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "licensePlate"
        .end annotation
    .end param
    .param p8    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "cardId"
        .end annotation
    .end param
    .param p9    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehicleId"
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vin"
        .end annotation
    .end param

    .line 1
    const-string p0, "locationId"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "pumpId"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "paymentType"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "countryCode"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;

    .line 22
    .line 23
    move-object v1, p1

    .line 24
    move-object v2, p2

    .line 25
    move-object v3, p3

    .line 26
    move-object v4, p4

    .line 27
    move-object/from16 v5, p5

    .line 28
    .line 29
    move-object/from16 v6, p6

    .line 30
    .line 31
    move-object/from16 v7, p7

    .line 32
    .line 33
    move-object/from16 v8, p8

    .line 34
    .line 35
    move-object/from16 v9, p9

    .line 36
    .line 37
    move-object/from16 v10, p10

    .line 38
    .line 39
    invoke-direct/range {v0 .. v10}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
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
    instance-of v1, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;

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
    check-cast p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 69
    .line 70
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 80
    .line 81
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v3, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 113
    .line 114
    iget-object p1, p1, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 115
    .line 116
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    if-nez p0, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    return v0
.end method

.method public final getCardId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCountryCode()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCurrencyCode()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFuel()Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLicensePlate()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLocationId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPaymentType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPumpId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicleId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

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
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    if-nez v2, :cond_0

    .line 32
    .line 33
    move v2, v3

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    :goto_0
    add-int/2addr v0, v2

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 42
    .line 43
    if-nez v2, :cond_1

    .line 44
    .line 45
    move v2, v3

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {v2}, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    :goto_1
    add-int/2addr v0, v2

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 54
    .line 55
    if-nez v2, :cond_2

    .line 56
    .line 57
    move v2, v3

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_2
    add-int/2addr v0, v2

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v2, :cond_3

    .line 68
    .line 69
    move v2, v3

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    :goto_3
    add-int/2addr v0, v2

    .line 76
    mul-int/2addr v0, v1

    .line 77
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 78
    .line 79
    if-nez v2, :cond_4

    .line 80
    .line 81
    move v2, v3

    .line 82
    goto :goto_4

    .line 83
    :cond_4
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    :goto_4
    add-int/2addr v0, v2

    .line 88
    mul-int/2addr v0, v1

    .line 89
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 90
    .line 91
    if-nez p0, :cond_5

    .line 92
    .line 93
    goto :goto_5

    .line 94
    :cond_5
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 95
    .line 96
    .line 97
    move-result v3

    .line 98
    :goto_5
    add-int/2addr v0, v3

    .line 99
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 12

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->locationId:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->pumpId:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->paymentType:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->countryCode:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->currencyCode:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->fuel:Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 12
    .line 13
    iget-object v6, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->licensePlate:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v7, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->cardId:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vehicleId:Ljava/lang/String;

    .line 18
    .line 19
    iget-object p0, p0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionRequestDto;->vin:Ljava/lang/String;

    .line 20
    .line 21
    const-string v9, ", pumpId="

    .line 22
    .line 23
    const-string v10, ", paymentType="

    .line 24
    .line 25
    const-string v11, "FuelingSessionRequestDto(locationId="

    .line 26
    .line 27
    invoke-static {v11, v0, v9, v1, v10}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const-string v1, ", countryCode="

    .line 32
    .line 33
    const-string v9, ", currencyCode="

    .line 34
    .line 35
    invoke-static {v0, v2, v1, v3, v9}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", fuel="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v1, ", licensePlate="

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", cardId="

    .line 55
    .line 56
    const-string v2, ", vehicleId="

    .line 57
    .line 58
    invoke-static {v0, v6, v1, v7, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v1, ", vin="

    .line 62
    .line 63
    const-string v2, ")"

    .line 64
    .line 65
    invoke-static {v0, v8, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method
