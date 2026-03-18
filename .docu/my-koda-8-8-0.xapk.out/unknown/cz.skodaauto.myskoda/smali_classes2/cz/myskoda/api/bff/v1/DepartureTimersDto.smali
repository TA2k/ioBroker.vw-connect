.class public final Lcz/myskoda/api/bff/v1/DepartureTimersDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u001c\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001BI\u0012\n\u0008\u0003\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u0012\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\u0010\u0008\u0003\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0008\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\n\u0012\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u000c\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u000b\u0010!\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u0010\u0010\"\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0015J\u0011\u0010#\u001a\n\u0012\u0004\u0012\u00020\u0008\u0018\u00010\u0007H\u00c6\u0003J\u0010\u0010$\u001a\u0004\u0018\u00010\nH\u00c6\u0003\u00a2\u0006\u0002\u0010\u001cJ\u000b\u0010%\u001a\u0004\u0018\u00010\u000cH\u00c6\u0003JP\u0010&\u001a\u00020\u00002\n\u0008\u0003\u0010\u0002\u001a\u0004\u0018\u00010\u00032\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u00052\u0010\u0008\u0003\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0008\u0018\u00010\u00072\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\n2\n\u0008\u0003\u0010\u000b\u001a\u0004\u0018\u00010\u000cH\u00c6\u0001\u00a2\u0006\u0002\u0010\'J\u0013\u0010(\u001a\u00020)2\u0008\u0010*\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010+\u001a\u00020\u0005H\u00d6\u0001J\t\u0010,\u001a\u00020-H\u00d6\u0001R\u001e\u0010\u0002\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u0010\u001a\u0004\u0008\u0011\u0010\u0012R \u0010\u0004\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0016\u0012\u0004\u0008\u0013\u0010\u0010\u001a\u0004\u0008\u0014\u0010\u0015R$\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0008\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0017\u0010\u0010\u001a\u0004\u0008\u0018\u0010\u0019R \u0010\t\u001a\u0004\u0018\u00010\n8\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u001d\u0012\u0004\u0008\u001a\u0010\u0010\u001a\u0004\u0008\u001b\u0010\u001cR\u001e\u0010\u000b\u001a\u0004\u0018\u00010\u000c8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001e\u0010\u0010\u001a\u0004\u0008\u001f\u0010 \u00a8\u0006."
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/DepartureTimersDto;",
        "",
        "targetTemperature",
        "Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;",
        "minimumBatteryStateOfChargeInPercent",
        "",
        "timers",
        "",
        "Lcz/myskoda/api/bff/v1/DepartureTimerDto;",
        "firstOccurringTimerId",
        "",
        "carCapturedTimestamp",
        "Ljava/time/OffsetDateTime;",
        "<init>",
        "(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V",
        "getTargetTemperature$annotations",
        "()V",
        "getTargetTemperature",
        "()Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;",
        "getMinimumBatteryStateOfChargeInPercent$annotations",
        "getMinimumBatteryStateOfChargeInPercent",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "getTimers$annotations",
        "getTimers",
        "()Ljava/util/List;",
        "getFirstOccurringTimerId$annotations",
        "getFirstOccurringTimerId",
        "()Ljava/lang/Long;",
        "Ljava/lang/Long;",
        "getCarCapturedTimestamp$annotations",
        "getCarCapturedTimestamp",
        "()Ljava/time/OffsetDateTime;",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "copy",
        "(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff/v1/DepartureTimersDto;",
        "equals",
        "",
        "other",
        "hashCode",
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
.field private final carCapturedTimestamp:Ljava/time/OffsetDateTime;

.field private final firstOccurringTimerId:Ljava/lang/Long;

.field private final minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

.field private final targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

.field private final timers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/DepartureTimerDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 8

    .line 1
    const/16 v6, 0x1f

    const/4 v7, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v7}, Lcz/myskoda/api/bff/v1/DepartureTimersDto;-><init>(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V
    .locals 0
    .param p1    # Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "targetTemperature"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "minimumBatteryStateOfChargeInPercent"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "timers"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "firstOccurringTimerId"
        .end annotation
    .end param
    .param p5    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "carCapturedTimestamp"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;",
            "Ljava/lang/Integer;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/DepartureTimerDto;",
            ">;",
            "Ljava/lang/Long;",
            "Ljava/time/OffsetDateTime;",
            ")V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 4
    iput-object p2, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 5
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 6
    iput-object p4, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 7
    iput-object p5, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    return-void
.end method

.method public synthetic constructor <init>(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p7, p6, 0x1

    const/4 v0, 0x0

    if-eqz p7, :cond_0

    move-object p1, v0

    :cond_0
    and-int/lit8 p7, p6, 0x2

    if-eqz p7, :cond_1

    move-object p2, v0

    :cond_1
    and-int/lit8 p7, p6, 0x4

    if-eqz p7, :cond_2

    move-object p3, v0

    :cond_2
    and-int/lit8 p7, p6, 0x8

    if-eqz p7, :cond_3

    move-object p4, v0

    :cond_3
    and-int/lit8 p6, p6, 0x10

    if-eqz p6, :cond_4

    move-object p5, v0

    .line 8
    :cond_4
    invoke-direct/range {p0 .. p5}, Lcz/myskoda/api/bff/v1/DepartureTimersDto;-><init>(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/DepartureTimersDto;Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/DepartureTimersDto;
    .locals 0

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p7, p6, 0x2

    .line 8
    .line 9
    if-eqz p7, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p7, p6, 0x4

    .line 14
    .line 15
    if-eqz p7, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p7, p6, 0x8

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p6, p6, 0x10

    .line 26
    .line 27
    if-eqz p6, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 30
    .line 31
    :cond_4
    move-object p6, p4

    .line 32
    move-object p7, p5

    .line 33
    move-object p4, p2

    .line 34
    move-object p5, p3

    .line 35
    move-object p2, p0

    .line 36
    move-object p3, p1

    .line 37
    invoke-virtual/range {p2 .. p7}, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->copy(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff/v1/DepartureTimersDto;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public static synthetic getCarCapturedTimestamp$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "carCapturedTimestamp"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getFirstOccurringTimerId$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "firstOccurringTimerId"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getMinimumBatteryStateOfChargeInPercent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "minimumBatteryStateOfChargeInPercent"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTargetTemperature$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "targetTemperature"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTimers$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "timers"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/DepartureTimerDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)Lcz/myskoda/api/bff/v1/DepartureTimersDto;
    .locals 0
    .param p1    # Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "targetTemperature"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "minimumBatteryStateOfChargeInPercent"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "timers"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Long;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "firstOccurringTimerId"
        .end annotation
    .end param
    .param p5    # Ljava/time/OffsetDateTime;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "carCapturedTimestamp"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;",
            "Ljava/lang/Integer;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/DepartureTimerDto;",
            ">;",
            "Ljava/lang/Long;",
            "Ljava/time/OffsetDateTime;",
            ")",
            "Lcz/myskoda/api/bff/v1/DepartureTimersDto;"
        }
    .end annotation

    .line 1
    new-instance p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;

    .line 2
    .line 3
    invoke-direct/range {p0 .. p5}, Lcz/myskoda/api/bff/v1/DepartureTimersDto;-><init>(Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/Long;Ljava/time/OffsetDateTime;)V

    .line 4
    .line 5
    .line 6
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 47
    .line 48
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

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
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 58
    .line 59
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 60
    .line 61
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-nez p0, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    return v0
.end method

.method public final getCarCapturedTimestamp()Ljava/time/OffsetDateTime;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFirstOccurringTimerId()Ljava/lang/Long;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMinimumBatteryStateOfChargeInPercent()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTargetTemperature()Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTimers()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/DepartureTimerDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move v2, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    :goto_1
    add-int/2addr v0, v2

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 28
    .line 29
    if-nez v2, :cond_2

    .line 30
    .line 31
    move v2, v1

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    :goto_2
    add-int/2addr v0, v2

    .line 38
    mul-int/lit8 v0, v0, 0x1f

    .line 39
    .line 40
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 41
    .line 42
    if-nez v2, :cond_3

    .line 43
    .line 44
    move v2, v1

    .line 45
    goto :goto_3

    .line 46
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    :goto_3
    add-int/2addr v0, v2

    .line 51
    mul-int/lit8 v0, v0, 0x1f

    .line 52
    .line 53
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 54
    .line 55
    if-nez p0, :cond_4

    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_4
    invoke-virtual {p0}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    :goto_4
    add-int/2addr v0, v1

    .line 63
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->targetTemperature:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->minimumBatteryStateOfChargeInPercent:Ljava/lang/Integer;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->timers:Ljava/util/List;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->firstOccurringTimerId:Ljava/lang/Long;

    .line 8
    .line 9
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DepartureTimersDto;->carCapturedTimestamp:Ljava/time/OffsetDateTime;

    .line 10
    .line 11
    new-instance v4, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v5, "DepartureTimersDto(targetTemperature="

    .line 14
    .line 15
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v0, ", minimumBatteryStateOfChargeInPercent="

    .line 22
    .line 23
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, ", timers="

    .line 30
    .line 31
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v0, ", firstOccurringTimerId="

    .line 38
    .line 39
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v0, ", carCapturedTimestamp="

    .line 46
    .line 47
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p0, ")"

    .line 54
    .line 55
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method
