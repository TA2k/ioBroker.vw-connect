.class public final Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0019\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001BI\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0010\u0005\u001a\u0004\u0018\u00010\u0003\u0012\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0003\u0012\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0003\u0012\u0008\u0010\u0008\u001a\u0004\u0018\u00010\u0003\u0012\u0008\u0010\t\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\t\u0010\u0014\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\u0016\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u0017\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u0018\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u0019\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u000b\u0010\u001a\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003JY\u0010\u001b\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\u0008\u001a\u0004\u0018\u00010\u00032\n\u0008\u0002\u0010\t\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001J\u0013\u0010\u001c\u001a\u00020\u001d2\u0008\u0010\u001e\u001a\u0004\u0018\u00010\u001fH\u00d6\u0003J\t\u0010 \u001a\u00020!H\u00d6\u0001J\t\u0010\"\u001a\u00020\u0003H\u00d6\u0001R\u0016\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\rR\u0016\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000e\u0010\rR\u0018\u0010\u0005\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\rR\u0018\u0010\u0006\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0010\u0010\rR\u0018\u0010\u0007\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\rR\u0018\u0010\u0008\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0012\u0010\rR\u0018\u0010\t\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\r\u00a8\u0006#"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;",
        "Lcz/skodaauto/myskoda/library/asyncevent/data/AsyncEventDataDto;",
        "userId",
        "",
        "vin",
        "chargeMode",
        "chargingState",
        "stateOfChargeInPercent",
        "cruisingRangeInKm",
        "remainingChargingTimeInMinutes",
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        "getUserId",
        "()Ljava/lang/String;",
        "getVin",
        "getChargeMode",
        "getChargingState",
        "getStateOfChargeInPercent",
        "getCruisingRangeInKm",
        "getRemainingChargingTimeInMinutes",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
        "component7",
        "copy",
        "equals",
        "",
        "other",
        "",
        "hashCode",
        "",
        "toString",
        "async-event_release"
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
.field private final chargeMode:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "mode"
    .end annotation
.end field

.field private final chargingState:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "state"
    .end annotation
.end field

.field private final cruisingRangeInKm:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "chargedRange"
    .end annotation
.end field

.field private final remainingChargingTimeInMinutes:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "timeToFinish"
    .end annotation
.end field

.field private final stateOfChargeInPercent:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "soc"
    .end annotation
.end field

.field private final userId:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "userId"
    .end annotation
.end field

.field private final vin:Ljava/lang/String;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vin"
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "userId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vin"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p3, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p4, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 21
    .line 22
    iput-object p5, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 23
    .line 24
    iput-object p6, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 25
    .line 26
    iput-object p7, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 27
    .line 28
    return-void
.end method

.method public static synthetic copy$default(Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;
    .locals 0

    .line 1
    and-int/lit8 p9, p8, 0x1

    .line 2
    .line 3
    if-eqz p9, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p9, p8, 0x2

    .line 8
    .line 9
    if-eqz p9, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p9, p8, 0x4

    .line 14
    .line 15
    if-eqz p9, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p9, p8, 0x8

    .line 20
    .line 21
    if-eqz p9, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p9, p8, 0x10

    .line 26
    .line 27
    if-eqz p9, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 30
    .line 31
    :cond_4
    and-int/lit8 p9, p8, 0x20

    .line 32
    .line 33
    if-eqz p9, :cond_5

    .line 34
    .line 35
    iget-object p6, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 36
    .line 37
    :cond_5
    and-int/lit8 p8, p8, 0x40

    .line 38
    .line 39
    if-eqz p8, :cond_6

    .line 40
    .line 41
    iget-object p7, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 42
    .line 43
    :cond_6
    move-object p8, p6

    .line 44
    move-object p9, p7

    .line 45
    move-object p6, p4

    .line 46
    move-object p7, p5

    .line 47
    move-object p4, p2

    .line 48
    move-object p5, p3

    .line 49
    move-object p2, p0

    .line 50
    move-object p3, p1

    .line 51
    invoke-virtual/range {p2 .. p9}, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component7()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;
    .locals 8

    .line 1
    const-string p0, "userId"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "vin"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;

    .line 12
    .line 13
    move-object v1, p1

    .line 14
    move-object v2, p2

    .line 15
    move-object v3, p3

    .line 16
    move-object v4, p4

    .line 17
    move-object v5, p5

    .line 18
    move-object v6, p6

    .line 19
    move-object v7, p7

    .line 20
    invoke-direct/range {v0 .. v7}, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
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
    instance-of v1, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;

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
    check-cast p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

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
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v3, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 80
    .line 81
    iget-object p1, p1, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 82
    .line 83
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    if-nez p0, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    return v0
.end method

.method public final getChargeMode()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getChargingState()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCruisingRangeInKm()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRemainingChargingTimeInMinutes()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStateOfChargeInPercent()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUserId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVin()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

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
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

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
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v2, :cond_1

    .line 32
    .line 33
    move v2, v3

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    :goto_1
    add-int/2addr v0, v2

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v2, :cond_2

    .line 44
    .line 45
    move v2, v3

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    :goto_2
    add-int/2addr v0, v2

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 54
    .line 55
    if-nez v2, :cond_3

    .line 56
    .line 57
    move v2, v3

    .line 58
    goto :goto_3

    .line 59
    :cond_3
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    :goto_3
    add-int/2addr v0, v2

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 66
    .line 67
    if-nez p0, :cond_4

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_4
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    :goto_4
    add-int/2addr v0, v3

    .line 75
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 9

    .line 1
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->userId:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->vin:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargeMode:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->chargingState:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->stateOfChargeInPercent:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->cruisingRangeInKm:Ljava/lang/String;

    .line 12
    .line 13
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/asyncevent/data/ChargingEventDataDto;->remainingChargingTimeInMinutes:Ljava/lang/String;

    .line 14
    .line 15
    const-string v6, ", vin="

    .line 16
    .line 17
    const-string v7, ", chargeMode="

    .line 18
    .line 19
    const-string v8, "ChargingEventDataDto(userId="

    .line 20
    .line 21
    invoke-static {v8, v0, v6, v1, v7}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    const-string v1, ", chargingState="

    .line 26
    .line 27
    const-string v6, ", stateOfChargeInPercent="

    .line 28
    .line 29
    invoke-static {v0, v2, v1, v3, v6}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-string v1, ", cruisingRangeInKm="

    .line 33
    .line 34
    const-string v2, ", remainingChargingTimeInMinutes="

    .line 35
    .line 36
    invoke-static {v0, v4, v1, v5, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v1, ")"

    .line 40
    .line 41
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method
