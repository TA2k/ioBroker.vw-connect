.class public final Lcz/myskoda/api/bff/v1/ChargingProfileDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000D\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u001c\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001BQ\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u0008\u0008\u0001\u0010\u0006\u001a\u00020\u0007\u0012\u000e\u0008\u0001\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\n0\t\u0012\u000e\u0008\u0001\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\t\u0012\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u000e\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\t\u0010#\u001a\u00020\u0003H\u00c6\u0003J\t\u0010$\u001a\u00020\u0005H\u00c6\u0003J\t\u0010%\u001a\u00020\u0007H\u00c6\u0003J\u000f\u0010&\u001a\u0008\u0012\u0004\u0012\u00020\n0\tH\u00c6\u0003J\u000f\u0010\'\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\tH\u00c6\u0003J\u000b\u0010(\u001a\u0004\u0018\u00010\u000eH\u00c6\u0003JS\u0010)\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0003\u0010\u0006\u001a\u00020\u00072\u000e\u0008\u0003\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\n0\t2\u000e\u0008\u0003\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\t2\n\u0008\u0003\u0010\r\u001a\u0004\u0018\u00010\u000eH\u00c6\u0001J\u0013\u0010*\u001a\u00020+2\u0008\u0010,\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010-\u001a\u00020.H\u00d6\u0001J\t\u0010/\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0011\u0010\u0012\u001a\u0004\u0008\u0013\u0010\u0014R\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0015\u0010\u0012\u001a\u0004\u0008\u0016\u0010\u0017R\u001c\u0010\u0006\u001a\u00020\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0018\u0010\u0012\u001a\u0004\u0008\u0019\u0010\u001aR\"\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\n0\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001b\u0010\u0012\u001a\u0004\u0008\u001c\u0010\u001dR\"\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u001e\u0010\u0012\u001a\u0004\u0008\u001f\u0010\u001dR\u001e\u0010\r\u001a\u0004\u0018\u00010\u000e8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008 \u0010\u0012\u001a\u0004\u0008!\u0010\"\u00a8\u00060"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/ChargingProfileDto;",
        "",
        "id",
        "",
        "name",
        "",
        "settings",
        "Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;",
        "preferredChargingTimes",
        "",
        "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
        "timers",
        "Lcz/myskoda/api/bff/v1/TimerDto;",
        "location",
        "Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;",
        "<init>",
        "(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)V",
        "getId$annotations",
        "()V",
        "getId",
        "()J",
        "getName$annotations",
        "getName",
        "()Ljava/lang/String;",
        "getSettings$annotations",
        "getSettings",
        "()Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;",
        "getPreferredChargingTimes$annotations",
        "getPreferredChargingTimes",
        "()Ljava/util/List;",
        "getTimers$annotations",
        "getTimers",
        "getLocation$annotations",
        "getLocation",
        "()Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
        "component6",
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
.field private final id:J

.field private final location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

.field private final name:Ljava/lang/String;

.field private final preferredChargingTimes:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
            ">;"
        }
    .end annotation
.end field

.field private final settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

.field private final timers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/TimerDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)V
    .locals 1
    .param p1    # J
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "settings"
        .end annotation
    .end param
    .param p5    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "preferredChargingTimes"
        .end annotation
    .end param
    .param p6    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "timers"
        .end annotation
    .end param
    .param p7    # Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "location"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/TimerDto;",
            ">;",
            "Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;",
            ")V"
        }
    .end annotation

    const-string v0, "name"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "settings"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "preferredChargingTimes"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "timers"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-wide p1, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 3
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 4
    iput-object p4, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 5
    iput-object p5, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 6
    iput-object p6, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 7
    iput-object p7, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    return-void
.end method

.method public synthetic constructor <init>(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;ILkotlin/jvm/internal/g;)V
    .locals 9

    and-int/lit8 v0, p8, 0x20

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    move-object v8, v0

    :goto_0
    move-object v1, p0

    move-wide v2, p1

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    move-object v7, p6

    goto :goto_1

    :cond_0
    move-object/from16 v8, p7

    goto :goto_0

    .line 8
    :goto_1
    invoke-direct/range {v1 .. v8}, Lcz/myskoda/api/bff/v1/ChargingProfileDto;-><init>(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/ChargingProfileDto;JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/ChargingProfileDto;
    .locals 8

    .line 1
    and-int/lit8 v0, p8, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 6
    .line 7
    :cond_0
    move-wide v1, p1

    .line 8
    and-int/lit8 p1, p8, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object p3, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 13
    .line 14
    :cond_1
    move-object v3, p3

    .line 15
    and-int/lit8 p1, p8, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-object p4, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 20
    .line 21
    :cond_2
    move-object v4, p4

    .line 22
    and-int/lit8 p1, p8, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-object p5, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 27
    .line 28
    :cond_3
    move-object v5, p5

    .line 29
    and-int/lit8 p1, p8, 0x10

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    iget-object p6, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 34
    .line 35
    :cond_4
    move-object v6, p6

    .line 36
    and-int/lit8 p1, p8, 0x20

    .line 37
    .line 38
    if-eqz p1, :cond_5

    .line 39
    .line 40
    iget-object p7, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 41
    .line 42
    :cond_5
    move-object v0, p0

    .line 43
    move-object v7, p7

    .line 44
    invoke-virtual/range {v0 .. v7}, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->copy(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)Lcz/myskoda/api/bff/v1/ChargingProfileDto;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
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

.method public static synthetic getLocation$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "location"
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

.method public static synthetic getPreferredChargingTimes$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "preferredChargingTimes"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getSettings$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "settings"
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
.method public final component1()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/TimerDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)Lcz/myskoda/api/bff/v1/ChargingProfileDto;
    .locals 8
    .param p1    # J
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "id"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "name"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "settings"
        .end annotation
    .end param
    .param p5    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "preferredChargingTimes"
        .end annotation
    .end param
    .param p6    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "timers"
        .end annotation
    .end param
    .param p7    # Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "location"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/TimerDto;",
            ">;",
            "Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;",
            ")",
            "Lcz/myskoda/api/bff/v1/ChargingProfileDto;"
        }
    .end annotation

    .line 1
    const-string p0, "name"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "settings"

    .line 7
    .line 8
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "preferredChargingTimes"

    .line 12
    .line 13
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "timers"

    .line 17
    .line 18
    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;

    .line 22
    .line 23
    move-wide v1, p1

    .line 24
    move-object v3, p3

    .line 25
    move-object v4, p4

    .line 26
    move-object v5, p5

    .line 27
    move-object v6, p6

    .line 28
    move-object v7, p7

    .line 29
    invoke-direct/range {v0 .. v7}, Lcz/myskoda/api/bff/v1/ChargingProfileDto;-><init>(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)V

    .line 30
    .line 31
    .line 32
    return-object v0
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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;

    .line 12
    .line 13
    iget-wide v3, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 14
    .line 15
    iget-wide v5, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 16
    .line 17
    cmp-long v1, v3, v5

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    return v2

    .line 22
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_3

    .line 31
    .line 32
    return v2

    .line 33
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 34
    .line 35
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 36
    .line 37
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_4

    .line 42
    .line 43
    return v2

    .line 44
    :cond_4
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 45
    .line 46
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 47
    .line 48
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-nez v1, :cond_5

    .line 53
    .line 54
    return v2

    .line 55
    :cond_5
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 56
    .line 57
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_6

    .line 64
    .line 65
    return v2

    .line 66
    :cond_6
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 67
    .line 68
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 69
    .line 70
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    if-nez p0, :cond_7

    .line 75
    .line 76
    return v2

    .line 77
    :cond_7
    return v0
.end method

.method public final getId()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getLocation()Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPreferredChargingTimes()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/ChargingTimeDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getSettings()Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

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
            "Lcz/myskoda/api/bff/v1/TimerDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

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
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 17
    .line 18
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 25
    .line 26
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 31
    .line 32
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 37
    .line 38
    if-nez p0, :cond_0

    .line 39
    .line 40
    const/4 p0, 0x0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    :goto_0
    add-int/2addr v0, p0

    .line 47
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 8

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->id:J

    .line 2
    .line 3
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->name:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v3, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->settings:Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 6
    .line 7
    iget-object v4, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->preferredChargingTimes:Ljava/util/List;

    .line 8
    .line 9
    iget-object v5, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->timers:Ljava/util/List;

    .line 10
    .line 11
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/ChargingProfileDto;->location:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 12
    .line 13
    new-instance v6, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v7, "ChargingProfileDto(id="

    .line 16
    .line 17
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v6, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v0, ", name="

    .line 24
    .line 25
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v0, ", settings="

    .line 32
    .line 33
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", preferredChargingTimes="

    .line 40
    .line 41
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v0, ", timers="

    .line 48
    .line 49
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v0, ", location="

    .line 56
    .line 57
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v6, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, ")"

    .line 64
    .line 65
    invoke-virtual {v6, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method
