.class public final Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0015\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B/\u0012\u000e\u0008\u0001\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u0012\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u0012\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\t\u0010\nJ\u000f\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0003J\u0010\u0010\u0017\u001a\u0004\u0018\u00010\u0006H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0011J\u000b\u0010\u0018\u001a\u0004\u0018\u00010\u0008H\u00c6\u0003J6\u0010\u0019\u001a\u00020\u00002\u000e\u0008\u0003\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00032\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u00062\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008H\u00c6\u0001\u00a2\u0006\u0002\u0010\u001aJ\u0013\u0010\u001b\u001a\u00020\u00062\u0008\u0010\u001c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001d\u001a\u00020\u001eH\u00d6\u0001J\t\u0010\u001f\u001a\u00020\u0004H\u00d6\u0001R\"\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR \u0010\u0005\u001a\u0004\u0018\u00010\u00068\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0012\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R\u001e\u0010\u0007\u001a\u0004\u0018\u00010\u00088\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\u000c\u001a\u0004\u0008\u0014\u0010\u0015\u00a8\u0006 "
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;",
        "",
        "avoidance",
        "",
        "",
        "preferPowerpassChargingProviders",
        "",
        "batteryLevels",
        "Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;",
        "<init>",
        "(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)V",
        "getAvoidance$annotations",
        "()V",
        "getAvoidance",
        "()Ljava/util/List;",
        "getPreferPowerpassChargingProviders$annotations",
        "getPreferPowerpassChargingProviders",
        "()Ljava/lang/Boolean;",
        "Ljava/lang/Boolean;",
        "getBatteryLevels$annotations",
        "getBatteryLevels",
        "()Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;",
        "component1",
        "component2",
        "component3",
        "copy",
        "(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;",
        "equals",
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
.field private final avoidance:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

.field private final preferPowerpassChargingProviders:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)V
    .locals 1
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "avoidance"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Boolean;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "preferPowerpassChargingProviders"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryLevels"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/Boolean;",
            "Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;",
            ")V"
        }
    .end annotation

    const-string v0, "avoidance"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_0

    .line 5
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    const/4 p3, 0x0

    .line 6
    :cond_1
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;-><init>(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->copy(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getAvoidance$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "avoidance"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getBatteryLevels$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "batteryLevels"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPreferPowerpassChargingProviders$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "preferPowerpassChargingProviders"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;
    .locals 0
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "avoidance"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Boolean;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "preferPowerpassChargingProviders"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "batteryLevels"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/Boolean;",
            "Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;",
            ")",
            "Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;"
        }
    .end annotation

    .line 1
    const-string p0, "avoidance"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;-><init>(Ljava/util/List;Ljava/lang/Boolean;Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

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

.method public final getAvoidance()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getBatteryLevels()Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPreferPowerpassChargingProviders()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

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
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    .line 24
    .line 25
    if-nez p0, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;->hashCode()I

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
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->avoidance:Ljava/util/List;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->preferPowerpassChargingProviders:Ljava/lang/Boolean;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/NavigationPreferencesDto;->batteryLevels:Lcz/myskoda/api/bff_maps/v3/NavigationBatteryLevelsDto;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "NavigationPreferencesDto(avoidance="

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
    const-string v0, ", preferPowerpassChargingProviders="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", batteryLevels="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, ")"

    .line 34
    .line 35
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
