.class public final Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0016\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001BS\u0012\u000e\u0008\u0001\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u0012\u000e\u0008\u0001\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u0012\u000e\u0008\u0001\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u0012\u000e\u0008\u0001\u0010\u0007\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0003\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u000f\u0010\u001a\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0003J\u000f\u0010\u001b\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0003J\u000f\u0010\u001c\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0003J\u000f\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0003H\u00c6\u0003J\u000b\u0010\u001e\u001a\u0004\u0018\u00010\nH\u00c6\u0003JU\u0010\u001f\u001a\u00020\u00002\u000e\u0008\u0003\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00032\u000e\u0008\u0003\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00032\u000e\u0008\u0003\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00032\u000e\u0008\u0003\u0010\u0007\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00032\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\nH\u00c6\u0001J\u0013\u0010 \u001a\u00020!2\u0008\u0010\"\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010#\u001a\u00020$H\u00d6\u0001J\t\u0010%\u001a\u00020\u0004H\u00d6\u0001R\"\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\r\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010R\"\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0011\u0010\u000e\u001a\u0004\u0008\u0012\u0010\u0010R\"\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\u000e\u001a\u0004\u0008\u0014\u0010\u0010R\"\u0010\u0007\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0015\u0010\u000e\u001a\u0004\u0008\u0016\u0010\u0010R\u001e\u0010\t\u001a\u0004\u0018\u00010\n8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0017\u0010\u000e\u001a\u0004\u0008\u0018\u0010\u0019\u00a8\u0006&"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;",
        "",
        "paymentMethods",
        "",
        "",
        "capabilities",
        "chargingOperators",
        "groupedChargingPointsByPower",
        "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
        "popularity",
        "Lcz/myskoda/api/bff_maps/v2/PopularityDto;",
        "<init>",
        "(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;)V",
        "getPaymentMethods$annotations",
        "()V",
        "getPaymentMethods",
        "()Ljava/util/List;",
        "getCapabilities$annotations",
        "getCapabilities",
        "getChargingOperators$annotations",
        "getChargingOperators",
        "getGroupedChargingPointsByPower$annotations",
        "getGroupedChargingPointsByPower",
        "getPopularity$annotations",
        "getPopularity",
        "()Lcz/myskoda/api/bff_maps/v2/PopularityDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "component5",
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
.field private final capabilities:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final chargingOperators:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final groupedChargingPointsByPower:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
            ">;"
        }
    .end annotation
.end field

.field private final paymentMethods:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;)V
    .locals 1
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "paymentMethods"
        .end annotation
    .end param
    .param p2    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "capabilities"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "chargingOperators"
        .end annotation
    .end param
    .param p4    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "groupedChargingPointsByPower"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff_maps/v2/PopularityDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "popularity"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
            ">;",
            "Lcz/myskoda/api/bff_maps/v2/PopularityDto;",
            ")V"
        }
    .end annotation

    const-string v0, "paymentMethods"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "capabilities"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "chargingOperators"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "groupedChargingPointsByPower"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 6
    iput-object p5, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;ILkotlin/jvm/internal/g;)V
    .locals 6

    and-int/lit8 p6, p6, 0x10

    if-eqz p6, :cond_0

    const/4 p5, 0x0

    :cond_0
    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    .line 7
    invoke-direct/range {v0 .. v5}, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;
    .locals 0

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p7, p6, 0x2

    .line 8
    .line 9
    if-eqz p7, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p7, p6, 0x4

    .line 14
    .line 15
    if-eqz p7, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p7, p6, 0x8

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 24
    .line 25
    :cond_3
    and-int/lit8 p6, p6, 0x10

    .line 26
    .line 27
    if-eqz p6, :cond_4

    .line 28
    .line 29
    iget-object p5, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

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
    invoke-virtual/range {p2 .. p7}, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->copy(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;)Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method public static synthetic getCapabilities$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "capabilities"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getChargingOperators$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "chargingOperators"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getGroupedChargingPointsByPower$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "groupedChargingPointsByPower"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPaymentMethods$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "paymentMethods"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPopularity$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "popularity"
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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/util/List;
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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

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
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

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
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Lcz/myskoda/api/bff_maps/v2/PopularityDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;)Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;
    .locals 6
    .param p1    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "paymentMethods"
        .end annotation
    .end param
    .param p2    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "capabilities"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "chargingOperators"
        .end annotation
    .end param
    .param p4    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "groupedChargingPointsByPower"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff_maps/v2/PopularityDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "popularity"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
            ">;",
            "Lcz/myskoda/api/bff_maps/v2/PopularityDto;",
            ")",
            "Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;"
        }
    .end annotation

    .line 1
    const-string p0, "paymentMethods"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "capabilities"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "chargingOperators"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "groupedChargingPointsByPower"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;

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
    move-object v5, p5

    .line 28
    invoke-direct/range {v0 .. v5}, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff_maps/v2/PopularityDto;)V

    .line 29
    .line 30
    .line 31
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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

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
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 47
    .line 48
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

    .line 58
    .line 59
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

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

.method public final getCapabilities()Ljava/util/List;
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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getChargingOperators()Ljava/util/List;
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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getGroupedChargingPointsByPower()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPaymentMethods()Ljava/util/List;
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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPopularity()Lcz/myskoda/api/bff_maps/v2/PopularityDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

    .line 29
    .line 30
    if-nez p0, :cond_0

    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff_maps/v2/PopularityDto;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    :goto_0
    add-int/2addr v0, p0

    .line 39
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->paymentMethods:Ljava/util/List;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->capabilities:Ljava/util/List;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->chargingOperators:Ljava/util/List;

    .line 6
    .line 7
    iget-object v3, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->groupedChargingPointsByPower:Ljava/util/List;

    .line 8
    .line 9
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ChargingStationDto;->popularity:Lcz/myskoda/api/bff_maps/v2/PopularityDto;

    .line 10
    .line 11
    new-instance v4, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v5, "ChargingStationDto(paymentMethods="

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
    const-string v0, ", capabilities="

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
    const-string v0, ", chargingOperators="

    .line 30
    .line 31
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v0, ", groupedChargingPointsByPower="

    .line 35
    .line 36
    const-string v1, ", popularity="

    .line 37
    .line 38
    invoke-static {v4, v2, v0, v3, v1}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string p0, ")"

    .line 45
    .line 46
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method
