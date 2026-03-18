.class public final Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0018\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B7\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u000e\u0008\u0001\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\t\u0010\u001a\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001b\u001a\u00020\u0005H\u00c6\u0003J\u000f\u0010\u001c\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u00c6\u0003J\u0010\u0010\u001d\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0018J>\u0010\u001e\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u000e\u0008\u0003\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00072\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\u0005H\u00c6\u0001\u00a2\u0006\u0002\u0010\u001fJ\u0013\u0010 \u001a\u00020!2\u0008\u0010\"\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010#\u001a\u00020\u0005H\u00d6\u0001J\t\u0010$\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000c\u0010\r\u001a\u0004\u0008\u000e\u0010\u000fR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\r\u001a\u0004\u0008\u0011\u0010\u0012R\"\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\r\u001a\u0004\u0008\u0014\u0010\u0015R \u0010\t\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0019\u0012\u0004\u0008\u0016\u0010\r\u001a\u0004\u0008\u0017\u0010\u0018\u00a8\u0006%"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;",
        "",
        "connectorType",
        "",
        "countTotal",
        "",
        "chargingPoints",
        "",
        "Lcz/myskoda/api/bff_maps/v3/ChargingPointDto;",
        "countAvailable",
        "<init>",
        "(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)V",
        "getConnectorType$annotations",
        "()V",
        "getConnectorType",
        "()Ljava/lang/String;",
        "getCountTotal$annotations",
        "getCountTotal",
        "()I",
        "getChargingPoints$annotations",
        "getChargingPoints",
        "()Ljava/util/List;",
        "getCountAvailable$annotations",
        "getCountAvailable",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;",
        "equals",
        "",
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
.field private final chargingPoints:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v3/ChargingPointDto;",
            ">;"
        }
    .end annotation
.end field

.field private final connectorType:Ljava/lang/String;

.field private final countAvailable:Ljava/lang/Integer;

.field private final countTotal:I


# direct methods
.method public constructor <init>(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "connectorType"
        .end annotation
    .end param
    .param p2    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "countTotal"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "chargingPoints"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "countAvailable"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "I",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v3/ChargingPointDto;",
            ">;",
            "Ljava/lang/Integer;",
            ")V"
        }
    .end annotation

    const-string v0, "connectorType"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "chargingPoints"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

    .line 3
    iput p2, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;-><init>(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->copy(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getChargingPoints$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "chargingPoints"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getConnectorType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "connectorType"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCountAvailable$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "countAvailable"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getCountTotal$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "countTotal"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v3/ChargingPointDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "connectorType"
        .end annotation
    .end param
    .param p2    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "countTotal"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "chargingPoints"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "countAvailable"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "I",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v3/ChargingPointDto;",
            ">;",
            "Ljava/lang/Integer;",
            ")",
            "Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;"
        }
    .end annotation

    .line 1
    const-string p0, "connectorType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "chargingPoints"

    .line 7
    .line 8
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;-><init>(Ljava/lang/String;ILjava/util/List;Ljava/lang/Integer;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

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
    iget v1, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 25
    .line 26
    iget v3, p1, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 32
    .line 33
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 43
    .line 44
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    return v0
.end method

.method public final getChargingPoints()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v3/ChargingPointDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConnectorType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCountAvailable()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCountTotal()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

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
    iget v2, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 23
    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    :goto_0
    add-int/2addr v0, p0

    .line 33
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->connectorType:Ljava/lang/String;

    .line 2
    .line 3
    iget v1, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countTotal:I

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->chargingPoints:Ljava/util/List;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/GroupedChargingPointsByConnectorsDto;->countAvailable:Ljava/lang/Integer;

    .line 8
    .line 9
    const-string v3, ", countTotal="

    .line 10
    .line 11
    const-string v4, ", chargingPoints="

    .line 12
    .line 13
    const-string v5, "GroupedChargingPointsByConnectorsDto(connectorType="

    .line 14
    .line 15
    invoke-static {v5, v1, v0, v3, v4}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, ", countAvailable="

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, ")"

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
