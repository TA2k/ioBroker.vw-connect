.class public final Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0011\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B+\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\u000e\u0008\u0001\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007\u00a2\u0006\u0004\u0008\t\u0010\nJ\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0016\u001a\u00020\u0005H\u00c6\u0003J\u000f\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u00c6\u0003J-\u0010\u0018\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\u000e\u0008\u0003\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u00c6\u0001J\u0013\u0010\u0019\u001a\u00020\u001a2\u0008\u0010\u001b\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001c\u001a\u00020\u001dH\u00d6\u0001J\t\u0010\u001e\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R\"\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u0014\u00a8\u0006\u001f"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;",
        "",
        "nominalPowerOutputInKw",
        "",
        "currentType",
        "",
        "groupedChargingPointsByConnectors",
        "",
        "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByConnectorsDto;",
        "<init>",
        "(FLjava/lang/String;Ljava/util/List;)V",
        "getNominalPowerOutputInKw$annotations",
        "()V",
        "getNominalPowerOutputInKw",
        "()F",
        "getCurrentType$annotations",
        "getCurrentType",
        "()Ljava/lang/String;",
        "getGroupedChargingPointsByConnectors$annotations",
        "getGroupedChargingPointsByConnectors",
        "()Ljava/util/List;",
        "component1",
        "component2",
        "component3",
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
.field private final currentType:Ljava/lang/String;

.field private final groupedChargingPointsByConnectors:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByConnectorsDto;",
            ">;"
        }
    .end annotation
.end field

.field private final nominalPowerOutputInKw:F


# direct methods
.method public constructor <init>(FLjava/lang/String;Ljava/util/List;)V
    .locals 1
    .param p1    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "nominalPowerOutputInKw"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currentType"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "groupedChargingPointsByConnectors"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(F",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByConnectorsDto;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "currentType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "groupedChargingPointsByConnectors"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput p1, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 15
    .line 16
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 19
    .line 20
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;FLjava/lang/String;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->copy(FLjava/lang/String;Ljava/util/List;)Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getCurrentType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "currentType"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getGroupedChargingPointsByConnectors$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "groupedChargingPointsByConnectors"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getNominalPowerOutputInKw$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "nominalPowerOutputInKw"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

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
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByConnectorsDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(FLjava/lang/String;Ljava/util/List;)Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;
    .locals 0
    .param p1    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "nominalPowerOutputInKw"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currentType"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "groupedChargingPointsByConnectors"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(F",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByConnectorsDto;",
            ">;)",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;"
        }
    .end annotation

    .line 1
    const-string p0, "currentType"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "groupedChargingPointsByConnectors"

    .line 7
    .line 8
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;-><init>(FLjava/lang/String;Ljava/util/List;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 14
    .line 15
    iget v3, p1, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 16
    .line 17
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

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

.method public final getCurrentType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getGroupedChargingPointsByConnectors()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByConnectorsDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNominalPowerOutputInKw()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

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
    iget-object v2, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/2addr p0, v0

    .line 23
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->nominalPowerOutputInKw:F

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->currentType:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/GroupedChargingPointsByPowerDto;->groupedChargingPointsByConnectors:Ljava/util/List;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "GroupedChargingPointsByPowerDto(nominalPowerOutputInKw="

    .line 10
    .line 11
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", currentType="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", groupedChargingPointsByConnectors="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, ")"

    .line 31
    .line 32
    invoke-static {v2, p0, v0}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
