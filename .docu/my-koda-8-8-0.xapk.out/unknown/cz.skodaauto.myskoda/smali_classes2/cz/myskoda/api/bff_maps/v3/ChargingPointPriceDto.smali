.class public final Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0010\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B%\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\t\u0010\u0012\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0013\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0014\u001a\u00020\u0006H\u00c6\u0003J\'\u0010\u0015\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0005\u001a\u00020\u0006H\u00c6\u0001J\u0013\u0010\u0016\u001a\u00020\u00172\u0008\u0010\u0018\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0019\u001a\u00020\u001aH\u00d6\u0001J\t\u0010\u001b\u001a\u00020\u0006H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000cR\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\r\u0010\n\u001a\u0004\u0008\u000e\u0010\u000cR\u001c\u0010\u0005\u001a\u00020\u00068\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\n\u001a\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u001c"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;",
        "",
        "pricePerKWh",
        "",
        "pricePerMinute",
        "currency",
        "",
        "<init>",
        "(FFLjava/lang/String;)V",
        "getPricePerKWh$annotations",
        "()V",
        "getPricePerKWh",
        "()F",
        "getPricePerMinute$annotations",
        "getPricePerMinute",
        "getCurrency$annotations",
        "getCurrency",
        "()Ljava/lang/String;",
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
.field private final currency:Ljava/lang/String;

.field private final pricePerKWh:F

.field private final pricePerMinute:F


# direct methods
.method public constructor <init>(FFLjava/lang/String;)V
    .locals 1
    .param p1    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pricePerKWh"
        .end annotation
    .end param
    .param p2    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pricePerMinute"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currency"
        .end annotation
    .end param

    .line 1
    const-string v0, "currency"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput p1, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

    .line 10
    .line 11
    iput p2, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 12
    .line 13
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;FFLjava/lang/String;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->copy(FFLjava/lang/String;)Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getCurrency$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "currency"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPricePerKWh$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "pricePerKWh"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPricePerMinute$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "pricePerMinute"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

    .line 2
    .line 3
    return p0
.end method

.method public final component2()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(FFLjava/lang/String;)Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;
    .locals 0
    .param p1    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pricePerKWh"
        .end annotation
    .end param
    .param p2    # F
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "pricePerMinute"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currency"
        .end annotation
    .end param

    .line 1
    const-string p0, "currency"

    .line 2
    .line 3
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;-><init>(FFLjava/lang/String;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

    .line 14
    .line 15
    iget v3, p1, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

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
    iget v1, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 25
    .line 26
    iget v3, p1, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 27
    .line 28
    invoke-static {v1, v3}, Ljava/lang/Float;->compare(FF)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

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

.method public final getCurrency()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPricePerKWh()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

    .line 2
    .line 3
    return p0
.end method

.method public final getPricePerMinute()F
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

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
    iget v2, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

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
    iget v0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerKWh:F

    .line 2
    .line 3
    iget v1, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->pricePerMinute:F

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v3/ChargingPointPriceDto;->currency:Ljava/lang/String;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "ChargingPointPriceDto(pricePerKWh="

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
    const-string v0, ", pricePerMinute="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", currency="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, ")"

    .line 31
    .line 32
    invoke-static {v2, p0, v0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
