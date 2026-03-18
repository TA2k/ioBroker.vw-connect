.class public final Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0014\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\'\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0003\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\t\u0010\u0014\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0015\u001a\u00020\u0005H\u00c6\u0003J\u0010\u0010\u0016\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0012J.\u0010\u0017\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0003H\u00c6\u0001\u00a2\u0006\u0002\u0010\u0018J\u0013\u0010\u0019\u001a\u00020\u001a2\u0008\u0010\u001b\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001c\u001a\u00020\u001dH\u00d6\u0001J\t\u0010\u001e\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\t\u0010\n\u001a\u0004\u0008\u000b\u0010\u000cR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\r\u0010\n\u001a\u0004\u0008\u000e\u0010\u000fR \u0010\u0006\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0013\u0012\u0004\u0008\u0010\u0010\n\u001a\u0004\u0008\u0011\u0010\u0012\u00a8\u0006\u001f"
    }
    d2 = {
        "Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;",
        "",
        "current",
        "",
        "currency",
        "",
        "original",
        "<init>",
        "(DLjava/lang/String;Ljava/lang/Double;)V",
        "getCurrent$annotations",
        "()V",
        "getCurrent",
        "()D",
        "getCurrency$annotations",
        "getCurrency",
        "()Ljava/lang/String;",
        "getOriginal$annotations",
        "getOriginal",
        "()Ljava/lang/Double;",
        "Ljava/lang/Double;",
        "component1",
        "component2",
        "component3",
        "copy",
        "(DLjava/lang/String;Ljava/lang/Double;)Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;",
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

.field private final current:D

.field private final original:Ljava/lang/Double;


# direct methods
.method public constructor <init>(DLjava/lang/String;Ljava/lang/Double;)V
    .locals 1
    .param p1    # D
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "current"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currency"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "original"
        .end annotation
    .end param

    const-string v0, "currency"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-wide p1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 3
    iput-object p3, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 4
    iput-object p4, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    return-void
.end method

.method public synthetic constructor <init>(DLjava/lang/String;Ljava/lang/Double;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x4

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 5
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;-><init>(DLjava/lang/String;Ljava/lang/Double;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;DLjava/lang/String;Ljava/lang/Double;ILjava/lang/Object;)Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p3, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p5, p5, 0x4

    .line 14
    .line 15
    if-eqz p5, :cond_2

    .line 16
    .line 17
    iget-object p4, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->copy(DLjava/lang/String;Ljava/lang/Double;)Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;

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

.method public static synthetic getCurrent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "current"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOriginal$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "original"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(DLjava/lang/String;Ljava/lang/Double;)Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;
    .locals 0
    .param p1    # D
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "current"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "currency"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Double;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "original"
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
    new-instance p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;-><init>(DLjava/lang/String;Ljava/lang/Double;)V

    .line 9
    .line 10
    .line 11
    return-object p0
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
    instance-of v1, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;

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
    check-cast p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;

    .line 12
    .line 13
    iget-wide v3, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 14
    .line 15
    iget-wide v5, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 16
    .line 17
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

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
    iget-object v1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCurrent()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final getOriginal()Ljava/lang/Double;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

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
    iget-object v2, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    :goto_0
    add-int/2addr v0, p0

    .line 27
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-wide v0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->current:D

    .line 2
    .line 3
    iget-object v2, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->currency:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionPriceDto;->original:Ljava/lang/Double;

    .line 6
    .line 7
    new-instance v3, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v4, "SubscriptionPriceDto(current="

    .line 10
    .line 11
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v0, v1}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", currency="

    .line 18
    .line 19
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", original="

    .line 26
    .line 27
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, ")"

    .line 34
    .line 35
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
