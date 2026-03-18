.class public final Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0017\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\'\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0016\u001a\u00020\u0005H\u00c6\u0003J\u0010\u0010\u0017\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0013J.\u0010\u0018\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007H\u00c6\u0001\u00a2\u0006\u0002\u0010\u0019J\u0013\u0010\u001a\u001a\u00020\u00052\u0008\u0010\u001b\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001c\u001a\u00020\u0007H\u00d6\u0001J\t\u0010\u001d\u001a\u00020\u0003H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\u0010R \u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0014\u0012\u0004\u0008\u0011\u0010\u000b\u001a\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u001e"
    }
    d2 = {
        "Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;",
        "",
        "unit",
        "",
        "teaser",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;ZLjava/lang/Integer;)V",
        "getUnit$annotations",
        "()V",
        "getUnit",
        "()Ljava/lang/String;",
        "getTeaser$annotations",
        "getTeaser",
        "()Z",
        "getValue$annotations",
        "getValue",
        "()Ljava/lang/Integer;",
        "Ljava/lang/Integer;",
        "component1",
        "component2",
        "component3",
        "copy",
        "(Ljava/lang/String;ZLjava/lang/Integer;)Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;",
        "equals",
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
.field private final teaser:Z

.field private final unit:Ljava/lang/String;

.field private final value:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(Ljava/lang/String;ZLjava/lang/Integer;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "unit"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "teaser"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "value"
        .end annotation
    .end param

    const-string v0, "unit"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

    .line 3
    iput-boolean p2, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ZLjava/lang/Integer;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_0

    const/4 p2, 0x0

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    const/4 p3, 0x0

    .line 5
    :cond_1
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;-><init>(Ljava/lang/String;ZLjava/lang/Integer;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;Ljava/lang/String;ZLjava/lang/Integer;ILjava/lang/Object;)Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->copy(Ljava/lang/String;ZLjava/lang/Integer;)Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getTeaser$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "teaser"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUnit$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "unit"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getValue$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "value"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;ZLjava/lang/Integer;)Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "unit"
        .end annotation
    .end param
    .param p2    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "teaser"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Integer;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "value"
        .end annotation
    .end param

    .line 1
    const-string p0, "unit"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;-><init>(Ljava/lang/String;ZLjava/lang/Integer;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;

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
    check-cast p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

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
    iget-boolean v1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    .line 32
    .line 33
    iget-object p1, p1, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    .line 34
    .line 35
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-nez p0, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    return v0
.end method

.method public final getTeaser()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getUnit()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getValue()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

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
    iget-boolean v2, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

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
    iget-object v0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->unit:Ljava/lang/String;

    .line 2
    .line 3
    iget-boolean v1, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->teaser:Z

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_shop/v2/SubscriptionTermDto;->value:Ljava/lang/Integer;

    .line 6
    .line 7
    const-string v2, ", teaser="

    .line 8
    .line 9
    const-string v3, ", value="

    .line 10
    .line 11
    const-string v4, "SubscriptionTermDto(unit="

    .line 12
    .line 13
    invoke-static {v4, v0, v2, v3, v1}, Lia/b;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    const-string v1, ")"

    .line 18
    .line 19
    invoke-static {v0, p0, v1}, Lkx/a;->l(Ljava/lang/StringBuilder;Ljava/lang/Integer;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
