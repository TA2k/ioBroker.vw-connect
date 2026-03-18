.class public final Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0080\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;",
        "Lv3/z0;",
        "Lym/j;",
        "lottie-compose_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:I

.field public final c:I


# direct methods
.method public constructor <init>(II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 5
    .line 6
    iput p2, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
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
    instance-of v1, p1, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;

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
    check-cast p1, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;

    .line 12
    .line 13
    iget v1, p1, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 14
    .line 15
    iget v3, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 16
    .line 17
    if-eq v3, v1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget p0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 21
    .line 22
    iget p1, p1, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 23
    .line 24
    if-eq p0, p1, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    return v0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Lym/j;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 7
    .line 8
    iput v1, v0, Lym/j;->r:I

    .line 9
    .line 10
    iget p0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 11
    .line 12
    iput p0, v0, Lym/j;->s:I

    .line 13
    .line 14
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget p0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 1

    .line 1
    check-cast p1, Lym/j;

    .line 2
    .line 3
    const-string v0, "node"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 9
    .line 10
    iput v0, p1, Lym/j;->r:I

    .line 11
    .line 12
    iget p0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 13
    .line 14
    iput p0, p1, Lym/j;->s:I

    .line 15
    .line 16
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, ", height="

    .line 2
    .line 3
    const-string v1, ")"

    .line 4
    .line 5
    iget v2, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->b:I

    .line 6
    .line 7
    iget p0, p0, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;->c:I

    .line 8
    .line 9
    const-string v3, "LottieAnimationSizeElement(width="

    .line 10
    .line 11
    invoke-static {v2, p0, v3, v0, v1}, Lf2/m0;->f(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
