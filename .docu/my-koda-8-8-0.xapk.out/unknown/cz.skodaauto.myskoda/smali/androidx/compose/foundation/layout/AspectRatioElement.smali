.class final Landroidx/compose/foundation/layout/AspectRatioElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/layout/AspectRatioElement;",
        "Lv3/z0;",
        "Lk1/k;",
        "foundation-layout"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:F

.field public final c:Z


# direct methods
.method public constructor <init>(FZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->b:F

    .line 5
    .line 6
    iput-boolean p2, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->c:Z

    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    cmpl-float p0, p1, p0

    .line 10
    .line 11
    if-lez p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string p2, "aspectRatio "

    .line 17
    .line 18
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p1, " must be > 0"

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-static {p0}, Ll1/a;->a(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Landroidx/compose/foundation/layout/AspectRatioElement;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Landroidx/compose/foundation/layout/AspectRatioElement;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 v0, 0x0

    .line 13
    :goto_0
    if-nez v0, :cond_2

    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_2
    iget v1, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->b:F

    .line 17
    .line 18
    iget v0, v0, Landroidx/compose/foundation/layout/AspectRatioElement;->b:F

    .line 19
    .line 20
    cmpg-float v0, v1, v0

    .line 21
    .line 22
    if-nez v0, :cond_3

    .line 23
    .line 24
    check-cast p1, Landroidx/compose/foundation/layout/AspectRatioElement;

    .line 25
    .line 26
    iget-boolean p1, p1, Landroidx/compose/foundation/layout/AspectRatioElement;->c:Z

    .line 27
    .line 28
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->c:Z

    .line 29
    .line 30
    if-ne p0, p1, :cond_3

    .line 31
    .line 32
    :goto_1
    const/4 p0, 0x1

    .line 33
    return p0

    .line 34
    :cond_3
    :goto_2
    const/4 p0, 0x0

    .line 35
    return p0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Lk1/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->b:F

    .line 7
    .line 8
    iput v1, v0, Lk1/k;->r:F

    .line 9
    .line 10
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->c:Z

    .line 11
    .line 12
    iput-boolean p0, v0, Lk1/k;->s:Z

    .line 13
    .line 14
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->b:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->c:Z

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    check-cast p1, Lk1/k;

    .line 2
    .line 3
    iget v0, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->b:F

    .line 4
    .line 5
    iput v0, p1, Lk1/k;->r:F

    .line 6
    .line 7
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/AspectRatioElement;->c:Z

    .line 8
    .line 9
    iput-boolean p0, p1, Lk1/k;->s:Z

    .line 10
    .line 11
    return-void
.end method
