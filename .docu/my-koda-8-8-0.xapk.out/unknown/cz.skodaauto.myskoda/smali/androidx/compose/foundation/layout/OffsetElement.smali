.class final Landroidx/compose/foundation/layout/OffsetElement;
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
        "Landroidx/compose/foundation/layout/OffsetElement;",
        "Lv3/z0;",
        "Lk1/w0;",
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

.field public final c:F


# direct methods
.method public constructor <init>(FFLjy/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Landroidx/compose/foundation/layout/OffsetElement;->b:F

    .line 5
    .line 6
    iput p2, p0, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/layout/OffsetElement;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Landroidx/compose/foundation/layout/OffsetElement;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 p1, 0x0

    .line 13
    :goto_0
    if-nez p1, :cond_2

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_2
    iget v1, p0, Landroidx/compose/foundation/layout/OffsetElement;->b:F

    .line 17
    .line 18
    iget v2, p1, Landroidx/compose/foundation/layout/OffsetElement;->b:F

    .line 19
    .line 20
    invoke-static {v1, v2}, Lt4/f;->a(FF)Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_3

    .line 25
    .line 26
    iget p0, p0, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 27
    .line 28
    iget p1, p1, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 29
    .line 30
    invoke-static {p0, p1}, Lt4/f;->a(FF)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_3

    .line 35
    .line 36
    return v0

    .line 37
    :cond_3
    :goto_1
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Lk1/w0;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, p0, Landroidx/compose/foundation/layout/OffsetElement;->b:F

    .line 7
    .line 8
    iput v1, v0, Lk1/w0;->r:F

    .line 9
    .line 10
    iget p0, p0, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 11
    .line 12
    iput p0, v0, Lk1/w0;->s:F

    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    iput-boolean p0, v0, Lk1/w0;->t:Z

    .line 16
    .line 17
    return-object v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Landroidx/compose/foundation/layout/OffsetElement;->b:F

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
    iget p0, p0, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 11
    .line 12
    invoke-static {p0, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    const/4 v0, 0x1

    .line 17
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    add-int/2addr v0, p0

    .line 22
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 4

    .line 1
    check-cast p1, Lk1/w0;

    .line 2
    .line 3
    iget v0, p1, Lk1/w0;->r:F

    .line 4
    .line 5
    iget v1, p0, Landroidx/compose/foundation/layout/OffsetElement;->b:F

    .line 6
    .line 7
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget p0, p0, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget v0, p1, Lk1/w0;->s:F

    .line 17
    .line 18
    invoke-static {v0, p0}, Lt4/f;->a(FF)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget-boolean v0, p1, Lk1/w0;->t:Z

    .line 25
    .line 26
    if-eq v0, v2, :cond_1

    .line 27
    .line 28
    :cond_0
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const/4 v3, 0x0

    .line 33
    invoke-virtual {v0, v3}, Lv3/h0;->X(Z)V

    .line 34
    .line 35
    .line 36
    :cond_1
    iput v1, p1, Lk1/w0;->r:F

    .line 37
    .line 38
    iput p0, p1, Lk1/w0;->s:F

    .line 39
    .line 40
    iput-boolean v2, p1, Lk1/w0;->t:Z

    .line 41
    .line 42
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "OffsetModifierElement(x="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Landroidx/compose/foundation/layout/OffsetElement;->b:F

    .line 9
    .line 10
    const-string v2, ", y="

    .line 11
    .line 12
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->t(FLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 13
    .line 14
    .line 15
    iget p0, p0, Landroidx/compose/foundation/layout/OffsetElement;->c:F

    .line 16
    .line 17
    invoke-static {p0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p0, ", rtlAware=true)"

    .line 25
    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method
