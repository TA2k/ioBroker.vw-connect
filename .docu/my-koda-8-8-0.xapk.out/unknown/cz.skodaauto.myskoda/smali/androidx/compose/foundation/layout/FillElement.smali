.class final Landroidx/compose/foundation/layout/FillElement;
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
        "Landroidx/compose/foundation/layout/FillElement;",
        "Lv3/z0;",
        "Lk1/a0;",
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
.field public final b:Lk1/y;

.field public final c:F


# direct methods
.method public constructor <init>(Lk1/y;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/layout/FillElement;->b:Lk1/y;

    .line 5
    .line 6
    iput p2, p0, Landroidx/compose/foundation/layout/FillElement;->c:F

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
    instance-of v1, p1, Landroidx/compose/foundation/layout/FillElement;

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
    check-cast p1, Landroidx/compose/foundation/layout/FillElement;

    .line 12
    .line 13
    iget-object v1, p1, Landroidx/compose/foundation/layout/FillElement;->b:Lk1/y;

    .line 14
    .line 15
    iget-object v3, p0, Landroidx/compose/foundation/layout/FillElement;->b:Lk1/y;

    .line 16
    .line 17
    if-eq v3, v1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget p0, p0, Landroidx/compose/foundation/layout/FillElement;->c:F

    .line 21
    .line 22
    iget p1, p1, Landroidx/compose/foundation/layout/FillElement;->c:F

    .line 23
    .line 24
    cmpg-float p0, p0, p1

    .line 25
    .line 26
    if-nez p0, :cond_3

    .line 27
    .line 28
    return v0

    .line 29
    :cond_3
    return v2
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Lk1/a0;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/compose/foundation/layout/FillElement;->b:Lk1/y;

    .line 7
    .line 8
    iput-object v1, v0, Lk1/a0;->r:Lk1/y;

    .line 9
    .line 10
    iget p0, p0, Landroidx/compose/foundation/layout/FillElement;->c:F

    .line 11
    .line 12
    iput p0, v0, Lk1/a0;->s:F

    .line 13
    .line 14
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/layout/FillElement;->b:Lk1/y;

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
    iget p0, p0, Landroidx/compose/foundation/layout/FillElement;->c:F

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

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
    check-cast p1, Lk1/a0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/foundation/layout/FillElement;->b:Lk1/y;

    .line 4
    .line 5
    iput-object v0, p1, Lk1/a0;->r:Lk1/y;

    .line 6
    .line 7
    iget p0, p0, Landroidx/compose/foundation/layout/FillElement;->c:F

    .line 8
    .line 9
    iput p0, p1, Lk1/a0;->s:F

    .line 10
    .line 11
    return-void
.end method
