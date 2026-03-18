.class public final Landroidx/compose/foundation/layout/HorizontalAlignElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/layout/HorizontalAlignElement;",
        "Lv3/z0;",
        "Lk1/l0;",
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
.field public final b:Lx2/h;


# direct methods
.method public constructor <init>(Lx2/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/layout/HorizontalAlignElement;->b:Lx2/h;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Landroidx/compose/foundation/layout/HorizontalAlignElement;

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
    const/4 p0, 0x0

    .line 16
    return p0

    .line 17
    :cond_2
    iget-object p0, p0, Landroidx/compose/foundation/layout/HorizontalAlignElement;->b:Lx2/h;

    .line 18
    .line 19
    iget-object p1, p1, Landroidx/compose/foundation/layout/HorizontalAlignElement;->b:Lx2/h;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lx2/h;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public final h()Lx2/r;
    .locals 1

    .line 1
    new-instance v0, Lk1/l0;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/compose/foundation/layout/HorizontalAlignElement;->b:Lx2/h;

    .line 7
    .line 8
    iput-object p0, v0, Lk1/l0;->r:Lx2/h;

    .line 9
    .line 10
    return-object v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/layout/HorizontalAlignElement;->b:Lx2/h;

    .line 2
    .line 3
    iget p0, p0, Lx2/h;->a:F

    .line 4
    .line 5
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 0

    .line 1
    check-cast p1, Lk1/l0;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/compose/foundation/layout/HorizontalAlignElement;->b:Lx2/h;

    .line 4
    .line 5
    iput-object p0, p1, Lk1/l0;->r:Lx2/h;

    .line 6
    .line 7
    return-void
.end method
