.class final Landroidx/compose/foundation/layout/BoxChildDataElement;
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
        "Landroidx/compose/foundation/layout/BoxChildDataElement;",
        "Lv3/z0;",
        "Lk1/l;",
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
.field public final b:Lx2/e;

.field public final c:Z


# direct methods
.method public constructor <init>(Lx2/e;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->b:Lx2/e;

    .line 5
    .line 6
    iput-boolean p2, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->c:Z

    .line 7
    .line 8
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
    instance-of v0, p1, Landroidx/compose/foundation/layout/BoxChildDataElement;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p1, Landroidx/compose/foundation/layout/BoxChildDataElement;

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_1
    const/4 p1, 0x0

    .line 12
    :goto_0
    if-nez p1, :cond_2

    .line 13
    .line 14
    goto :goto_2

    .line 15
    :cond_2
    iget-object v0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->b:Lx2/e;

    .line 16
    .line 17
    iget-object v1, p1, Landroidx/compose/foundation/layout/BoxChildDataElement;->b:Lx2/e;

    .line 18
    .line 19
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_3

    .line 24
    .line 25
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->c:Z

    .line 26
    .line 27
    iget-boolean p1, p1, Landroidx/compose/foundation/layout/BoxChildDataElement;->c:Z

    .line 28
    .line 29
    if-ne p0, p1, :cond_3

    .line 30
    .line 31
    :goto_1
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_3
    :goto_2
    const/4 p0, 0x0

    .line 34
    return p0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Lk1/l;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->b:Lx2/e;

    .line 7
    .line 8
    iput-object v1, v0, Lk1/l;->r:Lx2/e;

    .line 9
    .line 10
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->c:Z

    .line 11
    .line 12
    iput-boolean p0, v0, Lk1/l;->s:Z

    .line 13
    .line 14
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->b:Lx2/e;

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
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->c:Z

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
    check-cast p1, Lk1/l;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->b:Lx2/e;

    .line 4
    .line 5
    iput-object v0, p1, Lk1/l;->r:Lx2/e;

    .line 6
    .line 7
    iget-boolean p0, p0, Landroidx/compose/foundation/layout/BoxChildDataElement;->c:Z

    .line 8
    .line 9
    iput-boolean p0, p1, Lk1/l;->s:Z

    .line 10
    .line 11
    return-void
.end method
