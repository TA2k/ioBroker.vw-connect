.class final Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;
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
        "Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;",
        "Lv3/z0;",
        "Le3/n;",
        "ui_release"
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
.field public final b:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;->b:Lay0/k;

    .line 5
    .line 6
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
    instance-of v1, p1, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;

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
    check-cast p1, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;

    .line 12
    .line 13
    iget-object p1, p1, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;->b:Lay0/k;

    .line 14
    .line 15
    iget-object p0, p0, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;->b:Lay0/k;

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public final h()Lx2/r;
    .locals 1

    .line 1
    new-instance v0, Le3/n;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;->b:Lay0/k;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Le3/n;-><init>(Lay0/k;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;->b:Lay0/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 1

    .line 1
    check-cast p1, Le3/n;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/compose/ui/graphics/BlockGraphicsLayerElement;->b:Lay0/k;

    .line 4
    .line 5
    iput-object p0, p1, Le3/n;->r:Lay0/k;

    .line 6
    .line 7
    const/4 p0, 0x2

    .line 8
    invoke-static {p1, p0}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    iget-object p0, p0, Lv3/f1;->s:Lv3/f1;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    iget-object p1, p1, Le3/n;->r:Lay0/k;

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    invoke-virtual {p0, p1, v0}, Lv3/f1;->E1(Lay0/k;Z)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method
