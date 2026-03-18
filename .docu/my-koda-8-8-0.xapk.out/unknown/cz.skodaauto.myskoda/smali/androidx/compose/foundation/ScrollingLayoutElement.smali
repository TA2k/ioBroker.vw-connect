.class public final Landroidx/compose/foundation/ScrollingLayoutElement;
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
        "Landroidx/compose/foundation/ScrollingLayoutElement;",
        "Lv3/z0;",
        "Le1/k1;",
        "foundation_release"
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
.field public final b:Le1/n1;

.field public final c:Z

.field public final d:Z


# direct methods
.method public constructor <init>(Le1/n1;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->b:Le1/n1;

    .line 5
    .line 6
    iput-boolean p2, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->c:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->d:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Landroidx/compose/foundation/ScrollingLayoutElement;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    check-cast p1, Landroidx/compose/foundation/ScrollingLayoutElement;

    .line 7
    .line 8
    iget-object v0, p1, Landroidx/compose/foundation/ScrollingLayoutElement;->b:Le1/n1;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->b:Le1/n1;

    .line 11
    .line 12
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget-boolean v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->c:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Landroidx/compose/foundation/ScrollingLayoutElement;->c:Z

    .line 21
    .line 22
    if-ne v0, v1, :cond_1

    .line 23
    .line 24
    iget-boolean p0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->d:Z

    .line 25
    .line 26
    iget-boolean p1, p1, Landroidx/compose/foundation/ScrollingLayoutElement;->d:Z

    .line 27
    .line 28
    if-ne p0, p1, :cond_1

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 33
    return p0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Le1/k1;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->b:Le1/n1;

    .line 7
    .line 8
    iput-object v1, v0, Le1/k1;->r:Le1/n1;

    .line 9
    .line 10
    iget-boolean v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->c:Z

    .line 11
    .line 12
    iput-boolean v1, v0, Le1/k1;->s:Z

    .line 13
    .line 14
    iget-boolean p0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->d:Z

    .line 15
    .line 16
    iput-boolean p0, v0, Le1/k1;->t:Z

    .line 17
    .line 18
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->b:Le1/n1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-boolean v2, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->c:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean p0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->d:Z

    .line 17
    .line 18
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    add-int/2addr p0, v0

    .line 23
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 1

    .line 1
    check-cast p1, Le1/k1;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->b:Le1/n1;

    .line 4
    .line 5
    iput-object v0, p1, Le1/k1;->r:Le1/n1;

    .line 6
    .line 7
    iget-boolean v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->c:Z

    .line 8
    .line 9
    iput-boolean v0, p1, Le1/k1;->s:Z

    .line 10
    .line 11
    iget-boolean p0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->d:Z

    .line 12
    .line 13
    iput-boolean p0, p1, Le1/k1;->t:Z

    .line 14
    .line 15
    return-void
.end method
