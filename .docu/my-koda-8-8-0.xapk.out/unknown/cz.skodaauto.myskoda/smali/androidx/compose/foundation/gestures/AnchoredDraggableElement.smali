.class final Landroidx/compose/foundation/gestures/AnchoredDraggableElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u0000*\u0004\u0008\u0000\u0010\u00012\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00028\u00000\u00030\u0002\u00a8\u0006\u0004"
    }
    d2 = {
        "Landroidx/compose/foundation/gestures/AnchoredDraggableElement;",
        "T",
        "Lv3/z0;",
        "Lg1/m;",
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
.field public final b:Lg1/q;

.field public final c:Z

.field public final d:Lh1/g;


# direct methods
.method public constructor <init>(Lg1/q;ZLh1/g;)V
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->b:Lg1/q;

    .line 7
    .line 8
    iput-boolean p2, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->c:Z

    .line 9
    .line 10
    iput-object p3, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->d:Lh1/g;

    .line 11
    .line 12
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
    instance-of v0, p1, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;

    .line 10
    .line 11
    iget-object v0, p1, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->b:Lg1/q;

    .line 12
    .line 13
    iget-object v1, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->b:Lg1/q;

    .line 14
    .line 15
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_2

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 23
    .line 24
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->c:Z

    .line 25
    .line 26
    iget-boolean v1, p1, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->c:Z

    .line 27
    .line 28
    if-eq v0, v1, :cond_3

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_3
    iget-object p0, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->d:Lh1/g;

    .line 32
    .line 33
    iget-object p1, p1, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->d:Lh1/g;

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
    :goto_0
    const/4 p0, 0x0

    .line 42
    return p0

    .line 43
    :cond_4
    :goto_1
    const/4 p0, 0x1

    .line 44
    return p0
.end method

.method public final h()Lx2/r;
    .locals 5

    .line 1
    new-instance v0, Lg1/m;

    .line 2
    .line 3
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 4
    .line 5
    sget-object v2, Landroidx/compose/foundation/gestures/a;->a:Lfw0/i0;

    .line 6
    .line 7
    iget-boolean v3, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->c:Z

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v2, v3, v4, v1}, Lg1/d1;-><init>(Lay0/k;ZLi1/l;Lg1/w1;)V

    .line 11
    .line 12
    .line 13
    iget-object v2, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->b:Lg1/q;

    .line 14
    .line 15
    iput-object v2, v0, Lg1/m;->C:Lg1/q;

    .line 16
    .line 17
    iput-object v1, v0, Lg1/m;->D:Lg1/w1;

    .line 18
    .line 19
    iget-object p0, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->d:Lh1/g;

    .line 20
    .line 21
    iput-object p0, v0, Lg1/m;->E:Lh1/g;

    .line 22
    .line 23
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->b:Lg1/q;

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
    sget-object v1, Lg1/w1;->e:Lg1/w1;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->c:Z

    .line 19
    .line 20
    const v2, 0x1b4d89f

    .line 21
    .line 22
    .line 23
    invoke-static {v1, v2, v0}, La7/g0;->e(IIZ)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    iget-object p0, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->d:Lh1/g;

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 p0, 0x0

    .line 37
    :goto_0
    add-int/2addr v0, p0

    .line 38
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 6

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg1/m;

    .line 3
    .line 4
    sget-object v4, Lg1/w1;->e:Lg1/w1;

    .line 5
    .line 6
    iget-object p1, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->d:Lh1/g;

    .line 7
    .line 8
    iput-object p1, v0, Lg1/m;->E:Lh1/g;

    .line 9
    .line 10
    iget-object v1, v0, Lg1/m;->C:Lg1/q;

    .line 11
    .line 12
    iget-object v2, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->b:Lg1/q;

    .line 13
    .line 14
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    const/4 v3, 0x1

    .line 19
    if-nez v1, :cond_0

    .line 20
    .line 21
    iput-object v2, v0, Lg1/m;->C:Lg1/q;

    .line 22
    .line 23
    invoke-virtual {v0, p1}, Lg1/m;->l1(Lh1/g;)V

    .line 24
    .line 25
    .line 26
    move p1, v3

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p1, 0x0

    .line 29
    :goto_0
    iget-object v1, v0, Lg1/m;->D:Lg1/w1;

    .line 30
    .line 31
    if-eq v1, v4, :cond_1

    .line 32
    .line 33
    iput-object v4, v0, Lg1/m;->D:Lg1/w1;

    .line 34
    .line 35
    move v5, v3

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v5, p1

    .line 38
    :goto_1
    iget-object v1, v0, Lg1/d1;->u:Lay0/k;

    .line 39
    .line 40
    iget-boolean v2, p0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;->c:Z

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    invoke-virtual/range {v0 .. v5}, Lg1/d1;->i1(Lay0/k;ZLi1/l;Lg1/w1;Z)V

    .line 44
    .line 45
    .line 46
    return-void
.end method
