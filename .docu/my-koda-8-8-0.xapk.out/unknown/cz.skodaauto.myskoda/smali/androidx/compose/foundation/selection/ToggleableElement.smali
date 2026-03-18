.class final Landroidx/compose/foundation/selection/ToggleableElement;
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
        "Landroidx/compose/foundation/selection/ToggleableElement;",
        "Lv3/z0;",
        "Lr1/c;",
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
.field public final b:Z

.field public final c:Li1/l;

.field public final d:Z

.field public final e:Z

.field public final f:Ld4/i;

.field public final g:Lay0/k;


# direct methods
.method public constructor <init>(ZLi1/l;ZZLd4/i;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Landroidx/compose/foundation/selection/ToggleableElement;->b:Z

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/selection/ToggleableElement;->c:Li1/l;

    .line 7
    .line 8
    iput-boolean p3, p0, Landroidx/compose/foundation/selection/ToggleableElement;->d:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Landroidx/compose/foundation/selection/ToggleableElement;->e:Z

    .line 11
    .line 12
    iput-object p5, p0, Landroidx/compose/foundation/selection/ToggleableElement;->f:Ld4/i;

    .line 13
    .line 14
    iput-object p6, p0, Landroidx/compose/foundation/selection/ToggleableElement;->g:Lay0/k;

    .line 15
    .line 16
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
    if-nez p1, :cond_1

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_1
    const-class v0, Landroidx/compose/foundation/selection/ToggleableElement;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-eq v0, v1, :cond_2

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_2
    check-cast p1, Landroidx/compose/foundation/selection/ToggleableElement;

    .line 17
    .line 18
    iget-boolean v0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->b:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Landroidx/compose/foundation/selection/ToggleableElement;->b:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-object v0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->c:Li1/l;

    .line 26
    .line 27
    iget-object v1, p1, Landroidx/compose/foundation/selection/ToggleableElement;->c:Li1/l;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_4

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_4
    iget-boolean v0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->d:Z

    .line 37
    .line 38
    iget-boolean v1, p1, Landroidx/compose/foundation/selection/ToggleableElement;->d:Z

    .line 39
    .line 40
    if-eq v0, v1, :cond_5

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_5
    iget-boolean v0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->e:Z

    .line 44
    .line 45
    iget-boolean v1, p1, Landroidx/compose/foundation/selection/ToggleableElement;->e:Z

    .line 46
    .line 47
    if-eq v0, v1, :cond_6

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_6
    iget-object v0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->f:Ld4/i;

    .line 51
    .line 52
    iget-object v1, p1, Landroidx/compose/foundation/selection/ToggleableElement;->f:Ld4/i;

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ld4/i;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_7

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_7
    iget-object p0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->g:Lay0/k;

    .line 62
    .line 63
    iget-object p1, p1, Landroidx/compose/foundation/selection/ToggleableElement;->g:Lay0/k;

    .line 64
    .line 65
    if-eq p0, p1, :cond_8

    .line 66
    .line 67
    :goto_0
    const/4 p0, 0x0

    .line 68
    return p0

    .line 69
    :cond_8
    :goto_1
    const/4 p0, 0x1

    .line 70
    return p0
.end method

.method public final h()Lx2/r;
    .locals 7

    .line 1
    new-instance v0, Lr1/c;

    .line 2
    .line 3
    iget-object v5, p0, Landroidx/compose/foundation/selection/ToggleableElement;->f:Ld4/i;

    .line 4
    .line 5
    iget-object v6, p0, Landroidx/compose/foundation/selection/ToggleableElement;->g:Lay0/k;

    .line 6
    .line 7
    iget-boolean v1, p0, Landroidx/compose/foundation/selection/ToggleableElement;->b:Z

    .line 8
    .line 9
    iget-object v2, p0, Landroidx/compose/foundation/selection/ToggleableElement;->c:Li1/l;

    .line 10
    .line 11
    iget-boolean v3, p0, Landroidx/compose/foundation/selection/ToggleableElement;->d:Z

    .line 12
    .line 13
    iget-boolean v4, p0, Landroidx/compose/foundation/selection/ToggleableElement;->e:Z

    .line 14
    .line 15
    invoke-direct/range {v0 .. v6}, Lr1/c;-><init>(ZLi1/l;ZZLd4/i;Lay0/k;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->b:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-object v2, p0, Landroidx/compose/foundation/selection/ToggleableElement;->c:Li1/l;

    .line 11
    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v2, 0x0

    .line 20
    :goto_0
    add-int/2addr v0, v2

    .line 21
    mul-int/lit16 v0, v0, 0x3c1

    .line 22
    .line 23
    iget-boolean v2, p0, Landroidx/compose/foundation/selection/ToggleableElement;->d:Z

    .line 24
    .line 25
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-boolean v2, p0, Landroidx/compose/foundation/selection/ToggleableElement;->e:Z

    .line 30
    .line 31
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object v2, p0, Landroidx/compose/foundation/selection/ToggleableElement;->f:Ld4/i;

    .line 36
    .line 37
    iget v2, v2, Ld4/i;->a:I

    .line 38
    .line 39
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget-object p0, p0, Landroidx/compose/foundation/selection/ToggleableElement;->g:Lay0/k;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    add-int/2addr p0, v0

    .line 50
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 8

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lr1/c;

    .line 3
    .line 4
    iget-boolean p1, v0, Lr1/c;->O:Z

    .line 5
    .line 6
    iget-boolean v1, p0, Landroidx/compose/foundation/selection/ToggleableElement;->b:Z

    .line 7
    .line 8
    if-eq p1, v1, :cond_0

    .line 9
    .line 10
    iput-boolean v1, v0, Lr1/c;->O:Z

    .line 11
    .line 12
    invoke-static {v0}, Lv3/f;->o(Lv3/x1;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object p1, p0, Landroidx/compose/foundation/selection/ToggleableElement;->g:Lay0/k;

    .line 16
    .line 17
    iput-object p1, v0, Lr1/c;->P:Lay0/k;

    .line 18
    .line 19
    const/4 v5, 0x0

    .line 20
    iget-object v7, v0, Lr1/c;->Q:Lr1/b;

    .line 21
    .line 22
    iget-object v1, p0, Landroidx/compose/foundation/selection/ToggleableElement;->c:Li1/l;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    iget-boolean v3, p0, Landroidx/compose/foundation/selection/ToggleableElement;->d:Z

    .line 26
    .line 27
    iget-boolean v4, p0, Landroidx/compose/foundation/selection/ToggleableElement;->e:Z

    .line 28
    .line 29
    iget-object v6, p0, Landroidx/compose/foundation/selection/ToggleableElement;->f:Ld4/i;

    .line 30
    .line 31
    invoke-virtual/range {v0 .. v7}, Le1/h;->j1(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method
