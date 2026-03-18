.class public final Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;
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
        "Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;",
        "Lv3/z0;",
        "Lj2/o;",
        "material3"
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

.field public final c:Lay0/a;

.field public final d:Lj2/p;

.field public final e:F


# direct methods
.method public constructor <init>(ZLay0/a;Lj2/p;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->b:Z

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->c:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->d:Lj2/p;

    .line 9
    .line 10
    iput p4, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->e:F

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
    instance-of v0, p1, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;

    .line 10
    .line 11
    iget-boolean v0, p1, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->b:Z

    .line 12
    .line 13
    iget-boolean v1, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->b:Z

    .line 14
    .line 15
    if-eq v1, v0, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-object v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->c:Lay0/a;

    .line 19
    .line 20
    iget-object v1, p1, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->c:Lay0/a;

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-object v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->d:Lj2/p;

    .line 26
    .line 27
    iget-object v1, p1, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->d:Lj2/p;

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
    iget p0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->e:F

    .line 37
    .line 38
    iget p1, p1, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->e:F

    .line 39
    .line 40
    invoke-static {p0, p1}, Lt4/f;->a(FF)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-nez p0, :cond_5

    .line 45
    .line 46
    :goto_0
    const/4 p0, 0x0

    .line 47
    return p0

    .line 48
    :cond_5
    :goto_1
    const/4 p0, 0x1

    .line 49
    return p0
.end method

.method public final h()Lx2/r;
    .locals 4

    .line 1
    new-instance v0, Lj2/o;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->d:Lj2/p;

    .line 4
    .line 5
    iget v2, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->e:F

    .line 6
    .line 7
    iget-boolean v3, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->b:Z

    .line 8
    .line 9
    iget-object p0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->c:Lay0/a;

    .line 10
    .line 11
    invoke-direct {v0, v3, p0, v1, v2}, Lj2/o;-><init>(ZLay0/a;Lj2/p;F)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->b:Z

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
    const/4 v2, 0x1

    .line 11
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iget-object v2, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->c:Lay0/a;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    add-int/2addr v2, v0

    .line 22
    mul-int/2addr v2, v1

    .line 23
    iget-object v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->d:Lj2/p;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    add-int/2addr v0, v2

    .line 30
    mul-int/2addr v0, v1

    .line 31
    iget p0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->e:F

    .line 32
    .line 33
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    add-int/2addr p0, v0

    .line 38
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 3

    .line 1
    check-cast p1, Lj2/o;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->c:Lay0/a;

    .line 4
    .line 5
    iput-object v0, p1, Lj2/o;->u:Lay0/a;

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p1, Lj2/o;->v:Z

    .line 9
    .line 10
    iget-object v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->d:Lj2/p;

    .line 11
    .line 12
    iput-object v0, p1, Lj2/o;->w:Lj2/p;

    .line 13
    .line 14
    iget v0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->e:F

    .line 15
    .line 16
    iput v0, p1, Lj2/o;->x:F

    .line 17
    .line 18
    iget-boolean v0, p1, Lj2/o;->t:Z

    .line 19
    .line 20
    iget-boolean p0, p0, Landroidx/compose/material3/pulltorefresh/PullToRefreshElement;->b:Z

    .line 21
    .line 22
    if-eq v0, p0, :cond_0

    .line 23
    .line 24
    iput-boolean p0, p1, Lj2/o;->t:Z

    .line 25
    .line 26
    invoke-virtual {p1}, Lx2/r;->L0()Lvy0/b0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    new-instance v0, Lj2/l;

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    const/4 v2, 0x0

    .line 34
    invoke-direct {v0, p1, v2, v1}, Lj2/l;-><init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p1, 0x3

    .line 38
    invoke-static {p0, v2, v2, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    :cond_0
    return-void
.end method
