.class public final Ly9/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt7/j0;
.implements Landroid/view/View$OnClickListener;
.implements Ly9/q;
.implements Ly9/h;


# instance fields
.field public final d:Lt7/n0;

.field public e:Ljava/lang/Object;

.field public final synthetic f:Landroidx/media3/ui/PlayerView;


# direct methods
.method public constructor <init>(Landroidx/media3/ui/PlayerView;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 5
    .line 6
    new-instance p1, Lt7/n0;

    .line 7
    .line 8
    invoke-direct {p1}, Lt7/n0;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Ly9/y;->d:Lt7/n0;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final D(Lt7/w0;)V
    .locals 7

    .line 1
    iget-object p1, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 2
    .line 3
    iget-object v0, p1, Landroidx/media3/ui/PlayerView;->v:Lt7/l0;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lap0/o;

    .line 10
    .line 11
    const/16 v2, 0x11

    .line 12
    .line 13
    invoke-virtual {v1, v2}, Lap0/o;->I(I)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    move-object v2, v0

    .line 20
    check-cast v2, La8/i0;

    .line 21
    .line 22
    invoke-virtual {v2}, La8/i0;->k0()Lt7/p0;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    sget-object v2, Lt7/p0;->a:Lt7/m0;

    .line 28
    .line 29
    :goto_0
    invoke-virtual {v2}, Lt7/p0;->p()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    const/4 v4, 0x0

    .line 34
    const/4 v5, 0x0

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    iput-object v5, p0, Ly9/y;->e:Ljava/lang/Object;

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_1
    const/16 v3, 0x1e

    .line 41
    .line 42
    invoke-virtual {v1, v3}, Lap0/o;->I(I)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    iget-object v3, p0, Ly9/y;->d:Lt7/n0;

    .line 47
    .line 48
    if-eqz v1, :cond_3

    .line 49
    .line 50
    move-object v1, v0

    .line 51
    check-cast v1, La8/i0;

    .line 52
    .line 53
    invoke-virtual {v1}, La8/i0;->l0()Lt7/w0;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    iget-object v6, v6, Lt7/w0;->a:Lhr/h0;

    .line 58
    .line 59
    invoke-virtual {v6}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-nez v6, :cond_3

    .line 64
    .line 65
    invoke-virtual {v1}, La8/i0;->L0()V

    .line 66
    .line 67
    .line 68
    iget-object v0, v1, La8/i0;->y1:La8/i1;

    .line 69
    .line 70
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 71
    .line 72
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_2

    .line 77
    .line 78
    move v0, v4

    .line 79
    goto :goto_1

    .line 80
    :cond_2
    iget-object v0, v1, La8/i0;->y1:La8/i1;

    .line 81
    .line 82
    iget-object v1, v0, La8/i1;->a:Lt7/p0;

    .line 83
    .line 84
    iget-object v0, v0, La8/i1;->b:Lh8/b0;

    .line 85
    .line 86
    iget-object v0, v0, Lh8/b0;->a:Ljava/lang/Object;

    .line 87
    .line 88
    invoke-virtual {v1, v0}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    :goto_1
    const/4 v1, 0x1

    .line 93
    invoke-virtual {v2, v0, v3, v1}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v0, v0, Lt7/n0;->b:Ljava/lang/Object;

    .line 98
    .line 99
    iput-object v0, p0, Ly9/y;->e:Ljava/lang/Object;

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_3
    iget-object v1, p0, Ly9/y;->e:Ljava/lang/Object;

    .line 103
    .line 104
    if-eqz v1, :cond_5

    .line 105
    .line 106
    invoke-virtual {v2, v1}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    const/4 v6, -0x1

    .line 111
    if-eq v1, v6, :cond_4

    .line 112
    .line 113
    invoke-virtual {v2, v1, v3, v4}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    iget v1, v1, Lt7/n0;->c:I

    .line 118
    .line 119
    check-cast v0, La8/i0;

    .line 120
    .line 121
    invoke-virtual {v0}, La8/i0;->h0()I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-ne v0, v1, :cond_4

    .line 126
    .line 127
    return-void

    .line 128
    :cond_4
    iput-object v5, p0, Ly9/y;->e:Ljava/lang/Object;

    .line 129
    .line 130
    :cond_5
    :goto_2
    invoke-virtual {p1, v4}, Landroidx/media3/ui/PlayerView;->o(Z)V

    .line 131
    .line 132
    .line 133
    return-void
.end method

.method public final a(Lt7/a1;)V
    .locals 1

    .line 1
    sget-object v0, Lt7/a1;->d:Lt7/a1;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_1

    .line 8
    .line 9
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 10
    .line 11
    iget-object p1, p0, Landroidx/media3/ui/PlayerView;->v:Lt7/l0;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    check-cast p1, La8/i0;

    .line 16
    .line 17
    invoke-virtual {p1}, La8/i0;->o0()I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    const/4 v0, 0x1

    .line 22
    if-ne p1, v0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->k()V

    .line 26
    .line 27
    .line 28
    :cond_1
    :goto_0
    return-void
.end method

.method public final i(I)V
    .locals 0

    .line 1
    sget p1, Landroidx/media3/ui/PlayerView;->J:I

    .line 2
    .line 3
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->l()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->n()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->e()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p1, :cond_1

    .line 16
    .line 17
    iget-boolean p1, p0, Landroidx/media3/ui/PlayerView;->G:Z

    .line 18
    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    iget-object p0, p0, Landroidx/media3/ui/PlayerView;->o:Ly9/r;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ly9/r;->g()V

    .line 26
    .line 27
    .line 28
    :cond_0
    return-void

    .line 29
    :cond_1
    const/4 p1, 0x0

    .line 30
    invoke-virtual {p0, p1}, Landroidx/media3/ui/PlayerView;->f(Z)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final k(Lv7/c;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/media3/ui/PlayerView;->l:Landroidx/media3/ui/SubtitleView;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    iget-object p1, p1, Lv7/c;->a:Lhr/x0;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Landroidx/media3/ui/SubtitleView;->setCues(Ljava/util/List;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final onClick(Landroid/view/View;)V
    .locals 0

    .line 1
    sget p1, Landroidx/media3/ui/PlayerView;->J:I

    .line 2
    .line 3
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->j()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final q(ILt7/k0;Lt7/k0;)V
    .locals 0

    .line 1
    sget p1, Landroidx/media3/ui/PlayerView;->J:I

    .line 2
    .line 3
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->e()Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    iget-boolean p1, p0, Landroidx/media3/ui/PlayerView;->G:Z

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Landroidx/media3/ui/PlayerView;->o:Ly9/r;

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0}, Ly9/r;->g()V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method public final r()V
    .locals 2

    .line 1
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/media3/ui/PlayerView;->f:Landroid/view/View;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    const/4 v1, 0x4

    .line 8
    invoke-virtual {v0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->b()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Landroidx/media3/ui/PlayerView;->j:Landroid/widget/ImageView;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, v1}, Landroid/widget/ImageView;->setVisibility(I)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->d()V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final u(II)V
    .locals 3

    .line 1
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 2
    .line 3
    iget-object p1, p0, Landroidx/media3/ui/PlayerView;->g:Landroid/view/View;

    .line 4
    .line 5
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 6
    .line 7
    const/16 v0, 0x22

    .line 8
    .line 9
    if-ne p2, v0, :cond_0

    .line 10
    .line 11
    instance-of p2, p1, Landroid/view/SurfaceView;

    .line 12
    .line 13
    if-eqz p2, :cond_0

    .line 14
    .line 15
    iget-boolean p2, p0, Landroidx/media3/ui/PlayerView;->I:Z

    .line 16
    .line 17
    if-eqz p2, :cond_0

    .line 18
    .line 19
    iget-object p2, p0, Landroidx/media3/ui/PlayerView;->i:Lpv/g;

    .line 20
    .line 21
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Landroidx/media3/ui/PlayerView;->r:Landroid/os/Handler;

    .line 25
    .line 26
    check-cast p1, Landroid/view/SurfaceView;

    .line 27
    .line 28
    new-instance v1, Lm8/o;

    .line 29
    .line 30
    const/16 v2, 0x1d

    .line 31
    .line 32
    invoke-direct {v1, p0, v2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    new-instance p0, La8/y0;

    .line 36
    .line 37
    const/16 v2, 0x1b

    .line 38
    .line 39
    invoke-direct {p0, p2, p1, v1, v2}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, p0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 43
    .line 44
    .line 45
    :cond_0
    return-void
.end method

.method public final x(IZ)V
    .locals 0

    .line 1
    sget p1, Landroidx/media3/ui/PlayerView;->J:I

    .line 2
    .line 3
    iget-object p0, p0, Ly9/y;->f:Landroidx/media3/ui/PlayerView;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->l()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/media3/ui/PlayerView;->e()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-boolean p1, p0, Landroidx/media3/ui/PlayerView;->G:Z

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    iget-object p0, p0, Landroidx/media3/ui/PlayerView;->o:Ly9/r;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Ly9/r;->g()V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void

    .line 26
    :cond_1
    const/4 p1, 0x0

    .line 27
    invoke-virtual {p0, p1}, Landroidx/media3/ui/PlayerView;->f(Z)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
