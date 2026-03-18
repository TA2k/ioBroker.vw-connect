.class public final Ljl/h;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# instance fields
.field public i:Lpw0/a;

.field public final j:Lyy0/c2;

.field public final k:Ll2/j1;

.field public final l:Ll2/f1;

.field public final m:Ll2/j1;

.field public n:Ljl/f;

.field public o:Li3/c;

.field public p:Lay0/k;

.field public q:Lt3/k;

.field public r:I

.field public s:Z

.field public final t:Ll2/j1;

.field public final u:Ll2/j1;

.field public final v:Ll2/j1;


# direct methods
.method public constructor <init>(Ltl/h;Lil/j;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ld3/e;

    .line 5
    .line 6
    const-wide/16 v1, 0x0

    .line 7
    .line 8
    invoke-direct {v0, v1, v2}, Ld3/e;-><init>(J)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Ljl/h;->j:Lyy0/c2;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iput-object v1, p0, Ljl/h;->k:Ll2/j1;

    .line 23
    .line 24
    new-instance v1, Ll2/f1;

    .line 25
    .line 26
    const/high16 v2, 0x3f800000    # 1.0f

    .line 27
    .line 28
    invoke-direct {v1, v2}, Ll2/f1;-><init>(F)V

    .line 29
    .line 30
    .line 31
    iput-object v1, p0, Ljl/h;->l:Ll2/f1;

    .line 32
    .line 33
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    iput-object v0, p0, Ljl/h;->m:Ll2/j1;

    .line 38
    .line 39
    sget-object v0, Ljl/b;->a:Ljl/b;

    .line 40
    .line 41
    iput-object v0, p0, Ljl/h;->n:Ljl/f;

    .line 42
    .line 43
    sget-object v1, Ljl/a;->f:Ljl/a;

    .line 44
    .line 45
    iput-object v1, p0, Ljl/h;->p:Lay0/k;

    .line 46
    .line 47
    sget-object v1, Lt3/j;->b:Lt3/x0;

    .line 48
    .line 49
    iput-object v1, p0, Ljl/h;->q:Lt3/k;

    .line 50
    .line 51
    const/4 v1, 0x1

    .line 52
    iput v1, p0, Ljl/h;->r:I

    .line 53
    .line 54
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iput-object v0, p0, Ljl/h;->t:Ll2/j1;

    .line 59
    .line 60
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iput-object p1, p0, Ljl/h;->u:Ll2/j1;

    .line 65
    .line 66
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Ljl/h;->v:Ll2/j1;

    .line 71
    .line 72
    return-void
.end method


# virtual methods
.method public final a(F)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ljl/h;->l:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0
.end method

.method public final b(Le3/m;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ljl/h;->m:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0
.end method

.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Ljl/h;->i:Lpw0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 11
    .line 12
    sget-object v1, Laz0/m;->a:Lwy0/c;

    .line 13
    .line 14
    iget-object v1, v1, Lwy0/c;->h:Lwy0/c;

    .line 15
    .line 16
    invoke-static {v0, v1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Ljl/h;->i:Lpw0/a;

    .line 25
    .line 26
    iget-object v1, p0, Ljl/h;->o:Li3/c;

    .line 27
    .line 28
    instance-of v2, v1, Ll2/z1;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    check-cast v1, Ll2/z1;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move-object v1, v3

    .line 37
    :goto_0
    if-eqz v1, :cond_2

    .line 38
    .line 39
    invoke-interface {v1}, Ll2/z1;->c()V

    .line 40
    .line 41
    .line 42
    :cond_2
    iget-boolean v1, p0, Ljl/h;->s:Z

    .line 43
    .line 44
    if-eqz v1, :cond_3

    .line 45
    .line 46
    iget-object v0, p0, Ljl/h;->u:Ll2/j1;

    .line 47
    .line 48
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Ltl/h;

    .line 53
    .line 54
    invoke-static {v0}, Ltl/h;->a(Ltl/h;)Ltl/g;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iget-object v1, p0, Ljl/h;->v:Ll2/j1;

    .line 59
    .line 60
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Lil/j;

    .line 65
    .line 66
    iget-object v1, v1, Lil/j;->a:Ltl/b;

    .line 67
    .line 68
    iput-object v1, v0, Ltl/g;->b:Ltl/b;

    .line 69
    .line 70
    iput-object v3, v0, Ltl/g;->q:Lul/f;

    .line 71
    .line 72
    invoke-virtual {v0}, Ltl/g;->a()Ltl/h;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    new-instance v1, Ljl/d;

    .line 77
    .line 78
    iget-object v0, v0, Ltl/h;->z:Ltl/b;

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 81
    .line 82
    .line 83
    sget-object v0, Lxl/b;->a:Ltl/b;

    .line 84
    .line 85
    invoke-direct {v1, v3}, Ljl/d;-><init>(Li3/c;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p0, v1}, Ljl/h;->k(Ljl/f;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_3
    new-instance v1, Lh40/h;

    .line 93
    .line 94
    const/16 v2, 0x18

    .line 95
    .line 96
    invoke-direct {v1, p0, v3, v2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 97
    .line 98
    .line 99
    const/4 p0, 0x3

    .line 100
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 101
    .line 102
    .line 103
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Ljl/h;->i:Lpw0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-static {v0, v1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iput-object v1, p0, Ljl/h;->i:Lpw0/a;

    .line 10
    .line 11
    iget-object p0, p0, Ljl/h;->o:Li3/c;

    .line 12
    .line 13
    instance-of v0, p0, Ll2/z1;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    move-object v1, p0

    .line 18
    check-cast v1, Ll2/z1;

    .line 19
    .line 20
    :cond_1
    if-eqz v1, :cond_2

    .line 21
    .line 22
    invoke-interface {v1}, Ll2/z1;->e()V

    .line 23
    .line 24
    .line 25
    :cond_2
    return-void
.end method

.method public final g()J
    .locals 2

    .line 1
    iget-object p0, p0, Ljl/h;->k:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li3/c;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Li3/c;->g()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    return-wide v0

    .line 16
    :cond_0
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    return-wide v0
.end method

.method public final h()V
    .locals 2

    .line 1
    iget-object v0, p0, Ljl/h;->i:Lpw0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-static {v0, v1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iput-object v1, p0, Ljl/h;->i:Lpw0/a;

    .line 10
    .line 11
    iget-object p0, p0, Ljl/h;->o:Li3/c;

    .line 12
    .line 13
    instance-of v0, p0, Ll2/z1;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    move-object v1, p0

    .line 18
    check-cast v1, Ll2/z1;

    .line 19
    .line 20
    :cond_1
    if-eqz v1, :cond_2

    .line 21
    .line 22
    invoke-interface {v1}, Ll2/z1;->h()V

    .line 23
    .line 24
    .line 25
    :cond_2
    return-void
.end method

.method public final i(Lg3/d;)V
    .locals 7

    .line 1
    invoke-interface {p1}, Lg3/d;->e()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    new-instance v2, Ld3/e;

    .line 6
    .line 7
    invoke-direct {v2, v0, v1}, Ld3/e;-><init>(J)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Ljl/h;->j:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Ljl/h;->k:Ll2/j1;

    .line 20
    .line 21
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    move-object v1, v0

    .line 26
    check-cast v1, Li3/c;

    .line 27
    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    invoke-interface {p1}, Lg3/d;->e()J

    .line 31
    .line 32
    .line 33
    move-result-wide v3

    .line 34
    iget-object v0, p0, Ljl/h;->l:Ll2/f1;

    .line 35
    .line 36
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 37
    .line 38
    .line 39
    move-result v5

    .line 40
    iget-object p0, p0, Ljl/h;->m:Ll2/j1;

    .line 41
    .line 42
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    move-object v6, p0

    .line 47
    check-cast v6, Le3/m;

    .line 48
    .line 49
    move-object v2, p1

    .line 50
    invoke-virtual/range {v1 .. v6}, Li3/c;->f(Lg3/d;JFLe3/m;)V

    .line 51
    .line 52
    .line 53
    :cond_0
    return-void
.end method

.method public final j(Landroid/graphics/drawable/Drawable;)Li3/c;
    .locals 1

    .line 1
    instance-of v0, p1, Landroid/graphics/drawable/BitmapDrawable;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Landroid/graphics/drawable/BitmapDrawable;

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    new-instance v0, Le3/f;

    .line 12
    .line 13
    invoke-direct {v0, p1}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 14
    .line 15
    .line 16
    iget p0, p0, Ljl/h;->r:I

    .line 17
    .line 18
    invoke-static {v0, p0}, Llp/t1;->a(Le3/f;I)Li3/a;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_0
    new-instance p0, Lln/a;

    .line 24
    .line 25
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-direct {p0, p1}, Lln/a;-><init>(Landroid/graphics/drawable/Drawable;)V

    .line 30
    .line 31
    .line 32
    return-object p0
.end method

.method public final k(Ljl/f;)V
    .locals 12

    .line 1
    iget-object v0, p0, Ljl/h;->n:Ljl/f;

    .line 2
    .line 3
    iget-object v1, p0, Ljl/h;->p:Lay0/k;

    .line 4
    .line 5
    invoke-interface {v1, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Ljl/f;

    .line 10
    .line 11
    iput-object p1, p0, Ljl/h;->n:Ljl/f;

    .line 12
    .line 13
    iget-object v1, p0, Ljl/h;->t:Ll2/j1;

    .line 14
    .line 15
    invoke-virtual {v1, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    instance-of v1, p1, Ljl/e;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    move-object v1, p1

    .line 24
    check-cast v1, Ljl/e;

    .line 25
    .line 26
    iget-object v1, v1, Ljl/e;->b:Ltl/n;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    instance-of v1, p1, Ljl/c;

    .line 30
    .line 31
    if-eqz v1, :cond_4

    .line 32
    .line 33
    move-object v1, p1

    .line 34
    check-cast v1, Ljl/c;

    .line 35
    .line 36
    iget-object v1, v1, Ljl/c;->b:Ltl/d;

    .line 37
    .line 38
    :goto_0
    invoke-virtual {v1}, Ltl/i;->b()Ltl/h;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    iget-object v3, v3, Ltl/h;->g:Lwl/e;

    .line 43
    .line 44
    sget-object v4, Ljl/j;->a:Ljl/i;

    .line 45
    .line 46
    invoke-interface {v3, v4, v1}, Lwl/e;->a(Ljl/i;Ltl/i;)Lwl/f;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    instance-of v4, v3, Lwl/b;

    .line 51
    .line 52
    if-eqz v4, :cond_4

    .line 53
    .line 54
    invoke-virtual {v0}, Ljl/f;->a()Li3/c;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    instance-of v5, v0, Ljl/d;

    .line 59
    .line 60
    if-eqz v5, :cond_1

    .line 61
    .line 62
    move-object v7, v4

    .line 63
    goto :goto_1

    .line 64
    :cond_1
    move-object v7, v2

    .line 65
    :goto_1
    invoke-virtual {p1}, Ljl/f;->a()Li3/c;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    iget-object v9, p0, Ljl/h;->q:Lt3/k;

    .line 70
    .line 71
    check-cast v3, Lwl/b;

    .line 72
    .line 73
    iget v10, v3, Lwl/b;->c:I

    .line 74
    .line 75
    instance-of v3, v1, Ltl/n;

    .line 76
    .line 77
    if-eqz v3, :cond_3

    .line 78
    .line 79
    check-cast v1, Ltl/n;

    .line 80
    .line 81
    iget-boolean v1, v1, Ltl/n;->g:Z

    .line 82
    .line 83
    if-nez v1, :cond_2

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_2
    const/4 v1, 0x0

    .line 87
    :goto_2
    move v11, v1

    .line 88
    goto :goto_4

    .line 89
    :cond_3
    :goto_3
    const/4 v1, 0x1

    .line 90
    goto :goto_2

    .line 91
    :goto_4
    new-instance v6, Ljl/k;

    .line 92
    .line 93
    invoke-direct/range {v6 .. v11}, Ljl/k;-><init>(Li3/c;Li3/c;Lt3/k;IZ)V

    .line 94
    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_4
    move-object v6, v2

    .line 98
    :goto_5
    if-eqz v6, :cond_5

    .line 99
    .line 100
    goto :goto_6

    .line 101
    :cond_5
    invoke-virtual {p1}, Ljl/f;->a()Li3/c;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    :goto_6
    iput-object v6, p0, Ljl/h;->o:Li3/c;

    .line 106
    .line 107
    iget-object v1, p0, Ljl/h;->k:Ll2/j1;

    .line 108
    .line 109
    invoke-virtual {v1, v6}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iget-object p0, p0, Ljl/h;->i:Lpw0/a;

    .line 113
    .line 114
    if-eqz p0, :cond_9

    .line 115
    .line 116
    invoke-virtual {v0}, Ljl/f;->a()Li3/c;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-virtual {p1}, Ljl/f;->a()Li3/c;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    if-eq p0, v1, :cond_9

    .line 125
    .line 126
    invoke-virtual {v0}, Ljl/f;->a()Li3/c;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    instance-of v0, p0, Ll2/z1;

    .line 131
    .line 132
    if-eqz v0, :cond_6

    .line 133
    .line 134
    check-cast p0, Ll2/z1;

    .line 135
    .line 136
    goto :goto_7

    .line 137
    :cond_6
    move-object p0, v2

    .line 138
    :goto_7
    if-eqz p0, :cond_7

    .line 139
    .line 140
    invoke-interface {p0}, Ll2/z1;->h()V

    .line 141
    .line 142
    .line 143
    :cond_7
    invoke-virtual {p1}, Ljl/f;->a()Li3/c;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    instance-of p1, p0, Ll2/z1;

    .line 148
    .line 149
    if-eqz p1, :cond_8

    .line 150
    .line 151
    move-object v2, p0

    .line 152
    check-cast v2, Ll2/z1;

    .line 153
    .line 154
    :cond_8
    if-eqz v2, :cond_9

    .line 155
    .line 156
    invoke-interface {v2}, Ll2/z1;->c()V

    .line 157
    .line 158
    .line 159
    :cond_9
    return-void
.end method
