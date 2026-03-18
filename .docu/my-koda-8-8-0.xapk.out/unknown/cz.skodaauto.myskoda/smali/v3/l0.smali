.class public final Lv3/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lv3/h0;

.field public b:Z

.field public c:Z

.field public d:Lv3/d0;

.field public e:Z

.field public f:Z

.field public g:Z

.field public h:I

.field public i:I

.field public j:Z

.field public k:Z

.field public l:I

.field public m:Z

.field public n:Z

.field public o:I

.field public final p:Lv3/y0;

.field public q:Lv3/u0;


# direct methods
.method public constructor <init>(Lv3/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv3/l0;->a:Lv3/h0;

    .line 5
    .line 6
    sget-object p1, Lv3/d0;->h:Lv3/d0;

    .line 7
    .line 8
    iput-object p1, p0, Lv3/l0;->d:Lv3/d0;

    .line 9
    .line 10
    new-instance p1, Lv3/y0;

    .line 11
    .line 12
    invoke-direct {p1, p0}, Lv3/y0;-><init>(Lv3/l0;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lv3/l0;->p:Lv3/y0;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a()Lv3/f1;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 4
    .line 5
    iget-object p0, p0, Lg1/q;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lv3/f1;

    .line 8
    .line 9
    return-object p0
.end method

.method public final b()V
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/l0;->a:Lv3/h0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/h0;->I:Lv3/l0;

    .line 4
    .line 5
    iget-object v0, v0, Lv3/l0;->d:Lv3/d0;

    .line 6
    .line 7
    sget-object v1, Lv3/d0;->f:Lv3/d0;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    sget-object v1, Lv3/d0;->g:Lv3/d0;

    .line 13
    .line 14
    if-ne v0, v1, :cond_2

    .line 15
    .line 16
    :cond_0
    iget-object v1, p0, Lv3/l0;->p:Lv3/y0;

    .line 17
    .line 18
    iget-boolean v1, v1, Lv3/y0;->E:Z

    .line 19
    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0, v2}, Lv3/l0;->g(Z)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {p0, v2}, Lv3/l0;->f(Z)V

    .line 27
    .line 28
    .line 29
    :cond_2
    :goto_0
    sget-object v1, Lv3/d0;->g:Lv3/d0;

    .line 30
    .line 31
    if-ne v0, v1, :cond_4

    .line 32
    .line 33
    iget-object v0, p0, Lv3/l0;->q:Lv3/u0;

    .line 34
    .line 35
    if-eqz v0, :cond_3

    .line 36
    .line 37
    iget-boolean v0, v0, Lv3/u0;->y:Z

    .line 38
    .line 39
    if-ne v0, v2, :cond_3

    .line 40
    .line 41
    invoke-virtual {p0, v2}, Lv3/l0;->i(Z)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_3
    invoke-virtual {p0, v2}, Lv3/l0;->h(Z)V

    .line 46
    .line 47
    .line 48
    :cond_4
    return-void
.end method

.method public final c(J)V
    .locals 5

    .line 1
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 2
    .line 3
    if-eqz p0, :cond_2

    .line 4
    .line 5
    sget-object v0, Lv3/d0;->e:Lv3/d0;

    .line 6
    .line 7
    iget-object v1, p0, Lv3/u0;->i:Lv3/l0;

    .line 8
    .line 9
    iput-object v0, v1, Lv3/l0;->d:Lv3/d0;

    .line 10
    .line 11
    iget-object v0, v1, Lv3/l0;->p:Lv3/y0;

    .line 12
    .line 13
    iget-object v2, v1, Lv3/l0;->a:Lv3/h0;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    iput-boolean v3, v1, Lv3/l0;->e:Z

    .line 17
    .line 18
    invoke-static {v2}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    check-cast v3, Lw3/t;

    .line 23
    .line 24
    invoke-virtual {v3}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    new-instance v4, Lv3/s0;

    .line 29
    .line 30
    invoke-direct {v4, p0, p1, p2}, Lv3/s0;-><init>(Lv3/u0;J)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    iget-object p0, v2, Lv3/h0;->j:Lv3/h0;

    .line 37
    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    iget-object p0, v3, Lv3/q1;->b:Lv3/e;

    .line 41
    .line 42
    invoke-virtual {v3, v2, p0, v4}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    iget-object p0, v3, Lv3/q1;->c:Lv3/e;

    .line 47
    .line 48
    invoke-virtual {v3, v2, p0, v4}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 49
    .line 50
    .line 51
    :goto_0
    const/4 p0, 0x1

    .line 52
    iput-boolean p0, v1, Lv3/l0;->f:Z

    .line 53
    .line 54
    iput-boolean p0, v1, Lv3/l0;->g:Z

    .line 55
    .line 56
    invoke-static {v2}, Lv3/f;->s(Lv3/h0;)Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_1

    .line 61
    .line 62
    iput-boolean p0, v0, Lv3/y0;->z:Z

    .line 63
    .line 64
    iput-boolean p0, v0, Lv3/y0;->A:Z

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    iput-boolean p0, v0, Lv3/y0;->y:Z

    .line 68
    .line 69
    :goto_1
    sget-object p0, Lv3/d0;->h:Lv3/d0;

    .line 70
    .line 71
    iput-object p0, v1, Lv3/l0;->d:Lv3/d0;

    .line 72
    .line 73
    :cond_2
    return-void
.end method

.method public final d(I)V
    .locals 3

    .line 1
    iget v0, p0, Lv3/l0;->l:I

    .line 2
    .line 3
    iput p1, p0, Lv3/l0;->l:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    move v0, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    if-nez p1, :cond_1

    .line 13
    .line 14
    move v1, v2

    .line 15
    :cond_1
    if-eq v0, v1, :cond_4

    .line 16
    .line 17
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 18
    .line 19
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    if-eqz p0, :cond_2

    .line 24
    .line 25
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_2
    const/4 p0, 0x0

    .line 29
    :goto_1
    if-eqz p0, :cond_4

    .line 30
    .line 31
    if-nez p1, :cond_3

    .line 32
    .line 33
    iget p1, p0, Lv3/l0;->l:I

    .line 34
    .line 35
    add-int/lit8 p1, p1, -0x1

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lv3/l0;->d(I)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_3
    iget p1, p0, Lv3/l0;->l:I

    .line 42
    .line 43
    add-int/2addr p1, v2

    .line 44
    invoke-virtual {p0, p1}, Lv3/l0;->d(I)V

    .line 45
    .line 46
    .line 47
    :cond_4
    return-void
.end method

.method public final e(I)V
    .locals 3

    .line 1
    iget v0, p0, Lv3/l0;->o:I

    .line 2
    .line 3
    iput p1, p0, Lv3/l0;->o:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    move v0, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    if-nez p1, :cond_1

    .line 13
    .line 14
    move v1, v2

    .line 15
    :cond_1
    if-eq v0, v1, :cond_4

    .line 16
    .line 17
    iget-object p0, p0, Lv3/l0;->a:Lv3/h0;

    .line 18
    .line 19
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    if-eqz p0, :cond_2

    .line 24
    .line 25
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_2
    const/4 p0, 0x0

    .line 29
    :goto_1
    if-eqz p0, :cond_4

    .line 30
    .line 31
    if-nez p1, :cond_3

    .line 32
    .line 33
    iget p1, p0, Lv3/l0;->o:I

    .line 34
    .line 35
    add-int/lit8 p1, p1, -0x1

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lv3/l0;->e(I)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_3
    iget p1, p0, Lv3/l0;->o:I

    .line 42
    .line 43
    add-int/2addr p1, v2

    .line 44
    invoke-virtual {p0, p1}, Lv3/l0;->e(I)V

    .line 45
    .line 46
    .line 47
    :cond_4
    return-void
.end method

.method public final f(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/l0;->k:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-boolean p1, p0, Lv3/l0;->k:Z

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lv3/l0;->j:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget p1, p0, Lv3/l0;->l:I

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lv3/l0;->d(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    if-nez p1, :cond_1

    .line 22
    .line 23
    iget-boolean p1, p0, Lv3/l0;->j:Z

    .line 24
    .line 25
    if-nez p1, :cond_1

    .line 26
    .line 27
    iget p1, p0, Lv3/l0;->l:I

    .line 28
    .line 29
    add-int/lit8 p1, p1, -0x1

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lv3/l0;->d(I)V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public final g(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/l0;->j:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-boolean p1, p0, Lv3/l0;->j:Z

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lv3/l0;->k:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget p1, p0, Lv3/l0;->l:I

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lv3/l0;->d(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    if-nez p1, :cond_1

    .line 22
    .line 23
    iget-boolean p1, p0, Lv3/l0;->k:Z

    .line 24
    .line 25
    if-nez p1, :cond_1

    .line 26
    .line 27
    iget p1, p0, Lv3/l0;->l:I

    .line 28
    .line 29
    add-int/lit8 p1, p1, -0x1

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lv3/l0;->d(I)V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public final h(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/l0;->n:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-boolean p1, p0, Lv3/l0;->n:Z

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lv3/l0;->m:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget p1, p0, Lv3/l0;->o:I

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lv3/l0;->e(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    if-nez p1, :cond_1

    .line 22
    .line 23
    iget-boolean p1, p0, Lv3/l0;->m:Z

    .line 24
    .line 25
    if-nez p1, :cond_1

    .line 26
    .line 27
    iget p1, p0, Lv3/l0;->o:I

    .line 28
    .line 29
    add-int/lit8 p1, p1, -0x1

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lv3/l0;->e(I)V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public final i(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv3/l0;->m:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_1

    .line 4
    .line 5
    iput-boolean p1, p0, Lv3/l0;->m:Z

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lv3/l0;->n:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget p1, p0, Lv3/l0;->o:I

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Lv3/l0;->e(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    if-nez p1, :cond_1

    .line 22
    .line 23
    iget-boolean p1, p0, Lv3/l0;->n:Z

    .line 24
    .line 25
    if-nez p1, :cond_1

    .line 26
    .line 27
    iget p1, p0, Lv3/l0;->o:I

    .line 28
    .line 29
    add-int/lit8 p1, p1, -0x1

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lv3/l0;->e(I)V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public final j()V
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/l0;->p:Lv3/y0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/y0;->i:Lv3/l0;

    .line 4
    .line 5
    iget-object v2, v0, Lv3/y0;->v:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 v3, 0x7

    .line 8
    iget-object v4, p0, Lv3/l0;->a:Lv3/h0;

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    invoke-virtual {v1}, Lv3/l0;->a()Lv3/f1;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {v2}, Lv3/f1;->l()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iget-boolean v2, v0, Lv3/y0;->u:Z

    .line 25
    .line 26
    if-nez v2, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    iput-boolean v5, v0, Lv3/y0;->u:Z

    .line 30
    .line 31
    invoke-virtual {v1}, Lv3/l0;->a()Lv3/f1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v1}, Lv3/f1;->l()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    iput-object v1, v0, Lv3/y0;->v:Ljava/lang/Object;

    .line 40
    .line 41
    invoke-virtual {v4}, Lv3/h0;->v()Lv3/h0;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    if-eqz v0, :cond_2

    .line 46
    .line 47
    invoke-static {v0, v5, v3}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 48
    .line 49
    .line 50
    :cond_2
    :goto_0
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 51
    .line 52
    if-eqz p0, :cond_6

    .line 53
    .line 54
    iget-object v0, p0, Lv3/u0;->i:Lv3/l0;

    .line 55
    .line 56
    iget-object v1, p0, Lv3/u0;->A:Ljava/lang/Object;

    .line 57
    .line 58
    if-nez v1, :cond_3

    .line 59
    .line 60
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v1}, Lv3/f1;->d1()Lv3/q0;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iget-object v1, v1, Lv3/q0;->r:Lv3/f1;

    .line 72
    .line 73
    invoke-virtual {v1}, Lv3/f1;->l()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    if-nez v1, :cond_3

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    iget-boolean v1, p0, Lv3/u0;->z:Z

    .line 81
    .line 82
    if-nez v1, :cond_4

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_4
    iput-boolean v5, p0, Lv3/u0;->z:Z

    .line 86
    .line 87
    invoke-virtual {v0}, Lv3/l0;->a()Lv3/f1;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-virtual {v0}, Lv3/f1;->d1()Lv3/q0;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    iget-object v0, v0, Lv3/q0;->r:Lv3/f1;

    .line 99
    .line 100
    invoke-virtual {v0}, Lv3/f1;->l()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    iput-object v0, p0, Lv3/u0;->A:Ljava/lang/Object;

    .line 105
    .line 106
    invoke-static {v4}, Lv3/f;->s(Lv3/h0;)Z

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    if-eqz p0, :cond_5

    .line 111
    .line 112
    invoke-virtual {v4}, Lv3/h0;->v()Lv3/h0;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    if-eqz p0, :cond_6

    .line 117
    .line 118
    invoke-static {p0, v5, v3}, Lv3/h0;->Y(Lv3/h0;ZI)V

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    :cond_5
    invoke-virtual {v4}, Lv3/h0;->v()Lv3/h0;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    if-eqz p0, :cond_6

    .line 127
    .line 128
    invoke-static {p0, v5, v3}, Lv3/h0;->W(Lv3/h0;ZI)V

    .line 129
    .line 130
    .line 131
    :cond_6
    :goto_1
    return-void
.end method
