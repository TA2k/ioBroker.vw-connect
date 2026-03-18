.class public final Lv3/t;
.super Lv3/q0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final A(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/q0;->r:Lv3/f1;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lv3/h0;

    .line 16
    .line 17
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 18
    .line 19
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Lv3/f1;

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/h0;->m()Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->d(Lt3/t;Ljava/util/List;I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final C0(Lt3/a;)I
    .locals 6

    .line 1
    iget-object v0, p0, Lv3/q0;->r:Lv3/f1;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    iget-object v0, v0, Lv3/h0;->I:Lv3/l0;

    .line 6
    .line 7
    iget-object v0, v0, Lv3/l0;->q:Lv3/u0;

    .line 8
    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, v0, Lv3/u0;->v:Lv3/i0;

    .line 13
    .line 14
    iget-boolean v2, v0, Lv3/u0;->n:Z

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    if-nez v2, :cond_1

    .line 18
    .line 19
    iget-object v2, v0, Lv3/u0;->i:Lv3/l0;

    .line 20
    .line 21
    iget-object v4, v2, Lv3/l0;->d:Lv3/d0;

    .line 22
    .line 23
    sget-object v5, Lv3/d0;->e:Lv3/d0;

    .line 24
    .line 25
    if-ne v4, v5, :cond_0

    .line 26
    .line 27
    iput-boolean v3, v1, Lv3/i0;->f:Z

    .line 28
    .line 29
    iget-boolean v4, v1, Lv3/i0;->b:Z

    .line 30
    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    iput-boolean v3, v2, Lv3/l0;->f:Z

    .line 34
    .line 35
    iput-boolean v3, v2, Lv3/l0;->g:Z

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    iput-boolean v3, v1, Lv3/i0;->g:Z

    .line 39
    .line 40
    :cond_1
    :goto_0
    invoke-virtual {v0}, Lv3/u0;->E()Lv3/u;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    iget-object v2, v2, Lv3/u;->T:Lv3/t;

    .line 45
    .line 46
    if-eqz v2, :cond_2

    .line 47
    .line 48
    iput-boolean v3, v2, Lv3/p0;->n:Z

    .line 49
    .line 50
    :cond_2
    invoke-virtual {v0}, Lv3/u0;->t()V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0}, Lv3/u0;->E()Lv3/u;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    iget-object v0, v0, Lv3/u;->T:Lv3/t;

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    const/4 v2, 0x0

    .line 62
    iput-boolean v2, v0, Lv3/p0;->n:Z

    .line 63
    .line 64
    :cond_3
    iget-object v0, v1, Lv3/i0;->i:Ljava/util/HashMap;

    .line 65
    .line 66
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    check-cast v0, Ljava/lang/Integer;

    .line 71
    .line 72
    if-eqz v0, :cond_4

    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    goto :goto_1

    .line 79
    :cond_4
    const/high16 v0, -0x80000000

    .line 80
    .line 81
    :goto_1
    iget-object p0, p0, Lv3/q0;->w:Landroidx/collection/h0;

    .line 82
    .line 83
    invoke-virtual {p0, v0, p1}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    return v0
.end method

.method public final G(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/q0;->r:Lv3/f1;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lv3/h0;

    .line 16
    .line 17
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 18
    .line 19
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Lv3/f1;

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/h0;->m()Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->a(Lt3/t;Ljava/util/List;I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final J(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/q0;->r:Lv3/f1;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lv3/h0;

    .line 16
    .line 17
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 18
    .line 19
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Lv3/f1;

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/h0;->m()Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->e(Lt3/t;Ljava/util/List;I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public final L(J)Lt3/e1;
    .locals 6

    .line 1
    invoke-virtual {p0, p1, p2}, Lt3/e1;->y0(J)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lv3/q0;->r:Lv3/f1;

    .line 5
    .line 6
    iget-object v1, v0, Lv3/f1;->r:Lv3/h0;

    .line 7
    .line 8
    invoke-virtual {v1}, Lv3/h0;->z()Ln2/b;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iget-object v2, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 13
    .line 14
    iget v1, v1, Ln2/b;->f:I

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    :goto_0
    if-ge v3, v1, :cond_0

    .line 18
    .line 19
    aget-object v4, v2, v3

    .line 20
    .line 21
    check-cast v4, Lv3/h0;

    .line 22
    .line 23
    iget-object v4, v4, Lv3/h0;->I:Lv3/l0;

    .line 24
    .line 25
    iget-object v4, v4, Lv3/l0;->q:Lv3/u0;

    .line 26
    .line 27
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    sget-object v5, Lv3/f0;->f:Lv3/f0;

    .line 31
    .line 32
    iput-object v5, v4, Lv3/u0;->m:Lv3/f0;

    .line 33
    .line 34
    add-int/lit8 v3, v3, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    iget-object v0, v0, Lv3/f1;->r:Lv3/h0;

    .line 38
    .line 39
    iget-object v1, v0, Lv3/h0;->y:Lt3/q0;

    .line 40
    .line 41
    invoke-virtual {v0}, Lv3/h0;->m()Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-interface {v1, p0, v0, p1, p2}, Lt3/q0;->b(Lt3/s0;Ljava/util/List;J)Lt3/r0;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lv3/q0;->U0(Lv3/q0;Lt3/r0;)V

    .line 50
    .line 51
    .line 52
    return-object p0
.end method

.method public final V0()V
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/q0;->r:Lv3/f1;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 6
    .line 7
    iget-object p0, p0, Lv3/l0;->q:Lv3/u0;

    .line 8
    .line 9
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lv3/u0;->H0()V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final c(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/q0;->r:Lv3/f1;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lv3/h0;

    .line 16
    .line 17
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 18
    .line 19
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v1, Lv3/f1;

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/h0;->m()Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->c(Lt3/t;Ljava/util/List;I)I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method
