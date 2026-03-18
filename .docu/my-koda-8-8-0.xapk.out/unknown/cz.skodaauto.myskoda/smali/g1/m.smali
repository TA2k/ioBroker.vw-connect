.class public final Lg1/m;
.super Lg1/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public C:Lg1/q;

.field public D:Lg1/w1;

.field public E:Lh1/g;

.field public F:Lg1/j1;

.field public G:Lt4/c;


# direct methods
.method public static final j1(Lg1/m;FLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lg1/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/j;

    .line 7
    .line 8
    iget v1, v0, Lg1/j;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lg1/j;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lg1/j;-><init>(Lg1/m;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/j;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/j;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lg1/j;->d:Lkotlin/jvm/internal/c0;

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object p2

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p0, Lg1/m;->C:Lg1/q;

    .line 61
    .line 62
    invoke-virtual {p2}, Lg1/q;->h()Z

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    const/4 v2, 0x0

    .line 67
    if-eqz p2, :cond_5

    .line 68
    .line 69
    iget-object p0, p0, Lg1/m;->C:Lg1/q;

    .line 70
    .line 71
    iput v4, v0, Lg1/j;->g:I

    .line 72
    .line 73
    invoke-virtual {p0}, Lg1/q;->h()Z

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    if-nez p1, :cond_4

    .line 78
    .line 79
    const-string p1, "AnchoredDraggableState was configured through a constructor without providing positional and velocity threshold. This overload of settle has been deprecated. Please refer to AnchoredDraggableState#settle(animationSpec) for more information."

    .line 80
    .line 81
    invoke-static {p1}, Lj1/b;->a(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :cond_4
    iget-object p1, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p1, Ll2/j1;

    .line 87
    .line 88
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0}, Lg1/q;->g()Lg1/z;

    .line 92
    .line 93
    .line 94
    invoke-virtual {p0}, Lg1/q;->k()F

    .line 95
    .line 96
    .line 97
    const-string p0, "positionalThreshold"

    .line 98
    .line 99
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw v2

    .line 103
    :cond_5
    new-instance p2, Lkotlin/jvm/internal/c0;

    .line 104
    .line 105
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 106
    .line 107
    .line 108
    iput p1, p2, Lkotlin/jvm/internal/c0;->d:F

    .line 109
    .line 110
    iget-object v4, p0, Lg1/m;->C:Lg1/q;

    .line 111
    .line 112
    new-instance v5, Lg1/l;

    .line 113
    .line 114
    invoke-direct {v5, p0, p2, p1, v2}, Lg1/l;-><init>(Lg1/m;Lkotlin/jvm/internal/c0;FLkotlin/coroutines/Continuation;)V

    .line 115
    .line 116
    .line 117
    iput-object p2, v0, Lg1/j;->d:Lkotlin/jvm/internal/c0;

    .line 118
    .line 119
    iput v3, v0, Lg1/j;->g:I

    .line 120
    .line 121
    sget-object p0, Le1/w0;->d:Le1/w0;

    .line 122
    .line 123
    iget-object p1, v4, Lg1/q;->c:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p1, Le1/b1;

    .line 126
    .line 127
    new-instance v3, La2/c;

    .line 128
    .line 129
    invoke-direct {v3, v5, v4, v2}, La2/c;-><init>(Lay0/o;Lg1/q;Lkotlin/coroutines/Continuation;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    new-instance v4, Le1/z0;

    .line 136
    .line 137
    invoke-direct {v4, p0, p1, v3, v2}, Le1/z0;-><init>(Le1/w0;Le1/b1;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 138
    .line 139
    .line 140
    invoke-static {v4, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-ne p0, v1, :cond_6

    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    :goto_1
    if-ne p0, v1, :cond_7

    .line 150
    .line 151
    return-object v1

    .line 152
    :cond_7
    move-object p0, p2

    .line 153
    :goto_2
    iget p0, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 154
    .line 155
    new-instance p1, Ljava/lang/Float;

    .line 156
    .line 157
    invoke-direct {p1, p0}, Ljava/lang/Float;-><init>(F)V

    .line 158
    .line 159
    .line 160
    return-object p1
.end method


# virtual methods
.method public final P0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lg1/m;->E:Lh1/g;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lg1/m;->l1(Lh1/g;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lg1/d1;->l0()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v0, v0, Lv3/h0;->A:Lt4/c;

    .line 13
    .line 14
    iget-object v1, p0, Lg1/m;->G:Lt4/c;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    :cond_0
    iput-object v0, p0, Lg1/m;->G:Lt4/c;

    .line 25
    .line 26
    iget-object v0, p0, Lg1/m;->E:Lh1/g;

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Lg1/m;->l1(Lh1/g;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public final e1(Lg1/c1;Lg1/c1;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lg1/m;->C:Lg1/q;

    .line 2
    .line 3
    new-instance v1, La90/c;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p1, p0, v2}, La90/c;-><init>(Lg1/c1;Lg1/m;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Le1/w0;->d:Le1/w0;

    .line 10
    .line 11
    iget-object p1, v0, Lg1/q;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p1, Le1/b1;

    .line 14
    .line 15
    new-instance v3, La2/c;

    .line 16
    .line 17
    invoke-direct {v3, v1, v0, v2}, La2/c;-><init>(Lay0/o;Lg1/q;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    new-instance v0, Le1/z0;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1, v3, v2}, Le1/z0;-><init>(Le1/w0;Le1/b1;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, p2}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    if-ne p0, p1, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move-object p0, p2

    .line 40
    :goto_0
    if-ne p0, p1, :cond_1

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_1
    return-object p2
.end method

.method public final f1(J)V
    .locals 0

    .line 1
    return-void
.end method

.method public final g1(J)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Le2/f0;

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    const/4 v5, 0x0

    .line 14
    move-object v2, p0

    .line 15
    move-wide v3, p1

    .line 16
    invoke-direct/range {v1 .. v6}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    const/4 p0, 0x3

    .line 20
    invoke-static {v0, v5, v5, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final h1()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lg1/m;->C:Lg1/q;

    .line 2
    .line 3
    iget-object p0, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ll2/j1;

    .line 6
    .line 7
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final k1()Z
    .locals 2

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, Lv3/h0;->B:Lt4/m;

    .line 6
    .line 7
    sget-object v1, Lt4/m;->e:Lt4/m;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lg1/m;->D:Lg1/w1;

    .line 12
    .line 13
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final l1(Lh1/g;)V
    .locals 5

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p1, Lg1/b;->a:Lc1/a2;

    .line 4
    .line 5
    sget-object v0, Lg1/b;->b:Lfw0/i0;

    .line 6
    .line 7
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object v1, v1, Lv3/h0;->A:Lt4/c;

    .line 12
    .line 13
    iput-object v1, p0, Lg1/m;->G:Lt4/c;

    .line 14
    .line 15
    iget-object v2, p0, Lg1/m;->C:Lg1/q;

    .line 16
    .line 17
    new-instance v3, Ld2/g;

    .line 18
    .line 19
    const/16 v4, 0xf

    .line 20
    .line 21
    invoke-direct {v3, v1, v4}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lgw0/c;

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    invoke-direct {v1, v2, v0, v3, v4}, Lgw0/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    sget v0, Lh1/k;->a:F

    .line 32
    .line 33
    new-instance v0, Lh1/g;

    .line 34
    .line 35
    sget-object v2, Landroidx/compose/foundation/gestures/a;->b:Lc1/u;

    .line 36
    .line 37
    invoke-direct {v0, v1, v2, p1}, Lh1/g;-><init>(Lh1/l;Lc1/u;Lc1/j;)V

    .line 38
    .line 39
    .line 40
    move-object p1, v0

    .line 41
    :cond_0
    iput-object p1, p0, Lg1/m;->F:Lg1/j1;

    .line 42
    .line 43
    return-void
.end method
