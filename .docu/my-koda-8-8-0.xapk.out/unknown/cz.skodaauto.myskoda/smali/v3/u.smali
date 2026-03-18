.class public final Lv3/u;
.super Lv3/f1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final U:Le3/g;


# instance fields
.field public final S:Lv3/z1;

.field public T:Lv3/t;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget v1, Le3/s;->j:I

    .line 6
    .line 7
    sget-wide v1, Le3/s;->f:J

    .line 8
    .line 9
    invoke-virtual {v0, v1, v2}, Le3/g;->e(J)V

    .line 10
    .line 11
    .line 12
    const/high16 v1, 0x3f800000    # 1.0f

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Le3/g;->l(F)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-virtual {v0, v1}, Le3/g;->m(I)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lv3/u;->U:Le3/g;

    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>(Lv3/h0;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lv3/f1;-><init>(Lv3/h0;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lv3/z1;

    .line 5
    .line 6
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iput v1, v0, Lx2/r;->g:I

    .line 11
    .line 12
    iput-object v0, p0, Lv3/u;->S:Lv3/z1;

    .line 13
    .line 14
    iput-object p0, v0, Lx2/r;->k:Lv3/f1;

    .line 15
    .line 16
    iget-object p1, p1, Lv3/h0;->j:Lv3/h0;

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    new-instance p1, Lv3/t;

    .line 21
    .line 22
    invoke-direct {p1, p0}, Lv3/q0;-><init>(Lv3/f1;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p1, 0x0

    .line 27
    :goto_0
    iput-object p1, p0, Lv3/u;->T:Lv3/t;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final A(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lv3/h0;

    .line 14
    .line 15
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lv3/f1;

    .line 20
    .line 21
    invoke-virtual {p0}, Lv3/h0;->n()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->d(Lt3/t;Ljava/util/List;I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public final C0(Lt3/a;)I
    .locals 4

    .line 1
    iget-object v0, p0, Lv3/u;->T:Lv3/t;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Lv3/t;->C0(Lt3/a;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 11
    .line 12
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 13
    .line 14
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 15
    .line 16
    iget-object v0, p0, Lv3/y0;->B:Lv3/i0;

    .line 17
    .line 18
    iget-boolean v1, p0, Lv3/y0;->p:Z

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    iget-object v1, p0, Lv3/y0;->i:Lv3/l0;

    .line 24
    .line 25
    iget-object v1, v1, Lv3/l0;->d:Lv3/d0;

    .line 26
    .line 27
    sget-object v3, Lv3/d0;->d:Lv3/d0;

    .line 28
    .line 29
    if-ne v1, v3, :cond_1

    .line 30
    .line 31
    iput-boolean v2, v0, Lv3/i0;->f:Z

    .line 32
    .line 33
    iget-boolean v1, v0, Lv3/i0;->b:Z

    .line 34
    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    iput-boolean v2, p0, Lv3/y0;->z:Z

    .line 38
    .line 39
    iput-boolean v2, p0, Lv3/y0;->A:Z

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    iput-boolean v2, v0, Lv3/i0;->g:Z

    .line 43
    .line 44
    :cond_2
    :goto_0
    invoke-virtual {p0}, Lv3/y0;->E()Lv3/u;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    iput-boolean v2, v1, Lv3/p0;->n:Z

    .line 49
    .line 50
    invoke-virtual {p0}, Lv3/y0;->t()V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lv3/y0;->E()Lv3/u;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    const/4 v1, 0x0

    .line 58
    iput-boolean v1, p0, Lv3/p0;->n:Z

    .line 59
    .line 60
    iget-object p0, v0, Lv3/i0;->i:Ljava/util/HashMap;

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ljava/lang/Integer;

    .line 67
    .line 68
    if-eqz p0, :cond_3

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    return p0

    .line 75
    :cond_3
    const/high16 p0, -0x80000000

    .line 76
    .line 77
    return p0
.end method

.method public final G(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lv3/h0;

    .line 14
    .line 15
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lv3/f1;

    .line 20
    .line 21
    invoke-virtual {p0}, Lv3/h0;->n()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->a(Lt3/t;Ljava/util/List;I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public final J(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lv3/h0;

    .line 14
    .line 15
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lv3/f1;

    .line 20
    .line 21
    invoke-virtual {p0}, Lv3/h0;->n()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->e(Lt3/t;Ljava/util/List;I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public final L(J)Lt3/e1;
    .locals 6

    .line 1
    invoke-virtual {p0, p1, p2}, Lt3/e1;->y0(J)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lv3/f1;->r:Lv3/h0;

    .line 5
    .line 6
    invoke-virtual {v0}, Lv3/h0;->z()Ln2/b;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iget-object v2, v1, Ln2/b;->d:[Ljava/lang/Object;

    .line 11
    .line 12
    iget v1, v1, Ln2/b;->f:I

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    :goto_0
    if-ge v3, v1, :cond_0

    .line 16
    .line 17
    aget-object v4, v2, v3

    .line 18
    .line 19
    check-cast v4, Lv3/h0;

    .line 20
    .line 21
    iget-object v4, v4, Lv3/h0;->I:Lv3/l0;

    .line 22
    .line 23
    iget-object v4, v4, Lv3/l0;->p:Lv3/y0;

    .line 24
    .line 25
    sget-object v5, Lv3/f0;->f:Lv3/f0;

    .line 26
    .line 27
    iput-object v5, v4, Lv3/y0;->o:Lv3/f0;

    .line 28
    .line 29
    add-int/lit8 v3, v3, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-object v1, v0, Lv3/h0;->y:Lt3/q0;

    .line 33
    .line 34
    invoke-virtual {v0}, Lv3/h0;->n()Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-interface {v1, p0, v0, p1, p2}, Lt3/q0;->b(Lt3/s0;Ljava/util/List;J)Lt3/r0;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p0, p1}, Lv3/f1;->y1(Lt3/r0;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lv3/f1;->q1()V

    .line 46
    .line 47
    .line 48
    return-object p0
.end method

.method public final a1()V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/u;->T:Lv3/t;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lv3/t;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lv3/q0;-><init>(Lv3/f1;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lv3/u;->T:Lv3/t;

    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final c(I)I
    .locals 2

    .line 1
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv3/h0;->u()Lb81/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lb81/d;->l()Lt3/q0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lv3/h0;

    .line 14
    .line 15
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    iget-object v1, v1, Lg1/q;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lv3/f1;

    .line 20
    .line 21
    invoke-virtual {p0}, Lv3/h0;->n()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {v0, v1, p0, p1}, Lt3/q0;->c(Lt3/t;Ljava/util/List;I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0
.end method

.method public final d1()Lv3/q0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u;->T:Lv3/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f1()Lx2/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/u;->S:Lv3/z1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l0(JFLay0/k;)V
    .locals 6

    .line 1
    const/4 v5, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-wide v1, p1

    .line 4
    move v3, p3

    .line 5
    move-object v4, p4

    .line 6
    invoke-virtual/range {v0 .. v5}, Lv3/f1;->v1(JFLay0/k;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    iget-boolean p0, v0, Lv3/p0;->m:Z

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object p0, v0, Lv3/f1;->r:Lv3/h0;

    .line 15
    .line 16
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 17
    .line 18
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 19
    .line 20
    invoke-virtual {p0}, Lv3/y0;->J0()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final l1(Lv3/d;JLv3/s;IZ)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v9, p4

    .line 8
    .line 9
    iget v2, v1, Lv3/d;->d:I

    .line 10
    .line 11
    const/4 v12, 0x1

    .line 12
    const/4 v13, 0x0

    .line 13
    iget-object v5, v0, Lv3/f1;->r:Lv3/h0;

    .line 14
    .line 15
    packed-switch v2, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    invoke-virtual {v5}, Lv3/h0;->x()Ld4/l;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    iget-boolean v2, v2, Ld4/l;->g:Z

    .line 25
    .line 26
    if-ne v2, v12, :cond_0

    .line 27
    .line 28
    move v2, v12

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v2, v13

    .line 31
    :goto_0
    xor-int/2addr v2, v12

    .line 32
    goto :goto_1

    .line 33
    :pswitch_0
    move v2, v12

    .line 34
    :goto_1
    if-eqz v2, :cond_2

    .line 35
    .line 36
    invoke-virtual {v0, v3, v4}, Lv3/f1;->G1(J)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    move/from16 v2, p5

    .line 43
    .line 44
    move/from16 v11, p6

    .line 45
    .line 46
    move v0, v12

    .line 47
    goto :goto_2

    .line 48
    :cond_1
    move/from16 v2, p5

    .line 49
    .line 50
    if-ne v2, v12, :cond_3

    .line 51
    .line 52
    invoke-virtual {v0}, Lv3/f1;->e1()J

    .line 53
    .line 54
    .line 55
    move-result-wide v6

    .line 56
    invoke-virtual {v0, v3, v4, v6, v7}, Lv3/f1;->X0(JJ)F

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    const v6, 0x7fffffff

    .line 65
    .line 66
    .line 67
    and-int/2addr v0, v6

    .line 68
    const/high16 v6, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 69
    .line 70
    if-ge v0, v6, :cond_3

    .line 71
    .line 72
    move v0, v12

    .line 73
    move v11, v13

    .line 74
    goto :goto_2

    .line 75
    :cond_2
    move/from16 v2, p5

    .line 76
    .line 77
    :cond_3
    move/from16 v11, p6

    .line 78
    .line 79
    move v0, v13

    .line 80
    :goto_2
    if-eqz v0, :cond_10

    .line 81
    .line 82
    iget v0, v9, Lv3/s;->f:I

    .line 83
    .line 84
    invoke-virtual {v5}, Lv3/h0;->y()Ln2/b;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    iget-object v14, v5, Ln2/b;->d:[Ljava/lang/Object;

    .line 89
    .line 90
    iget v5, v5, Ln2/b;->f:I

    .line 91
    .line 92
    sub-int/2addr v5, v12

    .line 93
    move v15, v5

    .line 94
    :goto_3
    if-ltz v15, :cond_f

    .line 95
    .line 96
    aget-object v5, v14, v15

    .line 97
    .line 98
    check-cast v5, Lv3/h0;

    .line 99
    .line 100
    invoke-virtual {v5}, Lv3/h0;->J()Z

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    if-eqz v6, :cond_e

    .line 105
    .line 106
    iget v6, v1, Lv3/d;->d:I

    .line 107
    .line 108
    packed-switch v6, :pswitch_data_1

    .line 109
    .line 110
    .line 111
    iget-object v6, v5, Lv3/h0;->H:Lg1/q;

    .line 112
    .line 113
    iget-object v7, v6, Lg1/q;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v7, Lv3/f1;

    .line 116
    .line 117
    invoke-virtual {v7, v3, v4}, Lv3/f1;->c1(J)J

    .line 118
    .line 119
    .line 120
    move-result-wide v7

    .line 121
    iget-object v6, v6, Lg1/q;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v6, Lv3/f1;

    .line 124
    .line 125
    move-object v10, v5

    .line 126
    move-object v5, v6

    .line 127
    sget-object v6, Lv3/f1;->R:Lv3/d;

    .line 128
    .line 129
    move-object/from16 v16, v10

    .line 130
    .line 131
    const/4 v10, 0x1

    .line 132
    invoke-virtual/range {v5 .. v11}, Lv3/f1;->k1(Lv3/d;JLv3/s;IZ)V

    .line 133
    .line 134
    .line 135
    move-object/from16 v9, p4

    .line 136
    .line 137
    move-object/from16 v10, v16

    .line 138
    .line 139
    goto :goto_4

    .line 140
    :pswitch_1
    move v6, v2

    .line 141
    move-object v2, v5

    .line 142
    move-object v5, v9

    .line 143
    move v7, v11

    .line 144
    invoke-virtual/range {v2 .. v7}, Lv3/h0;->A(JLv3/s;IZ)V

    .line 145
    .line 146
    .line 147
    move-object v10, v2

    .line 148
    :goto_4
    invoke-virtual {v9}, Lv3/s;->c()J

    .line 149
    .line 150
    .line 151
    move-result-wide v2

    .line 152
    invoke-static {v2, v3}, Lv3/f;->l(J)F

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    const/4 v5, 0x0

    .line 157
    cmpg-float v4, v4, v5

    .line 158
    .line 159
    if-gez v4, :cond_e

    .line 160
    .line 161
    invoke-static {v2, v3}, Lv3/f;->q(J)Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_e

    .line 166
    .line 167
    invoke-static {v2, v3}, Lv3/f;->p(J)Z

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    if-nez v2, :cond_e

    .line 172
    .line 173
    iget-object v2, v10, Lv3/h0;->H:Lg1/q;

    .line 174
    .line 175
    iget-object v2, v2, Lg1/q;->e:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v2, Lv3/f1;

    .line 178
    .line 179
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    const/16 v3, 0x10

    .line 183
    .line 184
    invoke-static {v3}, Lv3/g1;->g(I)Z

    .line 185
    .line 186
    .line 187
    move-result v4

    .line 188
    invoke-virtual {v2, v4}, Lv3/f1;->h1(Z)Lx2/r;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    if-nez v2, :cond_4

    .line 193
    .line 194
    goto/16 :goto_a

    .line 195
    .line 196
    :cond_4
    iget-boolean v4, v2, Lx2/r;->q:Z

    .line 197
    .line 198
    if-eqz v4, :cond_f

    .line 199
    .line 200
    iget-object v4, v2, Lx2/r;->d:Lx2/r;

    .line 201
    .line 202
    iget-boolean v4, v4, Lx2/r;->q:Z

    .line 203
    .line 204
    if-nez v4, :cond_5

    .line 205
    .line 206
    const-string v4, "visitLocalDescendants called on an unattached node"

    .line 207
    .line 208
    invoke-static {v4}, Ls3/a;->b(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    :cond_5
    iget-object v2, v2, Lx2/r;->d:Lx2/r;

    .line 212
    .line 213
    iget v4, v2, Lx2/r;->g:I

    .line 214
    .line 215
    and-int/2addr v4, v3

    .line 216
    if-eqz v4, :cond_f

    .line 217
    .line 218
    :goto_5
    if-eqz v2, :cond_f

    .line 219
    .line 220
    iget v4, v2, Lx2/r;->f:I

    .line 221
    .line 222
    and-int/2addr v4, v3

    .line 223
    if-eqz v4, :cond_d

    .line 224
    .line 225
    const/4 v4, 0x0

    .line 226
    move-object v5, v2

    .line 227
    move-object v6, v4

    .line 228
    :goto_6
    if-eqz v5, :cond_d

    .line 229
    .line 230
    instance-of v7, v5, Lv3/t1;

    .line 231
    .line 232
    if-eqz v7, :cond_6

    .line 233
    .line 234
    check-cast v5, Lv3/t1;

    .line 235
    .line 236
    invoke-interface {v5}, Lv3/t1;->E0()Z

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    if-eqz v5, :cond_c

    .line 241
    .line 242
    iget-object v2, v9, Lv3/s;->d:Landroidx/collection/l0;

    .line 243
    .line 244
    iget v2, v2, Landroidx/collection/l0;->b:I

    .line 245
    .line 246
    sub-int/2addr v2, v12

    .line 247
    iput v2, v9, Lv3/s;->f:I

    .line 248
    .line 249
    goto :goto_9

    .line 250
    :cond_6
    iget v7, v5, Lx2/r;->f:I

    .line 251
    .line 252
    and-int/2addr v7, v3

    .line 253
    if-eqz v7, :cond_c

    .line 254
    .line 255
    instance-of v7, v5, Lv3/n;

    .line 256
    .line 257
    if-eqz v7, :cond_c

    .line 258
    .line 259
    move-object v7, v5

    .line 260
    check-cast v7, Lv3/n;

    .line 261
    .line 262
    iget-object v7, v7, Lv3/n;->s:Lx2/r;

    .line 263
    .line 264
    move v8, v13

    .line 265
    :goto_7
    if-eqz v7, :cond_b

    .line 266
    .line 267
    iget v10, v7, Lx2/r;->f:I

    .line 268
    .line 269
    and-int/2addr v10, v3

    .line 270
    if-eqz v10, :cond_a

    .line 271
    .line 272
    add-int/lit8 v8, v8, 0x1

    .line 273
    .line 274
    if-ne v8, v12, :cond_7

    .line 275
    .line 276
    move-object v5, v7

    .line 277
    goto :goto_8

    .line 278
    :cond_7
    if-nez v6, :cond_8

    .line 279
    .line 280
    new-instance v6, Ln2/b;

    .line 281
    .line 282
    new-array v10, v3, [Lx2/r;

    .line 283
    .line 284
    invoke-direct {v6, v10}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    :cond_8
    if-eqz v5, :cond_9

    .line 288
    .line 289
    invoke-virtual {v6, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    move-object v5, v4

    .line 293
    :cond_9
    invoke-virtual {v6, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    :cond_a
    :goto_8
    iget-object v7, v7, Lx2/r;->i:Lx2/r;

    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_b
    if-ne v8, v12, :cond_c

    .line 300
    .line 301
    goto :goto_6

    .line 302
    :cond_c
    invoke-static {v6}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 303
    .line 304
    .line 305
    move-result-object v5

    .line 306
    goto :goto_6

    .line 307
    :cond_d
    iget-object v2, v2, Lx2/r;->i:Lx2/r;

    .line 308
    .line 309
    goto :goto_5

    .line 310
    :cond_e
    :goto_9
    add-int/lit8 v15, v15, -0x1

    .line 311
    .line 312
    move-wide/from16 v3, p2

    .line 313
    .line 314
    move/from16 v2, p5

    .line 315
    .line 316
    goto/16 :goto_3

    .line 317
    .line 318
    :cond_f
    :goto_a
    iput v0, v9, Lv3/s;->f:I

    .line 319
    .line 320
    :cond_10
    return-void

    .line 321
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch

    .line 322
    .line 323
    .line 324
    .line 325
    .line 326
    .line 327
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_1
    .end packed-switch
.end method

.method public final m0(JFLh3/c;)V
    .locals 6

    .line 1
    const/4 v4, 0x0

    .line 2
    move-object v0, p0

    .line 3
    move-wide v1, p1

    .line 4
    move v3, p3

    .line 5
    move-object v5, p4

    .line 6
    invoke-virtual/range {v0 .. v5}, Lv3/f1;->v1(JFLay0/k;Lh3/c;)V

    .line 7
    .line 8
    .line 9
    iget-boolean p0, v0, Lv3/p0;->m:Z

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object p0, v0, Lv3/f1;->r:Lv3/h0;

    .line 15
    .line 16
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 17
    .line 18
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 19
    .line 20
    invoke-virtual {p0}, Lv3/y0;->J0()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final u1(Le3/r;Lh3/c;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lv3/f1;->r:Lv3/h0;

    .line 2
    .line 3
    invoke-static {v0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {v0}, Lv3/h0;->y()Ln2/b;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v2, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 12
    .line 13
    iget v0, v0, Ln2/b;->f:I

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    :goto_0
    if-ge v3, v0, :cond_1

    .line 17
    .line 18
    aget-object v4, v2, v3

    .line 19
    .line 20
    check-cast v4, Lv3/h0;

    .line 21
    .line 22
    invoke-virtual {v4}, Lv3/h0;->J()Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    if-eqz v5, :cond_0

    .line 27
    .line 28
    invoke-virtual {v4, p1, p2}, Lv3/h0;->j(Le3/r;Lh3/c;)V

    .line 29
    .line 30
    .line 31
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    check-cast v1, Lw3/t;

    .line 35
    .line 36
    invoke-virtual {v1}, Lw3/t;->getShowLayoutBounds()Z

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    if-eqz p2, :cond_2

    .line 41
    .line 42
    iget-wide v0, p0, Lt3/e1;->f:J

    .line 43
    .line 44
    const/16 p0, 0x20

    .line 45
    .line 46
    shr-long v2, v0, p0

    .line 47
    .line 48
    long-to-int p0, v2

    .line 49
    int-to-float p0, p0

    .line 50
    const/high16 p2, 0x3f000000    # 0.5f

    .line 51
    .line 52
    sub-float v5, p0, p2

    .line 53
    .line 54
    const-wide v2, 0xffffffffL

    .line 55
    .line 56
    .line 57
    .line 58
    .line 59
    and-long/2addr v0, v2

    .line 60
    long-to-int p0, v0

    .line 61
    int-to-float p0, p0

    .line 62
    sub-float v6, p0, p2

    .line 63
    .line 64
    const/high16 v3, 0x3f000000    # 0.5f

    .line 65
    .line 66
    const/high16 v4, 0x3f000000    # 0.5f

    .line 67
    .line 68
    sget-object v7, Lv3/u;->U:Le3/g;

    .line 69
    .line 70
    move-object v2, p1

    .line 71
    invoke-interface/range {v2 .. v7}, Le3/r;->r(FFFFLe3/g;)V

    .line 72
    .line 73
    .line 74
    :cond_2
    return-void
.end method
