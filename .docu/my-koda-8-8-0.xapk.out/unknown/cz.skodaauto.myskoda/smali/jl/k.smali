.class public final Ljl/k;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public i:Li3/c;

.field public final j:Li3/c;

.field public final k:Lt3/k;

.field public final l:I

.field public final m:Z

.field public final n:Ll2/g1;

.field public o:J

.field public p:Z

.field public final q:Ll2/f1;

.field public final r:Ll2/j1;


# direct methods
.method public constructor <init>(Li3/c;Li3/c;Lt3/k;IZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljl/k;->i:Li3/c;

    .line 5
    .line 6
    iput-object p2, p0, Ljl/k;->j:Li3/c;

    .line 7
    .line 8
    iput-object p3, p0, Ljl/k;->k:Lt3/k;

    .line 9
    .line 10
    iput p4, p0, Ljl/k;->l:I

    .line 11
    .line 12
    iput-boolean p5, p0, Ljl/k;->m:Z

    .line 13
    .line 14
    new-instance p1, Ll2/g1;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-direct {p1, p2}, Ll2/g1;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Ljl/k;->n:Ll2/g1;

    .line 21
    .line 22
    const-wide/16 p1, -0x1

    .line 23
    .line 24
    iput-wide p1, p0, Ljl/k;->o:J

    .line 25
    .line 26
    new-instance p1, Ll2/f1;

    .line 27
    .line 28
    const/high16 p2, 0x3f800000    # 1.0f

    .line 29
    .line 30
    invoke-direct {p1, p2}, Ll2/f1;-><init>(F)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Ljl/k;->q:Ll2/f1;

    .line 34
    .line 35
    const/4 p1, 0x0

    .line 36
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iput-object p1, p0, Ljl/k;->r:Ll2/j1;

    .line 41
    .line 42
    return-void
.end method


# virtual methods
.method public final a(F)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ljl/k;->q:Ll2/f1;

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
    iget-object p0, p0, Ljl/k;->r:Ll2/j1;

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

.method public final g()J
    .locals 9

    .line 1
    iget-object v0, p0, Ljl/k;->i:Li3/c;

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Li3/c;->g()J

    .line 8
    .line 9
    .line 10
    move-result-wide v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-wide v3, v1

    .line 13
    :goto_0
    iget-object p0, p0, Ljl/k;->j:Li3/c;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Li3/c;->g()J

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    :cond_1
    const-wide v5, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    cmp-long p0, v3, v5

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    const/4 v7, 0x1

    .line 30
    if-eqz p0, :cond_2

    .line 31
    .line 32
    move p0, v7

    .line 33
    goto :goto_1

    .line 34
    :cond_2
    move p0, v0

    .line 35
    :goto_1
    cmp-long v8, v1, v5

    .line 36
    .line 37
    if-eqz v8, :cond_3

    .line 38
    .line 39
    move v0, v7

    .line 40
    :cond_3
    if-eqz p0, :cond_4

    .line 41
    .line 42
    if-eqz v0, :cond_4

    .line 43
    .line 44
    invoke-static {v3, v4}, Ld3/e;->d(J)F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    invoke-static {v1, v2}, Ld3/e;->d(J)F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-static {p0, v0}, Ljava/lang/Math;->max(FF)F

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    invoke-static {v3, v4}, Ld3/e;->b(J)F

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    invoke-static {v1, v2}, Ld3/e;->b(J)F

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    invoke-static {v0, v1}, Ljava/lang/Math;->max(FF)F

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    invoke-static {p0, v0}, Ljp/ef;->a(FF)J

    .line 69
    .line 70
    .line 71
    move-result-wide v0

    .line 72
    return-wide v0

    .line 73
    :cond_4
    return-wide v5
.end method

.method public final i(Lg3/d;)V
    .locals 9

    .line 1
    iget-boolean v0, p0, Ljl/k;->p:Z

    .line 2
    .line 3
    iget-object v1, p0, Ljl/k;->q:Ll2/f1;

    .line 4
    .line 5
    iget-object v2, p0, Ljl/k;->j:Li3/c;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0, p1, v2, v0}, Ljl/k;->j(Lg3/d;Li3/c;F)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v3

    .line 21
    iget-wide v5, p0, Ljl/k;->o:J

    .line 22
    .line 23
    const-wide/16 v7, -0x1

    .line 24
    .line 25
    cmp-long v0, v5, v7

    .line 26
    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    iput-wide v3, p0, Ljl/k;->o:J

    .line 30
    .line 31
    :cond_1
    iget-wide v5, p0, Ljl/k;->o:J

    .line 32
    .line 33
    sub-long/2addr v3, v5

    .line 34
    long-to-float v0, v3

    .line 35
    iget v3, p0, Ljl/k;->l:I

    .line 36
    .line 37
    int-to-float v3, v3

    .line 38
    div-float/2addr v0, v3

    .line 39
    const/4 v3, 0x0

    .line 40
    const/high16 v4, 0x3f800000    # 1.0f

    .line 41
    .line 42
    invoke-static {v0, v3, v4}, Lkp/r9;->d(FFF)F

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    mul-float/2addr v5, v3

    .line 51
    iget-boolean v3, p0, Ljl/k;->m:Z

    .line 52
    .line 53
    if-eqz v3, :cond_2

    .line 54
    .line 55
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    sub-float/2addr v1, v5

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    :goto_0
    cmpl-float v0, v0, v4

    .line 66
    .line 67
    const/4 v3, 0x1

    .line 68
    if-ltz v0, :cond_3

    .line 69
    .line 70
    move v0, v3

    .line 71
    goto :goto_1

    .line 72
    :cond_3
    const/4 v0, 0x0

    .line 73
    :goto_1
    iput-boolean v0, p0, Ljl/k;->p:Z

    .line 74
    .line 75
    iget-object v0, p0, Ljl/k;->i:Li3/c;

    .line 76
    .line 77
    invoke-virtual {p0, p1, v0, v1}, Ljl/k;->j(Lg3/d;Li3/c;F)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0, p1, v2, v5}, Ljl/k;->j(Lg3/d;Li3/c;F)V

    .line 81
    .line 82
    .line 83
    iget-boolean p1, p0, Ljl/k;->p:Z

    .line 84
    .line 85
    if-eqz p1, :cond_4

    .line 86
    .line 87
    const/4 p1, 0x0

    .line 88
    iput-object p1, p0, Ljl/k;->i:Li3/c;

    .line 89
    .line 90
    return-void

    .line 91
    :cond_4
    iget-object p0, p0, Ljl/k;->n:Ll2/g1;

    .line 92
    .line 93
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    add-int/2addr p1, v3

    .line 98
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 99
    .line 100
    .line 101
    return-void
.end method

.method public final j(Lg3/d;Li3/c;F)V
    .locals 12

    .line 1
    if-eqz p2, :cond_7

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    cmpg-float v0, p3, v0

    .line 5
    .line 6
    if-gtz v0, :cond_0

    .line 7
    .line 8
    goto/16 :goto_4

    .line 9
    .line 10
    :cond_0
    invoke-interface {p1}, Lg3/d;->e()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-virtual {p2}, Li3/c;->g()J

    .line 15
    .line 16
    .line 17
    move-result-wide v2

    .line 18
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    cmp-long v6, v2, v4

    .line 24
    .line 25
    if-nez v6, :cond_1

    .line 26
    .line 27
    :goto_0
    move-wide v8, v0

    .line 28
    goto :goto_2

    .line 29
    :cond_1
    invoke-static {v2, v3}, Ld3/e;->e(J)Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-eqz v6, :cond_2

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_2
    cmp-long v6, v0, v4

    .line 37
    .line 38
    if-nez v6, :cond_3

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_3
    invoke-static {v0, v1}, Ld3/e;->e(J)Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_4

    .line 46
    .line 47
    :goto_1
    goto :goto_0

    .line 48
    :cond_4
    iget-object v6, p0, Ljl/k;->k:Lt3/k;

    .line 49
    .line 50
    invoke-interface {v6, v2, v3, v0, v1}, Lt3/k;->a(JJ)J

    .line 51
    .line 52
    .line 53
    move-result-wide v6

    .line 54
    invoke-static {v2, v3, v6, v7}, Lt3/k1;->l(JJ)J

    .line 55
    .line 56
    .line 57
    move-result-wide v2

    .line 58
    move-wide v8, v2

    .line 59
    :goto_2
    cmp-long v2, v0, v4

    .line 60
    .line 61
    iget-object p0, p0, Ljl/k;->r:Ll2/j1;

    .line 62
    .line 63
    if-nez v2, :cond_5

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_5
    invoke-static {v0, v1}, Ld3/e;->e(J)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    if-eqz v2, :cond_6

    .line 71
    .line 72
    :goto_3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    move-object v11, p0

    .line 77
    check-cast v11, Le3/m;

    .line 78
    .line 79
    move-object v7, p1

    .line 80
    move-object v6, p2

    .line 81
    move v10, p3

    .line 82
    invoke-virtual/range {v6 .. v11}, Li3/c;->f(Lg3/d;JFLe3/m;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_6
    move-object v7, p1

    .line 87
    move-object v6, p2

    .line 88
    move v10, p3

    .line 89
    invoke-static {v0, v1}, Ld3/e;->d(J)F

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    invoke-static {v8, v9}, Ld3/e;->d(J)F

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    sub-float/2addr p1, p2

    .line 98
    const/4 p2, 0x2

    .line 99
    int-to-float p2, p2

    .line 100
    div-float/2addr p1, p2

    .line 101
    invoke-static {v0, v1}, Ld3/e;->b(J)F

    .line 102
    .line 103
    .line 104
    move-result p3

    .line 105
    invoke-static {v8, v9}, Ld3/e;->b(J)F

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    sub-float/2addr p3, v0

    .line 110
    div-float/2addr p3, p2

    .line 111
    invoke-interface {v7}, Lg3/d;->x0()Lgw0/c;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    iget-object p2, p2, Lgw0/c;->e:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p2, Lbu/c;

    .line 118
    .line 119
    invoke-virtual {p2, p1, p3, p1, p3}, Lbu/c;->v(FFFF)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    move-object v11, p0

    .line 127
    check-cast v11, Le3/m;

    .line 128
    .line 129
    invoke-virtual/range {v6 .. v11}, Li3/c;->f(Lg3/d;JFLe3/m;)V

    .line 130
    .line 131
    .line 132
    invoke-interface {v7}, Lg3/d;->x0()Lgw0/c;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p0, Lbu/c;

    .line 139
    .line 140
    neg-float p1, p1

    .line 141
    neg-float p2, p3

    .line 142
    invoke-virtual {p0, p1, p2, p1, p2}, Lbu/c;->v(FFFF)V

    .line 143
    .line 144
    .line 145
    :cond_7
    :goto_4
    return-void
.end method
