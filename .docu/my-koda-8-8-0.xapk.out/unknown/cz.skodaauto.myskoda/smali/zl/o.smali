.class public final Lzl/o;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Li3/c;

.field public final j:Lt3/k;

.field public final k:J

.field public final l:Lmy0/m;

.field public final m:Z

.field public final n:Ll2/g1;

.field public o:Lmy0/k;

.field public p:Z

.field public q:F

.field public r:Le3/m;

.field public s:Li3/c;

.field public final t:J


# direct methods
.method public constructor <init>(Li3/c;Li3/c;Lt3/k;JZ)V
    .locals 4

    .line 1
    sget-object v0, Lmy0/a;->f:Lmy0/a;

    .line 2
    .line 3
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lzl/o;->i:Li3/c;

    .line 7
    .line 8
    iput-object p3, p0, Lzl/o;->j:Lt3/k;

    .line 9
    .line 10
    iput-wide p4, p0, Lzl/o;->k:J

    .line 11
    .line 12
    iput-object v0, p0, Lzl/o;->l:Lmy0/m;

    .line 13
    .line 14
    iput-boolean p6, p0, Lzl/o;->m:Z

    .line 15
    .line 16
    new-instance p3, Ll2/g1;

    .line 17
    .line 18
    const/4 p4, 0x0

    .line 19
    invoke-direct {p3, p4}, Ll2/g1;-><init>(I)V

    .line 20
    .line 21
    .line 22
    iput-object p3, p0, Lzl/o;->n:Ll2/g1;

    .line 23
    .line 24
    const/high16 p3, 0x3f800000    # 1.0f

    .line 25
    .line 26
    iput p3, p0, Lzl/o;->q:F

    .line 27
    .line 28
    iput-object p1, p0, Lzl/o;->s:Li3/c;

    .line 29
    .line 30
    const-wide/16 p5, 0x0

    .line 31
    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    invoke-virtual {p1}, Li3/c;->g()J

    .line 35
    .line 36
    .line 37
    move-result-wide v0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move-wide v0, p5

    .line 40
    :goto_0
    if-eqz p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p2}, Li3/c;->g()J

    .line 43
    .line 44
    .line 45
    move-result-wide p5

    .line 46
    :cond_1
    const-wide p1, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    cmp-long p3, v0, p1

    .line 52
    .line 53
    const/4 v2, 0x1

    .line 54
    if-eqz p3, :cond_2

    .line 55
    .line 56
    move p3, v2

    .line 57
    goto :goto_1

    .line 58
    :cond_2
    move p3, p4

    .line 59
    :goto_1
    cmp-long v3, p5, p1

    .line 60
    .line 61
    if-eqz v3, :cond_3

    .line 62
    .line 63
    move p4, v2

    .line 64
    :cond_3
    if-eqz p3, :cond_4

    .line 65
    .line 66
    if-eqz p4, :cond_4

    .line 67
    .line 68
    const/16 p1, 0x20

    .line 69
    .line 70
    shr-long p2, v0, p1

    .line 71
    .line 72
    long-to-int p2, p2

    .line 73
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    shr-long p3, p5, p1

    .line 78
    .line 79
    long-to-int p3, p3

    .line 80
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result p3

    .line 84
    invoke-static {p2, p3}, Ljava/lang/Math;->max(FF)F

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    const-wide p3, 0xffffffffL

    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    and-long/2addr v0, p3

    .line 94
    long-to-int v0, v0

    .line 95
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    and-long/2addr p5, p3

    .line 100
    long-to-int p5, p5

    .line 101
    invoke-static {p5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 102
    .line 103
    .line 104
    move-result p5

    .line 105
    invoke-static {v0, p5}, Ljava/lang/Math;->max(FF)F

    .line 106
    .line 107
    .line 108
    move-result p5

    .line 109
    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    int-to-long v0, p2

    .line 114
    invoke-static {p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    int-to-long p5, p2

    .line 119
    shl-long p1, v0, p1

    .line 120
    .line 121
    and-long/2addr p3, p5

    .line 122
    or-long/2addr p1, p3

    .line 123
    :cond_4
    iput-wide p1, p0, Lzl/o;->t:J

    .line 124
    .line 125
    return-void
.end method


# virtual methods
.method public final a(F)Z
    .locals 0

    .line 1
    iput p1, p0, Lzl/o;->q:F

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0
.end method

.method public final b(Le3/m;)Z
    .locals 0

    .line 1
    iput-object p1, p0, Lzl/o;->r:Le3/m;

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0
.end method

.method public final g()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lzl/o;->t:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final i(Lg3/d;)V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lzl/o;->p:Z

    .line 2
    .line 3
    iget-object v1, p0, Lzl/o;->i:Li3/c;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget v0, p0, Lzl/o;->q:F

    .line 8
    .line 9
    invoke-virtual {p0, p1, v1, v0}, Lzl/o;->j(Lg3/d;Li3/c;F)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget-object v0, p0, Lzl/o;->o:Lmy0/k;

    .line 14
    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    iget-object v0, p0, Lzl/o;->l:Lmy0/m;

    .line 18
    .line 19
    invoke-interface {v0}, Lmy0/m;->a()Lmy0/l;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lzl/o;->o:Lmy0/k;

    .line 24
    .line 25
    :cond_1
    check-cast v0, Lmy0/l;

    .line 26
    .line 27
    iget-wide v2, v0, Lmy0/l;->d:J

    .line 28
    .line 29
    invoke-static {v2, v3}, Lmy0/l;->a(J)J

    .line 30
    .line 31
    .line 32
    move-result-wide v2

    .line 33
    invoke-static {v2, v3}, Lmy0/c;->e(J)J

    .line 34
    .line 35
    .line 36
    move-result-wide v2

    .line 37
    long-to-float v0, v2

    .line 38
    iget-wide v2, p0, Lzl/o;->k:J

    .line 39
    .line 40
    invoke-static {v2, v3}, Lmy0/c;->e(J)J

    .line 41
    .line 42
    .line 43
    move-result-wide v2

    .line 44
    long-to-float v2, v2

    .line 45
    div-float/2addr v0, v2

    .line 46
    const/4 v2, 0x0

    .line 47
    const/high16 v3, 0x3f800000    # 1.0f

    .line 48
    .line 49
    invoke-static {v0, v2, v3}, Lkp/r9;->d(FFF)F

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    iget v4, p0, Lzl/o;->q:F

    .line 54
    .line 55
    mul-float/2addr v2, v4

    .line 56
    iget-boolean v5, p0, Lzl/o;->m:Z

    .line 57
    .line 58
    if-eqz v5, :cond_2

    .line 59
    .line 60
    sub-float/2addr v4, v2

    .line 61
    :cond_2
    cmpl-float v0, v0, v3

    .line 62
    .line 63
    const/4 v3, 0x1

    .line 64
    if-ltz v0, :cond_3

    .line 65
    .line 66
    move v0, v3

    .line 67
    goto :goto_0

    .line 68
    :cond_3
    const/4 v0, 0x0

    .line 69
    :goto_0
    iput-boolean v0, p0, Lzl/o;->p:Z

    .line 70
    .line 71
    iget-object v0, p0, Lzl/o;->s:Li3/c;

    .line 72
    .line 73
    invoke-virtual {p0, p1, v0, v4}, Lzl/o;->j(Lg3/d;Li3/c;F)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0, p1, v1, v2}, Lzl/o;->j(Lg3/d;Li3/c;F)V

    .line 77
    .line 78
    .line 79
    iget-boolean p1, p0, Lzl/o;->p:Z

    .line 80
    .line 81
    if-eqz p1, :cond_4

    .line 82
    .line 83
    const/4 p1, 0x0

    .line 84
    iput-object p1, p0, Lzl/o;->s:Li3/c;

    .line 85
    .line 86
    return-void

    .line 87
    :cond_4
    iget-object p0, p0, Lzl/o;->n:Ll2/g1;

    .line 88
    .line 89
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    add-int/2addr p1, v3

    .line 94
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 95
    .line 96
    .line 97
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
    iget-object v6, p0, Lzl/o;->j:Lt3/k;

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
    if-nez v2, :cond_5

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_5
    invoke-static {v0, v1}, Ld3/e;->e(J)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_6

    .line 69
    .line 70
    :goto_3
    iget-object v11, p0, Lzl/o;->r:Le3/m;

    .line 71
    .line 72
    move-object v7, p1

    .line 73
    move-object v6, p2

    .line 74
    move v10, p3

    .line 75
    invoke-virtual/range {v6 .. v11}, Li3/c;->f(Lg3/d;JFLe3/m;)V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :cond_6
    move-object v7, p1

    .line 80
    move-object v6, p2

    .line 81
    move v10, p3

    .line 82
    const/16 p1, 0x20

    .line 83
    .line 84
    shr-long p2, v0, p1

    .line 85
    .line 86
    long-to-int p2, p2

    .line 87
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    shr-long v2, v8, p1

    .line 92
    .line 93
    long-to-int p1, v2

    .line 94
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    sub-float/2addr p2, p1

    .line 99
    const/4 p1, 0x2

    .line 100
    int-to-float p1, p1

    .line 101
    div-float/2addr p2, p1

    .line 102
    const-wide v2, 0xffffffffL

    .line 103
    .line 104
    .line 105
    .line 106
    .line 107
    and-long/2addr v0, v2

    .line 108
    long-to-int p3, v0

    .line 109
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 110
    .line 111
    .line 112
    move-result p3

    .line 113
    and-long v0, v8, v2

    .line 114
    .line 115
    long-to-int v0, v0

    .line 116
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    sub-float/2addr p3, v0

    .line 121
    div-float/2addr p3, p1

    .line 122
    invoke-interface {v7}, Lg3/d;->x0()Lgw0/c;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    iget-object p1, p1, Lgw0/c;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast p1, Lbu/c;

    .line 129
    .line 130
    invoke-virtual {p1, p2, p3, p2, p3}, Lbu/c;->v(FFFF)V

    .line 131
    .line 132
    .line 133
    :try_start_0
    iget-object v11, p0, Lzl/o;->r:Le3/m;

    .line 134
    .line 135
    invoke-virtual/range {v6 .. v11}, Li3/c;->f(Lg3/d;JFLe3/m;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 136
    .line 137
    .line 138
    invoke-interface {v7}, Lg3/d;->x0()Lgw0/c;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    iget-object p0, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast p0, Lbu/c;

    .line 145
    .line 146
    neg-float p1, p2

    .line 147
    neg-float p2, p3

    .line 148
    invoke-virtual {p0, p1, p2, p1, p2}, Lbu/c;->v(FFFF)V

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :catchall_0
    move-exception v0

    .line 153
    move-object p0, v0

    .line 154
    invoke-interface {v7}, Lg3/d;->x0()Lgw0/c;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    iget-object p1, p1, Lgw0/c;->e:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast p1, Lbu/c;

    .line 161
    .line 162
    neg-float p2, p2

    .line 163
    neg-float p3, p3

    .line 164
    invoke-virtual {p1, p2, p3, p2, p3}, Lbu/c;->v(FFFF)V

    .line 165
    .line 166
    .line 167
    throw p0

    .line 168
    :cond_7
    :goto_4
    return-void
.end method
