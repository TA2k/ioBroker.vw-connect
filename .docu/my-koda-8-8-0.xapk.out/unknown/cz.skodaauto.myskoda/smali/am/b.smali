.class public abstract Lam/b;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p;
.implements Lv3/y;
.implements Lv3/x1;


# instance fields
.field public r:Lx2/e;

.field public s:Lt3/k;

.field public t:F

.field public u:Le3/m;

.field public v:Z

.field public w:Lzl/n;


# direct methods
.method public constructor <init>(Lx2/e;Lt3/k;FLe3/m;ZLzl/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lam/b;->r:Lx2/e;

    .line 5
    .line 6
    iput-object p2, p0, Lam/b;->s:Lt3/k;

    .line 7
    .line 8
    iput p3, p0, Lam/b;->t:F

    .line 9
    .line 10
    iput-object p4, p0, Lam/b;->u:Le3/m;

    .line 11
    .line 12
    iput-boolean p5, p0, Lam/b;->v:Z

    .line 13
    .line 14
    iput-object p6, p0, Lam/b;->w:Lzl/n;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lv3/j0;->d:Lg3/b;

    .line 6
    .line 7
    invoke-interface {v2}, Lg3/d;->e()J

    .line 8
    .line 9
    .line 10
    move-result-wide v3

    .line 11
    invoke-virtual {v0, v3, v4}, Lam/b;->X0(J)J

    .line 12
    .line 13
    .line 14
    move-result-wide v3

    .line 15
    iget-object v5, v0, Lam/b;->r:Lx2/e;

    .line 16
    .line 17
    invoke-static {v3, v4}, Lam/i;->e(J)J

    .line 18
    .line 19
    .line 20
    move-result-wide v6

    .line 21
    invoke-interface {v2}, Lg3/d;->e()J

    .line 22
    .line 23
    .line 24
    move-result-wide v8

    .line 25
    invoke-static {v8, v9}, Lam/i;->e(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide v8

    .line 29
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 30
    .line 31
    .line 32
    move-result-object v10

    .line 33
    invoke-interface/range {v5 .. v10}, Lx2/e;->a(JJLt4/m;)J

    .line 34
    .line 35
    .line 36
    move-result-wide v5

    .line 37
    const/16 v7, 0x20

    .line 38
    .line 39
    shr-long v8, v5, v7

    .line 40
    .line 41
    long-to-int v8, v8

    .line 42
    const-wide v9, 0xffffffffL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v5, v9

    .line 48
    long-to-int v5, v5

    .line 49
    iget-object v6, v2, Lg3/b;->e:Lgw0/c;

    .line 50
    .line 51
    invoke-virtual {v6}, Lgw0/c;->o()J

    .line 52
    .line 53
    .line 54
    move-result-wide v11

    .line 55
    invoke-virtual {v6}, Lgw0/c;->h()Le3/r;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-interface {v2}, Le3/r;->o()V

    .line 60
    .line 61
    .line 62
    :try_start_0
    iget-object v2, v6, Lgw0/c;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v2, Lbu/c;

    .line 65
    .line 66
    iget-object v13, v2, Lbu/c;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v13, Lgw0/c;

    .line 69
    .line 70
    iget-boolean v14, v0, Lam/b;->v:Z

    .line 71
    .line 72
    if-eqz v14, :cond_0

    .line 73
    .line 74
    invoke-virtual {v13}, Lgw0/c;->o()J

    .line 75
    .line 76
    .line 77
    move-result-wide v14

    .line 78
    shr-long/2addr v14, v7

    .line 79
    long-to-int v7, v14

    .line 80
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result v17

    .line 84
    invoke-virtual {v13}, Lgw0/c;->o()J

    .line 85
    .line 86
    .line 87
    move-result-wide v14

    .line 88
    and-long/2addr v9, v14

    .line 89
    long-to-int v7, v9

    .line 90
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 91
    .line 92
    .line 93
    move-result v18

    .line 94
    invoke-virtual {v13}, Lgw0/c;->h()Le3/r;

    .line 95
    .line 96
    .line 97
    move-result-object v14

    .line 98
    const/4 v15, 0x0

    .line 99
    const/16 v16, 0x0

    .line 100
    .line 101
    const/16 v19, 0x1

    .line 102
    .line 103
    invoke-interface/range {v14 .. v19}, Le3/r;->g(FFFFI)V

    .line 104
    .line 105
    .line 106
    :cond_0
    int-to-float v7, v8

    .line 107
    int-to-float v5, v5

    .line 108
    invoke-virtual {v2, v7, v5}, Lbu/c;->B(FF)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0}, Lam/b;->Y0()Li3/c;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    move-object v5, v2

    .line 116
    move-wide v2, v3

    .line 117
    iget v4, v0, Lam/b;->t:F

    .line 118
    .line 119
    iget-object v0, v0, Lam/b;->u:Le3/m;

    .line 120
    .line 121
    move-object/from16 v20, v5

    .line 122
    .line 123
    move-object v5, v0

    .line 124
    move-object/from16 v0, v20

    .line 125
    .line 126
    invoke-virtual/range {v0 .. v5}, Li3/c;->f(Lg3/d;JFLe3/m;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 127
    .line 128
    .line 129
    invoke-virtual {v6}, Lgw0/c;->h()Le3/r;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    invoke-interface {v0}, Le3/r;->i()V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v6, v11, v12}, Lgw0/c;->B(J)V

    .line 137
    .line 138
    .line 139
    invoke-virtual/range {p1 .. p1}, Lv3/j0;->b()V

    .line 140
    .line 141
    .line 142
    return-void

    .line 143
    :catchall_0
    move-exception v0

    .line 144
    invoke-static {v6, v11, v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 145
    .line 146
    .line 147
    throw v0
.end method

.method public final D(Lv3/p0;Lt3/p0;I)I
    .locals 6

    .line 1
    const/4 p1, 0x0

    .line 2
    const/16 v0, 0xd

    .line 3
    .line 4
    invoke-static {p3, p1, v0}, Lt4/b;->b(III)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iget-object p1, p0, Lam/b;->w:Lzl/n;

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lzl/n;->j(J)V

    .line 13
    .line 14
    .line 15
    :cond_0
    invoke-virtual {p0}, Lam/b;->Y0()Li3/c;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p1}, Li3/c;->g()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    cmp-long p1, v2, v4

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0, v0, v1}, Lam/b;->Z0(J)J

    .line 33
    .line 34
    .line 35
    move-result-wide p0

    .line 36
    invoke-interface {p2, p3}, Lt3/p0;->A(I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    invoke-static {p0, p1}, Lt4/a;->i(J)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-static {p0, p2}, Ljava/lang/Math;->max(II)I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    return p0

    .line 49
    :cond_1
    invoke-interface {p2, p3}, Lt3/p0;->A(I)I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    return p0
.end method

.method public final F0(Lv3/p0;Lt3/p0;I)I
    .locals 6

    .line 1
    const/4 p1, 0x0

    .line 2
    const/4 v0, 0x7

    .line 3
    invoke-static {p1, p3, v0}, Lt4/b;->b(III)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p1, p0, Lam/b;->w:Lzl/n;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p1, v0, v1}, Lzl/n;->j(J)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-virtual {p0}, Lam/b;->Y0()Li3/c;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p1}, Li3/c;->g()J

    .line 19
    .line 20
    .line 21
    move-result-wide v2

    .line 22
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    cmp-long p1, v2, v4

    .line 28
    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0, v0, v1}, Lam/b;->Z0(J)J

    .line 32
    .line 33
    .line 34
    move-result-wide p0

    .line 35
    invoke-interface {p2, p3}, Lt3/p0;->J(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    invoke-static {p0, p1}, Lt4/a;->j(J)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0, p2}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    return p0

    .line 48
    :cond_1
    invoke-interface {p2, p3}, Lt3/p0;->J(I)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    return p0
.end method

.method public final J(Lv3/p0;Lt3/p0;I)I
    .locals 6

    .line 1
    const/4 p1, 0x0

    .line 2
    const/16 v0, 0xd

    .line 3
    .line 4
    invoke-static {p3, p1, v0}, Lt4/b;->b(III)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iget-object p1, p0, Lam/b;->w:Lzl/n;

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Lzl/n;->j(J)V

    .line 13
    .line 14
    .line 15
    :cond_0
    invoke-virtual {p0}, Lam/b;->Y0()Li3/c;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p1}, Li3/c;->g()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    cmp-long p1, v2, v4

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0, v0, v1}, Lam/b;->Z0(J)J

    .line 33
    .line 34
    .line 35
    move-result-wide p0

    .line 36
    invoke-interface {p2, p3}, Lt3/p0;->c(I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    invoke-static {p0, p1}, Lt4/a;->i(J)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-static {p0, p2}, Ljava/lang/Math;->max(II)I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    return p0

    .line 49
    :cond_1
    invoke-interface {p2, p3}, Lt3/p0;->c(I)I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    return p0
.end method

.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final X(Lv3/p0;Lt3/p0;I)I
    .locals 6

    .line 1
    const/4 p1, 0x0

    .line 2
    const/4 v0, 0x7

    .line 3
    invoke-static {p1, p3, v0}, Lt4/b;->b(III)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p1, p0, Lam/b;->w:Lzl/n;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p1, v0, v1}, Lzl/n;->j(J)V

    .line 12
    .line 13
    .line 14
    :cond_0
    invoke-virtual {p0}, Lam/b;->Y0()Li3/c;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p1}, Li3/c;->g()J

    .line 19
    .line 20
    .line 21
    move-result-wide v2

    .line 22
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    cmp-long p1, v2, v4

    .line 28
    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0, v0, v1}, Lam/b;->Z0(J)J

    .line 32
    .line 33
    .line 34
    move-result-wide p0

    .line 35
    invoke-interface {p2, p3}, Lt3/p0;->G(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    invoke-static {p0, p1}, Lt4/a;->j(J)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0, p2}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    return p0

    .line 48
    :cond_1
    invoke-interface {p2, p3}, Lt3/p0;->G(I)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    return p0
.end method

.method public final X0(J)J
    .locals 10

    .line 1
    invoke-static {p1, p2}, Ld3/e;->e(J)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const-wide/16 p0, 0x0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :cond_0
    invoke-virtual {p0}, Lam/b;->Y0()Li3/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0}, Li3/c;->g()J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    const-wide v2, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    cmp-long v2, v0, v2

    .line 24
    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_1
    const/16 v2, 0x20

    .line 29
    .line 30
    shr-long v3, v0, v2

    .line 31
    .line 32
    long-to-int v3, v3

    .line 33
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    const v5, 0x7f7fffff    # Float.MAX_VALUE

    .line 42
    .line 43
    .line 44
    cmpg-float v4, v4, v5

    .line 45
    .line 46
    if-gtz v4, :cond_2

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    shr-long v3, p1, v2

    .line 50
    .line 51
    long-to-int v3, v3

    .line 52
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    :goto_0
    const-wide v6, 0xffffffffL

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    and-long/2addr v0, v6

    .line 62
    long-to-int v0, v0

    .line 63
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    cmpg-float v1, v1, v5

    .line 72
    .line 73
    if-gtz v1, :cond_3

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_3
    and-long v0, p1, v6

    .line 77
    .line 78
    long-to-int v0, v0

    .line 79
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    :goto_1
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    int-to-long v3, v1

    .line 88
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    int-to-long v0, v0

    .line 93
    shl-long/2addr v3, v2

    .line 94
    and-long/2addr v0, v6

    .line 95
    or-long/2addr v0, v3

    .line 96
    iget-object p0, p0, Lam/b;->s:Lt3/k;

    .line 97
    .line 98
    invoke-interface {p0, v0, v1, p1, p2}, Lt3/k;->a(JJ)J

    .line 99
    .line 100
    .line 101
    move-result-wide v3

    .line 102
    shr-long v8, v3, v2

    .line 103
    .line 104
    long-to-int p0, v8

    .line 105
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    cmpg-float p0, p0, v5

    .line 114
    .line 115
    if-gtz p0, :cond_4

    .line 116
    .line 117
    and-long/2addr v6, v3

    .line 118
    long-to-int p0, v6

    .line 119
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    cmpg-float p0, p0, v5

    .line 128
    .line 129
    if-gtz p0, :cond_4

    .line 130
    .line 131
    invoke-static {v0, v1, v3, v4}, Lt3/k1;->l(JJ)J

    .line 132
    .line 133
    .line 134
    move-result-wide p0

    .line 135
    return-wide p0

    .line 136
    :cond_4
    :goto_2
    return-wide p1
.end method

.method public abstract Y0()Li3/c;
.end method

.method public final Z0(J)J
    .locals 8

    .line 1
    invoke-static {p1, p2}, Lt4/a;->f(J)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, p2}, Lt4/a;->e(J)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    invoke-virtual {p0}, Lam/b;->Y0()Li3/c;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-static {p1, p2}, Lt4/a;->d(J)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    invoke-static {p1, p2}, Lt4/a;->c(J)Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    const/4 v3, 0x1

    .line 31
    goto :goto_0

    .line 32
    :cond_1
    const/4 v3, 0x0

    .line 33
    :goto_0
    invoke-virtual {v2}, Li3/c;->g()J

    .line 34
    .line 35
    .line 36
    move-result-wide v4

    .line 37
    const-wide v6, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    cmp-long v6, v4, v6

    .line 43
    .line 44
    if-nez v6, :cond_4

    .line 45
    .line 46
    if-eqz v3, :cond_3

    .line 47
    .line 48
    instance-of p0, v2, Lzl/h;

    .line 49
    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    check-cast v2, Lzl/h;

    .line 53
    .line 54
    iget-object p0, v2, Lzl/h;->x:Lyy0/l1;

    .line 55
    .line 56
    iget-object p0, p0, Lyy0/l1;->d:Lyy0/a2;

    .line 57
    .line 58
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lzl/g;

    .line 63
    .line 64
    invoke-interface {p0}, Lzl/g;->a()Li3/c;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-nez p0, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    invoke-static {p1, p2}, Lt4/a;->g(J)I

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    const/4 v5, 0x0

    .line 80
    const/16 v6, 0xa

    .line 81
    .line 82
    const/4 v3, 0x0

    .line 83
    move-wide v0, p1

    .line 84
    invoke-static/range {v0 .. v6}, Lt4/a;->a(JIIIII)J

    .line 85
    .line 86
    .line 87
    move-result-wide p0

    .line 88
    return-wide p0

    .line 89
    :cond_3
    :goto_1
    return-wide p1

    .line 90
    :cond_4
    const-wide v6, 0xffffffffL

    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    const/16 v2, 0x20

    .line 96
    .line 97
    if-eqz v3, :cond_6

    .line 98
    .line 99
    if-nez v0, :cond_5

    .line 100
    .line 101
    if-eqz v1, :cond_6

    .line 102
    .line 103
    :cond_5
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    int-to-float v0, v0

    .line 108
    invoke-static {p1, p2}, Lt4/a;->g(J)I

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    :goto_2
    int-to-float v1, v1

    .line 113
    goto :goto_4

    .line 114
    :cond_6
    shr-long v0, v4, v2

    .line 115
    .line 116
    long-to-int v0, v0

    .line 117
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    and-long v3, v4, v6

    .line 122
    .line 123
    long-to-int v1, v3

    .line 124
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    const v4, 0x7f7fffff    # Float.MAX_VALUE

    .line 133
    .line 134
    .line 135
    cmpg-float v3, v3, v4

    .line 136
    .line 137
    if-gtz v3, :cond_7

    .line 138
    .line 139
    sget v3, Lam/i;->b:I

    .line 140
    .line 141
    invoke-static {p1, p2}, Lt4/a;->j(J)I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    int-to-float v3, v3

    .line 146
    invoke-static {p1, p2}, Lt4/a;->h(J)I

    .line 147
    .line 148
    .line 149
    move-result v5

    .line 150
    int-to-float v5, v5

    .line 151
    invoke-static {v0, v3, v5}, Lkp/r9;->d(FFF)F

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    goto :goto_3

    .line 156
    :cond_7
    invoke-static {p1, p2}, Lt4/a;->j(J)I

    .line 157
    .line 158
    .line 159
    move-result v0

    .line 160
    int-to-float v0, v0

    .line 161
    :goto_3
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    cmpg-float v3, v3, v4

    .line 166
    .line 167
    if-gtz v3, :cond_8

    .line 168
    .line 169
    sget v3, Lam/i;->b:I

    .line 170
    .line 171
    invoke-static {p1, p2}, Lt4/a;->i(J)I

    .line 172
    .line 173
    .line 174
    move-result v3

    .line 175
    int-to-float v3, v3

    .line 176
    invoke-static {p1, p2}, Lt4/a;->g(J)I

    .line 177
    .line 178
    .line 179
    move-result v4

    .line 180
    int-to-float v4, v4

    .line 181
    invoke-static {v1, v3, v4}, Lkp/r9;->d(FFF)F

    .line 182
    .line 183
    .line 184
    move-result v1

    .line 185
    goto :goto_4

    .line 186
    :cond_8
    invoke-static {p1, p2}, Lt4/a;->i(J)I

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    goto :goto_2

    .line 191
    :goto_4
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    int-to-long v3, v0

    .line 196
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    int-to-long v0, v0

    .line 201
    shl-long/2addr v3, v2

    .line 202
    and-long/2addr v0, v6

    .line 203
    or-long/2addr v0, v3

    .line 204
    invoke-virtual {p0, v0, v1}, Lam/b;->X0(J)J

    .line 205
    .line 206
    .line 207
    move-result-wide v0

    .line 208
    shr-long v2, v0, v2

    .line 209
    .line 210
    long-to-int p0, v2

    .line 211
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 212
    .line 213
    .line 214
    move-result p0

    .line 215
    and-long/2addr v0, v6

    .line 216
    long-to-int v0, v0

    .line 217
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 218
    .line 219
    .line 220
    move-result v0

    .line 221
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 222
    .line 223
    .line 224
    move-result p0

    .line 225
    invoke-static {p0, p1, p2}, Lt4/b;->g(IJ)I

    .line 226
    .line 227
    .line 228
    move-result v2

    .line 229
    invoke-static {v0}, Lcy0/a;->i(F)I

    .line 230
    .line 231
    .line 232
    move-result p0

    .line 233
    invoke-static {p0, p1, p2}, Lt4/b;->f(IJ)I

    .line 234
    .line 235
    .line 236
    move-result v4

    .line 237
    const/4 v5, 0x0

    .line 238
    const/16 v6, 0xa

    .line 239
    .line 240
    const/4 v3, 0x0

    .line 241
    move-wide v0, p1

    .line 242
    invoke-static/range {v0 .. v6}, Lt4/a;->a(JIIIII)J

    .line 243
    .line 244
    .line 245
    move-result-wide p0

    .line 246
    return-wide p0
.end method

.method public final a0(Ld4/l;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 1

    .line 1
    iget-object v0, p0, Lam/b;->w:Lzl/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p3, p4}, Lzl/n;->j(J)V

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-virtual {p0, p3, p4}, Lam/b;->Z0(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide p3

    .line 12
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    iget p2, p0, Lt3/e1;->d:I

    .line 17
    .line 18
    iget p3, p0, Lt3/e1;->e:I

    .line 19
    .line 20
    new-instance p4, Lam/a;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    invoke-direct {p4, p0, v0}, Lam/a;-><init>(Lt3/e1;I)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 27
    .line 28
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
