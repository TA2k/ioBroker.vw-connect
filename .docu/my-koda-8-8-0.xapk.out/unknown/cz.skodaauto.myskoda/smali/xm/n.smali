.class public final Lxm/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/graphics/Matrix;

.field public final b:Landroid/graphics/Matrix;

.field public final c:Landroid/graphics/Matrix;

.field public final d:Landroid/graphics/Matrix;

.field public final e:[F

.field public final f:Lxm/i;

.field public final g:Lxm/e;

.field public final h:Lxm/h;

.field public final i:Lxm/f;

.field public final j:Lxm/f;

.field public final k:Lxm/f;

.field public final l:Lxm/f;

.field public final m:Lxm/f;

.field public final n:Lxm/f;

.field public final o:Z


# direct methods
.method public constructor <init>(Lbn/e;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Matrix;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lxm/n;->a:Landroid/graphics/Matrix;

    .line 10
    .line 11
    iget-object v0, p1, Lbn/e;->a:Lbn/c;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    move-object v0, v1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {v0}, Lbn/c;->p()Lxm/e;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :goto_0
    check-cast v0, Lxm/i;

    .line 23
    .line 24
    iput-object v0, p0, Lxm/n;->f:Lxm/i;

    .line 25
    .line 26
    iget-object v0, p1, Lbn/e;->b:Lbn/f;

    .line 27
    .line 28
    if-nez v0, :cond_1

    .line 29
    .line 30
    move-object v0, v1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    invoke-interface {v0}, Lbn/f;->p()Lxm/e;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :goto_1
    iput-object v0, p0, Lxm/n;->g:Lxm/e;

    .line 37
    .line 38
    iget-object v0, p1, Lbn/e;->c:Lbn/a;

    .line 39
    .line 40
    if-nez v0, :cond_2

    .line 41
    .line 42
    move-object v0, v1

    .line 43
    goto :goto_2

    .line 44
    :cond_2
    invoke-virtual {v0}, Lbn/a;->p()Lxm/e;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    :goto_2
    check-cast v0, Lxm/h;

    .line 49
    .line 50
    iput-object v0, p0, Lxm/n;->h:Lxm/h;

    .line 51
    .line 52
    iget-object v0, p1, Lbn/e;->d:Lbn/b;

    .line 53
    .line 54
    if-nez v0, :cond_3

    .line 55
    .line 56
    move-object v0, v1

    .line 57
    goto :goto_3

    .line 58
    :cond_3
    invoke-virtual {v0}, Lbn/b;->b0()Lxm/f;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    :goto_3
    iput-object v0, p0, Lxm/n;->i:Lxm/f;

    .line 63
    .line 64
    iget-object v0, p1, Lbn/e;->f:Lbn/b;

    .line 65
    .line 66
    if-nez v0, :cond_4

    .line 67
    .line 68
    move-object v0, v1

    .line 69
    goto :goto_4

    .line 70
    :cond_4
    invoke-virtual {v0}, Lbn/b;->b0()Lxm/f;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    :goto_4
    iput-object v0, p0, Lxm/n;->k:Lxm/f;

    .line 75
    .line 76
    iget-boolean v2, p1, Lbn/e;->j:Z

    .line 77
    .line 78
    iput-boolean v2, p0, Lxm/n;->o:Z

    .line 79
    .line 80
    if-eqz v0, :cond_5

    .line 81
    .line 82
    new-instance v0, Landroid/graphics/Matrix;

    .line 83
    .line 84
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 85
    .line 86
    .line 87
    iput-object v0, p0, Lxm/n;->b:Landroid/graphics/Matrix;

    .line 88
    .line 89
    new-instance v0, Landroid/graphics/Matrix;

    .line 90
    .line 91
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 92
    .line 93
    .line 94
    iput-object v0, p0, Lxm/n;->c:Landroid/graphics/Matrix;

    .line 95
    .line 96
    new-instance v0, Landroid/graphics/Matrix;

    .line 97
    .line 98
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 99
    .line 100
    .line 101
    iput-object v0, p0, Lxm/n;->d:Landroid/graphics/Matrix;

    .line 102
    .line 103
    const/16 v0, 0x9

    .line 104
    .line 105
    new-array v0, v0, [F

    .line 106
    .line 107
    iput-object v0, p0, Lxm/n;->e:[F

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_5
    iput-object v1, p0, Lxm/n;->b:Landroid/graphics/Matrix;

    .line 111
    .line 112
    iput-object v1, p0, Lxm/n;->c:Landroid/graphics/Matrix;

    .line 113
    .line 114
    iput-object v1, p0, Lxm/n;->d:Landroid/graphics/Matrix;

    .line 115
    .line 116
    iput-object v1, p0, Lxm/n;->e:[F

    .line 117
    .line 118
    :goto_5
    iget-object v0, p1, Lbn/e;->g:Lbn/b;

    .line 119
    .line 120
    if-nez v0, :cond_6

    .line 121
    .line 122
    move-object v0, v1

    .line 123
    goto :goto_6

    .line 124
    :cond_6
    invoke-virtual {v0}, Lbn/b;->b0()Lxm/f;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    :goto_6
    iput-object v0, p0, Lxm/n;->l:Lxm/f;

    .line 129
    .line 130
    iget-object v0, p1, Lbn/e;->e:Lbn/a;

    .line 131
    .line 132
    if-eqz v0, :cond_7

    .line 133
    .line 134
    invoke-virtual {v0}, Lbn/a;->p()Lxm/e;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    check-cast v0, Lxm/f;

    .line 139
    .line 140
    iput-object v0, p0, Lxm/n;->j:Lxm/f;

    .line 141
    .line 142
    :cond_7
    iget-object v0, p1, Lbn/e;->h:Lbn/b;

    .line 143
    .line 144
    if-eqz v0, :cond_8

    .line 145
    .line 146
    invoke-virtual {v0}, Lbn/b;->b0()Lxm/f;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    iput-object v0, p0, Lxm/n;->m:Lxm/f;

    .line 151
    .line 152
    goto :goto_7

    .line 153
    :cond_8
    iput-object v1, p0, Lxm/n;->m:Lxm/f;

    .line 154
    .line 155
    :goto_7
    iget-object p1, p1, Lbn/e;->i:Lbn/b;

    .line 156
    .line 157
    if-eqz p1, :cond_9

    .line 158
    .line 159
    invoke-virtual {p1}, Lbn/b;->b0()Lxm/f;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    iput-object p1, p0, Lxm/n;->n:Lxm/f;

    .line 164
    .line 165
    return-void

    .line 166
    :cond_9
    iput-object v1, p0, Lxm/n;->n:Lxm/f;

    .line 167
    .line 168
    return-void
.end method


# virtual methods
.method public final a(Ldn/b;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lxm/n;->j:Lxm/f;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxm/n;->m:Lxm/f;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lxm/n;->n:Lxm/f;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lxm/n;->f:Lxm/i;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lxm/n;->g:Lxm/e;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lxm/n;->h:Lxm/h;

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lxm/n;->i:Lxm/f;

    .line 32
    .line 33
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lxm/n;->k:Lxm/f;

    .line 37
    .line 38
    invoke-virtual {p1, v0}, Ldn/b;->f(Lxm/e;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lxm/n;->l:Lxm/f;

    .line 42
    .line 43
    invoke-virtual {p1, p0}, Ldn/b;->f(Lxm/e;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final b(Lxm/a;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lxm/n;->j:Lxm/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Lxm/n;->m:Lxm/f;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 13
    .line 14
    .line 15
    :cond_1
    iget-object v0, p0, Lxm/n;->n:Lxm/f;

    .line 16
    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 20
    .line 21
    .line 22
    :cond_2
    iget-object v0, p0, Lxm/n;->f:Lxm/i;

    .line 23
    .line 24
    if-eqz v0, :cond_3

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 27
    .line 28
    .line 29
    :cond_3
    iget-object v0, p0, Lxm/n;->g:Lxm/e;

    .line 30
    .line 31
    if-eqz v0, :cond_4

    .line 32
    .line 33
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 34
    .line 35
    .line 36
    :cond_4
    iget-object v0, p0, Lxm/n;->h:Lxm/h;

    .line 37
    .line 38
    if-eqz v0, :cond_5

    .line 39
    .line 40
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 41
    .line 42
    .line 43
    :cond_5
    iget-object v0, p0, Lxm/n;->i:Lxm/f;

    .line 44
    .line 45
    if-eqz v0, :cond_6

    .line 46
    .line 47
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 48
    .line 49
    .line 50
    :cond_6
    iget-object v0, p0, Lxm/n;->k:Lxm/f;

    .line 51
    .line 52
    if-eqz v0, :cond_7

    .line 53
    .line 54
    invoke-virtual {v0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 55
    .line 56
    .line 57
    :cond_7
    iget-object p0, p0, Lxm/n;->l:Lxm/f;

    .line 58
    .line 59
    if-eqz p0, :cond_8

    .line 60
    .line 61
    invoke-virtual {p0, p1}, Lxm/e;->a(Lxm/a;)V

    .line 62
    .line 63
    .line 64
    :cond_8
    return-void
.end method

.method public final c()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    const/16 v1, 0x9

    .line 3
    .line 4
    if-ge v0, v1, :cond_0

    .line 5
    .line 6
    iget-object v1, p0, Lxm/n;->e:[F

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    aput v2, v1, v0

    .line 10
    .line 11
    add-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    return-void
.end method

.method public final d()Landroid/graphics/Matrix;
    .locals 14

    .line 1
    iget-object v0, p0, Lxm/n;->a:Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/graphics/Matrix;->reset()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    iget-object v2, p0, Lxm/n;->g:Lxm/e;

    .line 8
    .line 9
    if-eqz v2, :cond_1

    .line 10
    .line 11
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    check-cast v3, Landroid/graphics/PointF;

    .line 16
    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    iget v4, v3, Landroid/graphics/PointF;->x:F

    .line 20
    .line 21
    cmpl-float v5, v4, v1

    .line 22
    .line 23
    if-nez v5, :cond_0

    .line 24
    .line 25
    iget v5, v3, Landroid/graphics/PointF;->y:F

    .line 26
    .line 27
    cmpl-float v5, v5, v1

    .line 28
    .line 29
    if-eqz v5, :cond_1

    .line 30
    .line 31
    :cond_0
    iget v3, v3, Landroid/graphics/PointF;->y:F

    .line 32
    .line 33
    invoke-virtual {v0, v4, v3}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 34
    .line 35
    .line 36
    :cond_1
    iget-boolean v3, p0, Lxm/n;->o:Z

    .line 37
    .line 38
    if-eqz v3, :cond_2

    .line 39
    .line 40
    if-eqz v2, :cond_3

    .line 41
    .line 42
    iget v3, v2, Lxm/e;->d:F

    .line 43
    .line 44
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v4

    .line 48
    check-cast v4, Landroid/graphics/PointF;

    .line 49
    .line 50
    iget v5, v4, Landroid/graphics/PointF;->x:F

    .line 51
    .line 52
    iget v4, v4, Landroid/graphics/PointF;->y:F

    .line 53
    .line 54
    const v6, 0x38d1b717    # 1.0E-4f

    .line 55
    .line 56
    .line 57
    add-float/2addr v6, v3

    .line 58
    invoke-virtual {v2, v6}, Lxm/e;->g(F)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    check-cast v6, Landroid/graphics/PointF;

    .line 66
    .line 67
    invoke-virtual {v2, v3}, Lxm/e;->g(F)V

    .line 68
    .line 69
    .line 70
    iget v2, v6, Landroid/graphics/PointF;->y:F

    .line 71
    .line 72
    sub-float/2addr v2, v4

    .line 73
    float-to-double v2, v2

    .line 74
    iget v4, v6, Landroid/graphics/PointF;->x:F

    .line 75
    .line 76
    sub-float/2addr v4, v5

    .line 77
    float-to-double v4, v4

    .line 78
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Math;->atan2(DD)D

    .line 79
    .line 80
    .line 81
    move-result-wide v2

    .line 82
    invoke-static {v2, v3}, Ljava/lang/Math;->toDegrees(D)D

    .line 83
    .line 84
    .line 85
    move-result-wide v2

    .line 86
    double-to-float v2, v2

    .line 87
    invoke-virtual {v0, v2}, Landroid/graphics/Matrix;->preRotate(F)Z

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_2
    iget-object v2, p0, Lxm/n;->i:Lxm/f;

    .line 92
    .line 93
    if-eqz v2, :cond_3

    .line 94
    .line 95
    invoke-virtual {v2}, Lxm/f;->i()F

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    cmpl-float v3, v2, v1

    .line 100
    .line 101
    if-eqz v3, :cond_3

    .line 102
    .line 103
    invoke-virtual {v0, v2}, Landroid/graphics/Matrix;->preRotate(F)Z

    .line 104
    .line 105
    .line 106
    :cond_3
    :goto_0
    const/high16 v2, 0x3f800000    # 1.0f

    .line 107
    .line 108
    iget-object v3, p0, Lxm/n;->k:Lxm/f;

    .line 109
    .line 110
    if-eqz v3, :cond_6

    .line 111
    .line 112
    const/high16 v4, 0x42b40000    # 90.0f

    .line 113
    .line 114
    iget-object v5, p0, Lxm/n;->l:Lxm/f;

    .line 115
    .line 116
    if-nez v5, :cond_4

    .line 117
    .line 118
    move v6, v1

    .line 119
    goto :goto_1

    .line 120
    :cond_4
    invoke-virtual {v5}, Lxm/f;->i()F

    .line 121
    .line 122
    .line 123
    move-result v6

    .line 124
    neg-float v6, v6

    .line 125
    add-float/2addr v6, v4

    .line 126
    float-to-double v6, v6

    .line 127
    invoke-static {v6, v7}, Ljava/lang/Math;->toRadians(D)D

    .line 128
    .line 129
    .line 130
    move-result-wide v6

    .line 131
    invoke-static {v6, v7}, Ljava/lang/Math;->cos(D)D

    .line 132
    .line 133
    .line 134
    move-result-wide v6

    .line 135
    double-to-float v6, v6

    .line 136
    :goto_1
    if-nez v5, :cond_5

    .line 137
    .line 138
    move v4, v2

    .line 139
    goto :goto_2

    .line 140
    :cond_5
    invoke-virtual {v5}, Lxm/f;->i()F

    .line 141
    .line 142
    .line 143
    move-result v5

    .line 144
    neg-float v5, v5

    .line 145
    add-float/2addr v5, v4

    .line 146
    float-to-double v4, v5

    .line 147
    invoke-static {v4, v5}, Ljava/lang/Math;->toRadians(D)D

    .line 148
    .line 149
    .line 150
    move-result-wide v4

    .line 151
    invoke-static {v4, v5}, Ljava/lang/Math;->sin(D)D

    .line 152
    .line 153
    .line 154
    move-result-wide v4

    .line 155
    double-to-float v4, v4

    .line 156
    :goto_2
    invoke-virtual {v3}, Lxm/f;->i()F

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    float-to-double v7, v3

    .line 161
    invoke-static {v7, v8}, Ljava/lang/Math;->toRadians(D)D

    .line 162
    .line 163
    .line 164
    move-result-wide v7

    .line 165
    invoke-static {v7, v8}, Ljava/lang/Math;->tan(D)D

    .line 166
    .line 167
    .line 168
    move-result-wide v7

    .line 169
    double-to-float v3, v7

    .line 170
    invoke-virtual {p0}, Lxm/n;->c()V

    .line 171
    .line 172
    .line 173
    iget-object v5, p0, Lxm/n;->e:[F

    .line 174
    .line 175
    const/4 v7, 0x0

    .line 176
    aput v6, v5, v7

    .line 177
    .line 178
    const/4 v8, 0x1

    .line 179
    aput v4, v5, v8

    .line 180
    .line 181
    neg-float v9, v4

    .line 182
    const/4 v10, 0x3

    .line 183
    aput v9, v5, v10

    .line 184
    .line 185
    const/4 v11, 0x4

    .line 186
    aput v6, v5, v11

    .line 187
    .line 188
    const/16 v12, 0x8

    .line 189
    .line 190
    aput v2, v5, v12

    .line 191
    .line 192
    iget-object v13, p0, Lxm/n;->b:Landroid/graphics/Matrix;

    .line 193
    .line 194
    invoke-virtual {v13, v5}, Landroid/graphics/Matrix;->setValues([F)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {p0}, Lxm/n;->c()V

    .line 198
    .line 199
    .line 200
    aput v2, v5, v7

    .line 201
    .line 202
    aput v3, v5, v10

    .line 203
    .line 204
    aput v2, v5, v11

    .line 205
    .line 206
    aput v2, v5, v12

    .line 207
    .line 208
    iget-object v3, p0, Lxm/n;->c:Landroid/graphics/Matrix;

    .line 209
    .line 210
    invoke-virtual {v3, v5}, Landroid/graphics/Matrix;->setValues([F)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {p0}, Lxm/n;->c()V

    .line 214
    .line 215
    .line 216
    aput v6, v5, v7

    .line 217
    .line 218
    aput v9, v5, v8

    .line 219
    .line 220
    aput v4, v5, v10

    .line 221
    .line 222
    aput v6, v5, v11

    .line 223
    .line 224
    aput v2, v5, v12

    .line 225
    .line 226
    iget-object v4, p0, Lxm/n;->d:Landroid/graphics/Matrix;

    .line 227
    .line 228
    invoke-virtual {v4, v5}, Landroid/graphics/Matrix;->setValues([F)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v3, v13}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 232
    .line 233
    .line 234
    invoke-virtual {v4, v3}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 235
    .line 236
    .line 237
    invoke-virtual {v0, v4}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 238
    .line 239
    .line 240
    :cond_6
    iget-object v3, p0, Lxm/n;->h:Lxm/h;

    .line 241
    .line 242
    if-eqz v3, :cond_8

    .line 243
    .line 244
    invoke-virtual {v3}, Lxm/e;->d()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    check-cast v3, Lhn/b;

    .line 249
    .line 250
    if-eqz v3, :cond_8

    .line 251
    .line 252
    iget v4, v3, Lhn/b;->a:F

    .line 253
    .line 254
    cmpl-float v5, v4, v2

    .line 255
    .line 256
    if-nez v5, :cond_7

    .line 257
    .line 258
    iget v5, v3, Lhn/b;->b:F

    .line 259
    .line 260
    cmpl-float v2, v5, v2

    .line 261
    .line 262
    if-eqz v2, :cond_8

    .line 263
    .line 264
    :cond_7
    iget v2, v3, Lhn/b;->b:F

    .line 265
    .line 266
    invoke-virtual {v0, v4, v2}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 267
    .line 268
    .line 269
    :cond_8
    iget-object p0, p0, Lxm/n;->f:Lxm/i;

    .line 270
    .line 271
    if-eqz p0, :cond_a

    .line 272
    .line 273
    invoke-virtual {p0}, Lxm/e;->d()Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    check-cast p0, Landroid/graphics/PointF;

    .line 278
    .line 279
    if-eqz p0, :cond_a

    .line 280
    .line 281
    iget v2, p0, Landroid/graphics/PointF;->x:F

    .line 282
    .line 283
    cmpl-float v3, v2, v1

    .line 284
    .line 285
    if-nez v3, :cond_9

    .line 286
    .line 287
    iget v3, p0, Landroid/graphics/PointF;->y:F

    .line 288
    .line 289
    cmpl-float v1, v3, v1

    .line 290
    .line 291
    if-eqz v1, :cond_a

    .line 292
    .line 293
    :cond_9
    neg-float v1, v2

    .line 294
    iget p0, p0, Landroid/graphics/PointF;->y:F

    .line 295
    .line 296
    neg-float p0, p0

    .line 297
    invoke-virtual {v0, v1, p0}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 298
    .line 299
    .line 300
    :cond_a
    return-object v0
.end method

.method public final e(F)Landroid/graphics/Matrix;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lxm/n;->g:Lxm/e;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move-object v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Landroid/graphics/PointF;

    .line 13
    .line 14
    :goto_0
    iget-object v2, p0, Lxm/n;->h:Lxm/h;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move-object v2, v0

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Lhn/b;

    .line 25
    .line 26
    :goto_1
    iget-object v3, p0, Lxm/n;->a:Landroid/graphics/Matrix;

    .line 27
    .line 28
    invoke-virtual {v3}, Landroid/graphics/Matrix;->reset()V

    .line 29
    .line 30
    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget v4, v1, Landroid/graphics/PointF;->x:F

    .line 34
    .line 35
    mul-float/2addr v4, p1

    .line 36
    iget v1, v1, Landroid/graphics/PointF;->y:F

    .line 37
    .line 38
    mul-float/2addr v1, p1

    .line 39
    invoke-virtual {v3, v4, v1}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 40
    .line 41
    .line 42
    :cond_2
    if-eqz v2, :cond_3

    .line 43
    .line 44
    iget v1, v2, Lhn/b;->a:F

    .line 45
    .line 46
    float-to-double v4, v1

    .line 47
    float-to-double v6, p1

    .line 48
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 49
    .line 50
    .line 51
    move-result-wide v4

    .line 52
    double-to-float v1, v4

    .line 53
    iget v2, v2, Lhn/b;->b:F

    .line 54
    .line 55
    float-to-double v4, v2

    .line 56
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 57
    .line 58
    .line 59
    move-result-wide v4

    .line 60
    double-to-float v2, v4

    .line 61
    invoke-virtual {v3, v1, v2}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 62
    .line 63
    .line 64
    :cond_3
    iget-object v1, p0, Lxm/n;->i:Lxm/f;

    .line 65
    .line 66
    if-eqz v1, :cond_7

    .line 67
    .line 68
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    check-cast v1, Ljava/lang/Float;

    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    iget-object p0, p0, Lxm/n;->f:Lxm/i;

    .line 79
    .line 80
    if-nez p0, :cond_4

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    invoke-virtual {p0}, Lxm/e;->d()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    move-object v0, p0

    .line 88
    check-cast v0, Landroid/graphics/PointF;

    .line 89
    .line 90
    :goto_2
    mul-float/2addr v1, p1

    .line 91
    const/4 p0, 0x0

    .line 92
    if-nez v0, :cond_5

    .line 93
    .line 94
    move p1, p0

    .line 95
    goto :goto_3

    .line 96
    :cond_5
    iget p1, v0, Landroid/graphics/PointF;->x:F

    .line 97
    .line 98
    :goto_3
    if-nez v0, :cond_6

    .line 99
    .line 100
    goto :goto_4

    .line 101
    :cond_6
    iget p0, v0, Landroid/graphics/PointF;->y:F

    .line 102
    .line 103
    :goto_4
    invoke-virtual {v3, v1, p1, p0}, Landroid/graphics/Matrix;->preRotate(FFF)Z

    .line 104
    .line 105
    .line 106
    :cond_7
    return-object v3
.end method
