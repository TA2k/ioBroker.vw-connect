.class public abstract Lcom/google/android/gms/internal/measurement/z3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Lss/b;


# direct methods
.method public static final a(Lum/a;Lay0/a;Lx2/s;Lt3/k;Ll2/o;III)V
    .locals 15

    .line 1
    move-object/from16 v3, p2

    .line 2
    .line 3
    const-string v0, "progress"

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v0, p4

    .line 11
    .line 12
    check-cast v0, Ll2/t;

    .line 13
    .line 14
    const v1, 0x16d2bdc6

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    move/from16 v1, p7

    .line 21
    .line 22
    and-int/lit16 v4, v1, 0x800

    .line 23
    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    sget-object v4, Lt3/j;->b:Lt3/x0;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move-object/from16 v4, p3

    .line 30
    .line 31
    :goto_0
    const v5, 0xb0932b9

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, v5}, Ll2/t;->Z(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 42
    .line 43
    if-ne v5, v6, :cond_1

    .line 44
    .line 45
    new-instance v5, Lum/j;

    .line 46
    .line 47
    invoke-direct {v5}, Lum/j;-><init>()V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    move-object v8, v5

    .line 54
    check-cast v8, Lum/j;

    .line 55
    .line 56
    const/4 v13, 0x0

    .line 57
    invoke-virtual {v0, v13}, Ll2/t;->q(Z)V

    .line 58
    .line 59
    .line 60
    const v5, 0xb0932e8

    .line 61
    .line 62
    .line 63
    invoke-virtual {v0, v5}, Ll2/t;->Z(I)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    if-ne v5, v6, :cond_2

    .line 71
    .line 72
    new-instance v5, Landroid/graphics/Matrix;

    .line 73
    .line 74
    invoke-direct {v5}, Landroid/graphics/Matrix;-><init>()V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_2
    move-object v7, v5

    .line 81
    check-cast v7, Landroid/graphics/Matrix;

    .line 82
    .line 83
    invoke-virtual {v0, v13}, Ll2/t;->q(Z)V

    .line 84
    .line 85
    .line 86
    const v5, 0xb093338

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, v5}, Ll2/t;->Z(I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v5

    .line 96
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v9

    .line 100
    if-nez v5, :cond_3

    .line 101
    .line 102
    if-ne v9, v6, :cond_4

    .line 103
    .line 104
    :cond_3
    const/4 v5, 0x0

    .line 105
    invoke-static {v5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 106
    .line 107
    .line 108
    move-result-object v9

    .line 109
    invoke-virtual {v0, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    :cond_4
    move-object v12, v9

    .line 113
    check-cast v12, Ll2/b1;

    .line 114
    .line 115
    invoke-virtual {v0, v13}, Ll2/t;->q(Z)V

    .line 116
    .line 117
    .line 118
    const v5, 0xb09336c

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, v5}, Ll2/t;->Z(I)V

    .line 122
    .line 123
    .line 124
    if-eqz p0, :cond_6

    .line 125
    .line 126
    invoke-virtual {p0}, Lum/a;->b()F

    .line 127
    .line 128
    .line 129
    move-result v5

    .line 130
    const/4 v6, 0x0

    .line 131
    cmpg-float v5, v5, v6

    .line 132
    .line 133
    if-nez v5, :cond_5

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_5
    invoke-virtual {v0, v13}, Ll2/t;->q(Z)V

    .line 137
    .line 138
    .line 139
    iget-object v5, p0, Lum/a;->k:Landroid/graphics/Rect;

    .line 140
    .line 141
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 142
    .line 143
    invoke-virtual {v0, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    move-object v10, v6

    .line 148
    check-cast v10, Landroid/content/Context;

    .line 149
    .line 150
    invoke-virtual {v5}, Landroid/graphics/Rect;->width()I

    .line 151
    .line 152
    .line 153
    move-result v6

    .line 154
    invoke-virtual {v5}, Landroid/graphics/Rect;->height()I

    .line 155
    .line 156
    .line 157
    move-result v9

    .line 158
    const-string v11, "<this>"

    .line 159
    .line 160
    invoke-static {v3, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    new-instance v11, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;

    .line 164
    .line 165
    invoke-direct {v11, v6, v9}, Lcom/airbnb/lottie/compose/LottieAnimationSizeElement;-><init>(II)V

    .line 166
    .line 167
    .line 168
    invoke-interface {v3, v11}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 169
    .line 170
    .line 171
    move-result-object v14

    .line 172
    move-object v6, v4

    .line 173
    new-instance v4, Lym/i;

    .line 174
    .line 175
    move-object v9, p0

    .line 176
    move-object v11, v2

    .line 177
    invoke-direct/range {v4 .. v12}, Lym/i;-><init>(Landroid/graphics/Rect;Lt3/k;Landroid/graphics/Matrix;Lum/j;Lum/a;Landroid/content/Context;Lay0/a;Ll2/b1;)V

    .line 178
    .line 179
    .line 180
    move-object v2, v4

    .line 181
    move-object v4, v6

    .line 182
    invoke-static {v14, v2, v0, v13}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 186
    .line 187
    .line 188
    move-result-object v9

    .line 189
    if-eqz v9, :cond_7

    .line 190
    .line 191
    new-instance v0, Lym/h;

    .line 192
    .line 193
    const/4 v8, 0x1

    .line 194
    move-object/from16 v2, p1

    .line 195
    .line 196
    move/from16 v5, p5

    .line 197
    .line 198
    move/from16 v6, p6

    .line 199
    .line 200
    move v7, v1

    .line 201
    move-object v1, p0

    .line 202
    invoke-direct/range {v0 .. v8}, Lym/h;-><init>(Lum/a;Lay0/a;Lx2/s;Lt3/k;IIII)V

    .line 203
    .line 204
    .line 205
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 206
    .line 207
    return-void

    .line 208
    :cond_6
    :goto_1
    shr-int/lit8 v1, p5, 0x6

    .line 209
    .line 210
    and-int/lit8 v1, v1, 0xe

    .line 211
    .line 212
    invoke-static {v3, v0, v1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, v13}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 219
    .line 220
    .line 221
    move-result-object v9

    .line 222
    if-eqz v9, :cond_7

    .line 223
    .line 224
    new-instance v0, Lym/h;

    .line 225
    .line 226
    const/4 v8, 0x0

    .line 227
    move-object v1, p0

    .line 228
    move-object/from16 v2, p1

    .line 229
    .line 230
    move/from16 v5, p5

    .line 231
    .line 232
    move/from16 v6, p6

    .line 233
    .line 234
    move/from16 v7, p7

    .line 235
    .line 236
    invoke-direct/range {v0 .. v8}, Lym/h;-><init>(Lum/a;Lay0/a;Lx2/s;Lt3/k;IIII)V

    .line 237
    .line 238
    .line 239
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 240
    .line 241
    :cond_7
    return-void
.end method

.method public static final b(La3/h;J)Z
    .locals 10

    .line 1
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 2
    .line 3
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object v0, v0, Lv3/h0;->H:Lg1/q;

    .line 13
    .line 14
    iget-object v0, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lv3/u;

    .line 17
    .line 18
    iget-object v1, v0, Lv3/u;->S:Lv3/z1;

    .line 19
    .line 20
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 21
    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const-wide/16 v1, 0x0

    .line 26
    .line 27
    invoke-virtual {v0, v1, v2}, Lv3/f1;->R(J)J

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    const/16 v2, 0x20

    .line 32
    .line 33
    shr-long v3, v0, v2

    .line 34
    .line 35
    long-to-int v3, v3

    .line 36
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    const-wide v4, 0xffffffffL

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    and-long/2addr v0, v4

    .line 46
    long-to-int v0, v0

    .line 47
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget-wide v6, p0, La3/h;->t:J

    .line 52
    .line 53
    shr-long v8, v6, v2

    .line 54
    .line 55
    long-to-int p0, v8

    .line 56
    int-to-float p0, p0

    .line 57
    add-float/2addr p0, v3

    .line 58
    and-long/2addr v6, v4

    .line 59
    long-to-int v1, v6

    .line 60
    int-to-float v1, v1

    .line 61
    add-float/2addr v1, v0

    .line 62
    shr-long v6, p1, v2

    .line 63
    .line 64
    long-to-int v2, v6

    .line 65
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    cmpg-float v3, v3, v2

    .line 70
    .line 71
    if-gtz v3, :cond_2

    .line 72
    .line 73
    cmpg-float p0, v2, p0

    .line 74
    .line 75
    if-gtz p0, :cond_2

    .line 76
    .line 77
    and-long p0, p1, v4

    .line 78
    .line 79
    long-to-int p0, p0

    .line 80
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    cmpg-float p1, v0, p0

    .line 85
    .line 86
    if-gtz p1, :cond_2

    .line 87
    .line 88
    cmpg-float p0, p0, v1

    .line 89
    .line 90
    if-gtz p0, :cond_2

    .line 91
    .line 92
    const/4 p0, 0x1

    .line 93
    return p0

    .line 94
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 95
    return p0
.end method

.method public static final c(Ll2/i2;Ll2/c;I)V
    .locals 2

    .line 1
    :goto_0
    iget v0, p0, Ll2/i2;->v:I

    .line 2
    .line 3
    if-le p2, v0, :cond_0

    .line 4
    .line 5
    iget v1, p0, Ll2/i2;->u:I

    .line 6
    .line 7
    if-lt p2, v1, :cond_1

    .line 8
    .line 9
    :cond_0
    if-nez v0, :cond_2

    .line 10
    .line 11
    if-nez p2, :cond_2

    .line 12
    .line 13
    :cond_1
    return-void

    .line 14
    :cond_2
    invoke-virtual {p0}, Ll2/i2;->L()V

    .line 15
    .line 16
    .line 17
    iget v0, p0, Ll2/i2;->v:I

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ll2/i2;->x(I)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_3

    .line 24
    .line 25
    invoke-interface {p1}, Ll2/c;->o()V

    .line 26
    .line 27
    .line 28
    :cond_3
    invoke-virtual {p0}, Ll2/i2;->j()V

    .line 29
    .line 30
    .line 31
    goto :goto_0
.end method
