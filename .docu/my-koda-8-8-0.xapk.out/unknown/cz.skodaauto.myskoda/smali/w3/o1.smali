.class public final Lw3/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/n1;


# instance fields
.field public d:Lh3/c;

.field public final e:Le3/w;

.field public final f:Lw3/t;

.field public g:Lay0/n;

.field public h:Lay0/a;

.field public i:J

.field public j:Z

.field public final k:[F

.field public l:[F

.field public m:Z

.field public n:Lt4/c;

.field public o:Lt4/m;

.field public final p:Lg3/b;

.field public q:I

.field public r:J

.field public s:Le3/g0;

.field public t:Z

.field public u:Z

.field public v:Z

.field public w:Z

.field public final x:Lw3/a0;


# direct methods
.method public constructor <init>(Lh3/c;Le3/w;Lw3/t;Lay0/n;Lay0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/o1;->d:Lh3/c;

    .line 5
    .line 6
    iput-object p2, p0, Lw3/o1;->e:Le3/w;

    .line 7
    .line 8
    iput-object p3, p0, Lw3/o1;->f:Lw3/t;

    .line 9
    .line 10
    iput-object p4, p0, Lw3/o1;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lw3/o1;->h:Lay0/a;

    .line 13
    .line 14
    const p1, 0x7fffffff

    .line 15
    .line 16
    .line 17
    int-to-long p1, p1

    .line 18
    const/16 p3, 0x20

    .line 19
    .line 20
    shl-long p3, p1, p3

    .line 21
    .line 22
    const-wide v0, 0xffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    and-long/2addr p1, v0

    .line 28
    or-long/2addr p1, p3

    .line 29
    iput-wide p1, p0, Lw3/o1;->i:J

    .line 30
    .line 31
    invoke-static {}, Le3/c0;->a()[F

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lw3/o1;->k:[F

    .line 36
    .line 37
    invoke-static {}, Lkp/b9;->a()Lt4/d;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Lw3/o1;->n:Lt4/c;

    .line 42
    .line 43
    sget-object p1, Lt4/m;->d:Lt4/m;

    .line 44
    .line 45
    iput-object p1, p0, Lw3/o1;->o:Lt4/m;

    .line 46
    .line 47
    new-instance p1, Lg3/b;

    .line 48
    .line 49
    invoke-direct {p1}, Lg3/b;-><init>()V

    .line 50
    .line 51
    .line 52
    iput-object p1, p0, Lw3/o1;->p:Lg3/b;

    .line 53
    .line 54
    sget-wide p1, Le3/q0;->b:J

    .line 55
    .line 56
    iput-wide p1, p0, Lw3/o1;->r:J

    .line 57
    .line 58
    const/4 p1, 0x1

    .line 59
    iput-boolean p1, p0, Lw3/o1;->v:Z

    .line 60
    .line 61
    new-instance p1, Lw3/a0;

    .line 62
    .line 63
    const/4 p2, 0x4

    .line 64
    invoke-direct {p1, p0, p2}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 65
    .line 66
    .line 67
    iput-object p1, p0, Lw3/o1;->x:Lw3/a0;

    .line 68
    .line 69
    return-void
.end method


# virtual methods
.method public final a()[F
    .locals 4

    .line 1
    iget-object v0, p0, Lw3/o1;->l:[F

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Le3/c0;->a()[F

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lw3/o1;->l:[F

    .line 10
    .line 11
    :cond_0
    iget-boolean v1, p0, Lw3/o1;->u:Z

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    aget p0, v0, v2

    .line 18
    .line 19
    invoke-static {p0}, Ljava/lang/Float;->isNaN(F)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_3

    .line 24
    .line 25
    return-object v3

    .line 26
    :cond_1
    iput-boolean v2, p0, Lw3/o1;->u:Z

    .line 27
    .line 28
    invoke-virtual {p0}, Lw3/o1;->b()[F

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    iget-boolean p0, p0, Lw3/o1;->v:Z

    .line 33
    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    return-object v1

    .line 37
    :cond_2
    invoke-static {v1, v0}, Lw3/h0;->w([F[F)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_4

    .line 42
    .line 43
    :cond_3
    return-object v0

    .line 44
    :cond_4
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 45
    .line 46
    aput p0, v0, v2

    .line 47
    .line 48
    return-object v3
.end method

.method public final b()[F
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lw3/o1;->t:Z

    .line 4
    .line 5
    iget-object v2, v0, Lw3/o1;->k:[F

    .line 6
    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    iget-object v1, v0, Lw3/o1;->d:Lh3/c;

    .line 10
    .line 11
    iget-wide v3, v1, Lh3/c;->v:J

    .line 12
    .line 13
    iget-object v1, v1, Lh3/c;->a:Lh3/d;

    .line 14
    .line 15
    const-wide v5, 0x7fffffff7fffffffL

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    and-long/2addr v5, v3

    .line 21
    const-wide v7, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    cmp-long v5, v5, v7

    .line 27
    .line 28
    if-nez v5, :cond_0

    .line 29
    .line 30
    iget-wide v3, v0, Lw3/o1;->i:J

    .line 31
    .line 32
    invoke-static {v3, v4}, Lkp/f9;->c(J)J

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    invoke-static {v3, v4}, Ljp/ef;->d(J)J

    .line 37
    .line 38
    .line 39
    move-result-wide v3

    .line 40
    :cond_0
    const/16 v5, 0x20

    .line 41
    .line 42
    shr-long v5, v3, v5

    .line 43
    .line 44
    long-to-int v5, v5

    .line 45
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    const-wide v6, 0xffffffffL

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    and-long/2addr v3, v6

    .line 55
    long-to-int v3, v3

    .line 56
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    iget v4, v1, Lh3/d;->l:F

    .line 61
    .line 62
    iget v6, v1, Lh3/d;->m:F

    .line 63
    .line 64
    iget v7, v1, Lh3/d;->q:F

    .line 65
    .line 66
    iget v8, v1, Lh3/d;->r:F

    .line 67
    .line 68
    iget v9, v1, Lh3/d;->s:F

    .line 69
    .line 70
    iget v10, v1, Lh3/d;->j:F

    .line 71
    .line 72
    iget v1, v1, Lh3/d;->k:F

    .line 73
    .line 74
    float-to-double v11, v7

    .line 75
    const-wide v13, 0x3f91df46a2529d39L    # 0.017453292519943295

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    mul-double/2addr v11, v13

    .line 81
    move-wide v15, v13

    .line 82
    invoke-static {v11, v12}, Ljava/lang/Math;->sin(D)D

    .line 83
    .line 84
    .line 85
    move-result-wide v13

    .line 86
    double-to-float v7, v13

    .line 87
    invoke-static {v11, v12}, Ljava/lang/Math;->cos(D)D

    .line 88
    .line 89
    .line 90
    move-result-wide v11

    .line 91
    double-to-float v11, v11

    .line 92
    neg-float v12, v7

    .line 93
    mul-float v13, v6, v11

    .line 94
    .line 95
    const/high16 v14, 0x3f800000    # 1.0f

    .line 96
    .line 97
    mul-float v17, v14, v7

    .line 98
    .line 99
    sub-float v13, v13, v17

    .line 100
    .line 101
    mul-float/2addr v6, v7

    .line 102
    mul-float v17, v14, v11

    .line 103
    .line 104
    add-float v17, v17, v6

    .line 105
    .line 106
    move v6, v14

    .line 107
    move-wide/from16 v18, v15

    .line 108
    .line 109
    float-to-double v14, v8

    .line 110
    mul-double v14, v14, v18

    .line 111
    .line 112
    move/from16 v16, v6

    .line 113
    .line 114
    move v8, v7

    .line 115
    invoke-static {v14, v15}, Ljava/lang/Math;->sin(D)D

    .line 116
    .line 117
    .line 118
    move-result-wide v6

    .line 119
    double-to-float v6, v6

    .line 120
    invoke-static {v14, v15}, Ljava/lang/Math;->cos(D)D

    .line 121
    .line 122
    .line 123
    move-result-wide v14

    .line 124
    double-to-float v7, v14

    .line 125
    neg-float v14, v6

    .line 126
    mul-float v15, v8, v6

    .line 127
    .line 128
    mul-float/2addr v8, v7

    .line 129
    mul-float v20, v11, v6

    .line 130
    .line 131
    mul-float v21, v11, v7

    .line 132
    .line 133
    mul-float v22, v4, v7

    .line 134
    .line 135
    mul-float v23, v17, v6

    .line 136
    .line 137
    add-float v23, v23, v22

    .line 138
    .line 139
    neg-float v4, v4

    .line 140
    mul-float/2addr v4, v6

    .line 141
    mul-float v17, v17, v7

    .line 142
    .line 143
    add-float v17, v17, v4

    .line 144
    .line 145
    move v6, v3

    .line 146
    float-to-double v3, v9

    .line 147
    mul-double v3, v3, v18

    .line 148
    .line 149
    move-wide/from16 v18, v3

    .line 150
    .line 151
    invoke-static/range {v18 .. v19}, Ljava/lang/Math;->sin(D)D

    .line 152
    .line 153
    .line 154
    move-result-wide v3

    .line 155
    double-to-float v3, v3

    .line 156
    move v9, v6

    .line 157
    move v4, v7

    .line 158
    invoke-static/range {v18 .. v19}, Ljava/lang/Math;->cos(D)D

    .line 159
    .line 160
    .line 161
    move-result-wide v6

    .line 162
    double-to-float v6, v6

    .line 163
    neg-float v7, v3

    .line 164
    mul-float v18, v7, v4

    .line 165
    .line 166
    mul-float v19, v6, v15

    .line 167
    .line 168
    add-float v19, v19, v18

    .line 169
    .line 170
    mul-float/2addr v4, v6

    .line 171
    mul-float/2addr v15, v3

    .line 172
    add-float/2addr v15, v4

    .line 173
    mul-float v4, v3, v11

    .line 174
    .line 175
    mul-float/2addr v11, v6

    .line 176
    mul-float/2addr v7, v14

    .line 177
    mul-float v18, v6, v8

    .line 178
    .line 179
    add-float v18, v18, v7

    .line 180
    .line 181
    mul-float/2addr v6, v14

    .line 182
    mul-float/2addr v3, v8

    .line 183
    add-float/2addr v3, v6

    .line 184
    mul-float/2addr v15, v10

    .line 185
    mul-float/2addr v4, v10

    .line 186
    mul-float/2addr v3, v10

    .line 187
    mul-float v19, v19, v1

    .line 188
    .line 189
    mul-float/2addr v11, v1

    .line 190
    mul-float v18, v18, v1

    .line 191
    .line 192
    mul-float v20, v20, v16

    .line 193
    .line 194
    mul-float v12, v12, v16

    .line 195
    .line 196
    mul-float v21, v21, v16

    .line 197
    .line 198
    array-length v1, v2

    .line 199
    const/16 v6, 0x10

    .line 200
    .line 201
    const/4 v7, 0x0

    .line 202
    if-ge v1, v6, :cond_1

    .line 203
    .line 204
    goto :goto_0

    .line 205
    :cond_1
    aput v15, v2, v7

    .line 206
    .line 207
    const/4 v1, 0x1

    .line 208
    aput v4, v2, v1

    .line 209
    .line 210
    const/4 v1, 0x2

    .line 211
    aput v3, v2, v1

    .line 212
    .line 213
    const/4 v1, 0x3

    .line 214
    const/4 v6, 0x0

    .line 215
    aput v6, v2, v1

    .line 216
    .line 217
    const/4 v1, 0x4

    .line 218
    aput v19, v2, v1

    .line 219
    .line 220
    const/4 v1, 0x5

    .line 221
    aput v11, v2, v1

    .line 222
    .line 223
    const/4 v1, 0x6

    .line 224
    aput v18, v2, v1

    .line 225
    .line 226
    const/4 v1, 0x7

    .line 227
    aput v6, v2, v1

    .line 228
    .line 229
    const/16 v1, 0x8

    .line 230
    .line 231
    aput v20, v2, v1

    .line 232
    .line 233
    const/16 v1, 0x9

    .line 234
    .line 235
    aput v12, v2, v1

    .line 236
    .line 237
    const/16 v1, 0xa

    .line 238
    .line 239
    aput v21, v2, v1

    .line 240
    .line 241
    const/16 v1, 0xb

    .line 242
    .line 243
    aput v6, v2, v1

    .line 244
    .line 245
    neg-float v1, v5

    .line 246
    mul-float/2addr v15, v1

    .line 247
    mul-float v6, v9, v19

    .line 248
    .line 249
    sub-float/2addr v15, v6

    .line 250
    add-float v15, v15, v23

    .line 251
    .line 252
    add-float/2addr v15, v5

    .line 253
    const/16 v5, 0xc

    .line 254
    .line 255
    aput v15, v2, v5

    .line 256
    .line 257
    mul-float/2addr v4, v1

    .line 258
    mul-float v5, v9, v11

    .line 259
    .line 260
    sub-float/2addr v4, v5

    .line 261
    add-float/2addr v4, v13

    .line 262
    add-float/2addr v4, v9

    .line 263
    const/16 v5, 0xd

    .line 264
    .line 265
    aput v4, v2, v5

    .line 266
    .line 267
    mul-float/2addr v1, v3

    .line 268
    mul-float v3, v9, v18

    .line 269
    .line 270
    sub-float/2addr v1, v3

    .line 271
    add-float v1, v1, v17

    .line 272
    .line 273
    const/16 v3, 0xe

    .line 274
    .line 275
    aput v1, v2, v3

    .line 276
    .line 277
    const/16 v1, 0xf

    .line 278
    .line 279
    aput v16, v2, v1

    .line 280
    .line 281
    :goto_0
    iput-boolean v7, v0, Lw3/o1;->t:Z

    .line 282
    .line 283
    invoke-static {v2}, Le3/j0;->p([F)Z

    .line 284
    .line 285
    .line 286
    move-result v1

    .line 287
    iput-boolean v1, v0, Lw3/o1;->v:Z

    .line 288
    .line 289
    :cond_2
    return-object v2
.end method

.method public final c(Ld3/a;Z)V
    .locals 0

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Lw3/o1;->a()[F

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {p0}, Lw3/o1;->b()[F

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    :goto_0
    iget-boolean p0, p0, Lw3/o1;->v:Z

    .line 13
    .line 14
    if-nez p0, :cond_2

    .line 15
    .line 16
    if-nez p2, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    iput p0, p1, Ld3/a;->b:F

    .line 20
    .line 21
    iput p0, p1, Ld3/a;->c:F

    .line 22
    .line 23
    iput p0, p1, Ld3/a;->d:F

    .line 24
    .line 25
    iput p0, p1, Ld3/a;->e:F

    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    invoke-static {p2, p1}, Le3/c0;->c([FLd3/a;)V

    .line 29
    .line 30
    .line 31
    :cond_2
    return-void
.end method

.method public final d(JZ)J
    .locals 0

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Lw3/o1;->a()[F

    .line 4
    .line 5
    .line 6
    move-result-object p3

    .line 7
    if-nez p3, :cond_1

    .line 8
    .line 9
    const-wide p0, 0x7f8000007f800000L    # 1.404448428688076E306

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    return-wide p0

    .line 15
    :cond_0
    invoke-virtual {p0}, Lw3/o1;->b()[F

    .line 16
    .line 17
    .line 18
    move-result-object p3

    .line 19
    :cond_1
    iget-boolean p0, p0, Lw3/o1;->v:Z

    .line 20
    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    return-wide p1

    .line 24
    :cond_2
    invoke-static {p1, p2, p3}, Le3/c0;->b(J[F)J

    .line 25
    .line 26
    .line 27
    move-result-wide p0

    .line 28
    return-wide p0
.end method

.method public final e(J)V
    .locals 9

    .line 1
    iget-object v0, p0, Lw3/o1;->f:Lw3/t;

    .line 2
    .line 3
    iget-boolean v1, v0, Lw3/t;->i:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    const/high16 v1, -0x3f800000    # -4.0f

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Lw3/t;->I(F)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lw3/o1;->d:Lh3/c;

    .line 13
    .line 14
    iget-wide v1, p0, Lh3/c;->t:J

    .line 15
    .line 16
    invoke-static {v1, v2, p1, p2}, Lt4/j;->b(JJ)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    iput-wide p1, p0, Lh3/c;->t:J

    .line 23
    .line 24
    iget-wide v1, p0, Lh3/c;->u:J

    .line 25
    .line 26
    iget-object p0, p0, Lh3/c;->a:Lh3/d;

    .line 27
    .line 28
    const/16 v3, 0x20

    .line 29
    .line 30
    shr-long v4, p1, v3

    .line 31
    .line 32
    long-to-int v4, v4

    .line 33
    const-wide v5, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr p1, v5

    .line 39
    long-to-int p1, p1

    .line 40
    iget-object p2, p0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 41
    .line 42
    shr-long v7, v1, v3

    .line 43
    .line 44
    long-to-int v3, v7

    .line 45
    add-int/2addr v3, v4

    .line 46
    and-long/2addr v5, v1

    .line 47
    long-to-int v5, v5

    .line 48
    add-int/2addr v5, p1

    .line 49
    invoke-virtual {p2, v4, p1, v3, v5}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 50
    .line 51
    .line 52
    invoke-static {v1, v2}, Lkp/f9;->c(J)J

    .line 53
    .line 54
    .line 55
    move-result-wide p1

    .line 56
    iput-wide p1, p0, Lh3/d;->d:J

    .line 57
    .line 58
    :cond_1
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    if-eqz p0, :cond_2

    .line 63
    .line 64
    invoke-interface {p0, v0, v0}, Landroid/view/ViewParent;->onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V

    .line 65
    .line 66
    .line 67
    :cond_2
    return-void
.end method

.method public final f(J)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lw3/o1;->i:J

    .line 2
    .line 3
    invoke-static {p1, p2, v0, v1}, Lt4/l;->a(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lw3/o1;->f:Lw3/t;

    .line 10
    .line 11
    iget-boolean v1, v0, Lw3/t;->i:Z

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    const/high16 v1, -0x3f800000    # -4.0f

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Lw3/t;->I(F)V

    .line 18
    .line 19
    .line 20
    :cond_0
    iput-wide p1, p0, Lw3/o1;->i:J

    .line 21
    .line 22
    iget-boolean p1, p0, Lw3/o1;->m:Z

    .line 23
    .line 24
    if-nez p1, :cond_1

    .line 25
    .line 26
    iget-boolean p1, p0, Lw3/o1;->j:Z

    .line 27
    .line 28
    if-nez p1, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 31
    .line 32
    .line 33
    iget-boolean p1, p0, Lw3/o1;->m:Z

    .line 34
    .line 35
    const/4 p2, 0x1

    .line 36
    if-eq p2, p1, :cond_1

    .line 37
    .line 38
    iput-boolean p2, p0, Lw3/o1;->m:Z

    .line 39
    .line 40
    invoke-virtual {v0, p0, p2}, Lw3/t;->t(Lv3/n1;Z)V

    .line 41
    .line 42
    .line 43
    :cond_1
    return-void
.end method

.method public final g()V
    .locals 11

    .line 1
    iget-boolean v0, p0, Lw3/o1;->m:Z

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-wide v0, p0, Lw3/o1;->r:J

    .line 6
    .line 7
    sget-wide v2, Le3/q0;->b:J

    .line 8
    .line 9
    invoke-static {v0, v1, v2, v3}, Le3/q0;->a(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    iget-object v0, p0, Lw3/o1;->d:Lh3/c;

    .line 16
    .line 17
    iget-wide v0, v0, Lh3/c;->u:J

    .line 18
    .line 19
    iget-wide v2, p0, Lw3/o1;->i:J

    .line 20
    .line 21
    invoke-static {v0, v1, v2, v3}, Lt4/l;->a(JJ)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    iget-object v0, p0, Lw3/o1;->d:Lh3/c;

    .line 28
    .line 29
    iget-wide v1, p0, Lw3/o1;->r:J

    .line 30
    .line 31
    invoke-static {v1, v2}, Le3/q0;->b(J)F

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    iget-wide v2, p0, Lw3/o1;->i:J

    .line 36
    .line 37
    const/16 v4, 0x20

    .line 38
    .line 39
    shr-long/2addr v2, v4

    .line 40
    long-to-int v2, v2

    .line 41
    int-to-float v2, v2

    .line 42
    mul-float/2addr v1, v2

    .line 43
    iget-wide v2, p0, Lw3/o1;->r:J

    .line 44
    .line 45
    invoke-static {v2, v3}, Le3/q0;->c(J)F

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    iget-wide v5, p0, Lw3/o1;->i:J

    .line 50
    .line 51
    const-wide v7, 0xffffffffL

    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    and-long/2addr v5, v7

    .line 57
    long-to-int v3, v5

    .line 58
    int-to-float v3, v3

    .line 59
    mul-float/2addr v2, v3

    .line 60
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    int-to-long v5, v1

    .line 65
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    int-to-long v1, v1

    .line 70
    shl-long/2addr v5, v4

    .line 71
    and-long/2addr v1, v7

    .line 72
    or-long/2addr v1, v5

    .line 73
    iget-wide v5, v0, Lh3/c;->v:J

    .line 74
    .line 75
    invoke-static {v5, v6, v1, v2}, Ld3/b;->c(JJ)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-nez v3, :cond_1

    .line 80
    .line 81
    iput-wide v1, v0, Lh3/c;->v:J

    .line 82
    .line 83
    iget-object v0, v0, Lh3/c;->a:Lh3/d;

    .line 84
    .line 85
    iget-object v0, v0, Lh3/d;->c:Landroid/graphics/RenderNode;

    .line 86
    .line 87
    const-wide v5, 0x7fffffff7fffffffL

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    and-long/2addr v5, v1

    .line 93
    const-wide v9, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    cmp-long v3, v5, v9

    .line 99
    .line 100
    if-nez v3, :cond_0

    .line 101
    .line 102
    invoke-virtual {v0}, Landroid/graphics/RenderNode;->resetPivot()Z

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_0
    shr-long v3, v1, v4

    .line 107
    .line 108
    long-to-int v3, v3

    .line 109
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    invoke-virtual {v0, v3}, Landroid/graphics/RenderNode;->setPivotX(F)Z

    .line 114
    .line 115
    .line 116
    and-long/2addr v1, v7

    .line 117
    long-to-int v1, v1

    .line 118
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    invoke-virtual {v0, v1}, Landroid/graphics/RenderNode;->setPivotY(F)Z

    .line 123
    .line 124
    .line 125
    :cond_1
    :goto_0
    iget-object v2, p0, Lw3/o1;->d:Lh3/c;

    .line 126
    .line 127
    iget-object v3, p0, Lw3/o1;->n:Lt4/c;

    .line 128
    .line 129
    iget-object v4, p0, Lw3/o1;->o:Lt4/m;

    .line 130
    .line 131
    iget-wide v5, p0, Lw3/o1;->i:J

    .line 132
    .line 133
    iget-object v7, p0, Lw3/o1;->x:Lw3/a0;

    .line 134
    .line 135
    invoke-virtual/range {v2 .. v7}, Lh3/c;->g(Lt4/c;Lt4/m;JLay0/k;)V

    .line 136
    .line 137
    .line 138
    iget-boolean v0, p0, Lw3/o1;->m:Z

    .line 139
    .line 140
    if-eqz v0, :cond_2

    .line 141
    .line 142
    const/4 v0, 0x0

    .line 143
    iput-boolean v0, p0, Lw3/o1;->m:Z

    .line 144
    .line 145
    iget-object v1, p0, Lw3/o1;->f:Lw3/t;

    .line 146
    .line 147
    invoke-virtual {v1, p0, v0}, Lw3/t;->t(Lv3/n1;Z)V

    .line 148
    .line 149
    .line 150
    :cond_2
    return-void
.end method

.method public final invalidate()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lw3/o1;->m:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lw3/o1;->j:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lw3/o1;->f:Lw3/t;

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 12
    .line 13
    .line 14
    iget-boolean v1, p0, Lw3/o1;->m:Z

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    if-eq v2, v1, :cond_0

    .line 18
    .line 19
    iput-boolean v2, p0, Lw3/o1;->m:Z

    .line 20
    .line 21
    invoke-virtual {v0, p0, v2}, Lw3/t;->t(Lv3/n1;Z)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method
