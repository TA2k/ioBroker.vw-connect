.class public final Lbb/u;
.super Lbb/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J

.field public b:Z

.field public c:Z

.field public d:Lr6/e;

.field public final e:Lbb/g0;

.field public f:Landroidx/fragment/app/m;

.field public final synthetic g:Lbb/d0;


# direct methods
.method public constructor <init>(Lbb/d0;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbb/u;->g:Lbb/d0;

    .line 5
    .line 6
    const-wide/16 v0, -0x1

    .line 7
    .line 8
    iput-wide v0, p0, Lbb/u;->a:J

    .line 9
    .line 10
    new-instance p1, Lbb/g0;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {p1, v1, v0}, Lbb/g0;-><init>(CI)V

    .line 15
    .line 16
    .line 17
    const/16 v0, 0x14

    .line 18
    .line 19
    new-array v1, v0, [J

    .line 20
    .line 21
    iput-object v1, p1, Lbb/g0;->f:Ljava/lang/Object;

    .line 22
    .line 23
    new-array v0, v0, [F

    .line 24
    .line 25
    iput-object v0, p1, Lbb/g0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    iput v0, p1, Lbb/g0;->e:I

    .line 29
    .line 30
    const-wide/high16 v2, -0x8000000000000000L

    .line 31
    .line 32
    invoke-static {v1, v2, v3}, Ljava/util/Arrays;->fill([JJ)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lbb/u;->e:Lbb/g0;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final e(Lbb/x;)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    .line 2
    iput-boolean p1, p0, Lbb/u;->c:Z

    .line 3
    .line 4
    return-void
.end method

.method public final g()V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lbb/u;->d:Lr6/e;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    goto/16 :goto_6

    .line 8
    .line 9
    :cond_0
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    iget-wide v3, v0, Lbb/u;->a:J

    .line 14
    .line 15
    long-to-float v3, v3

    .line 16
    iget-object v4, v0, Lbb/u;->e:Lbb/g0;

    .line 17
    .line 18
    iget v5, v4, Lbb/g0;->e:I

    .line 19
    .line 20
    iget-object v6, v4, Lbb/g0;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v6, [F

    .line 23
    .line 24
    iget-object v7, v4, Lbb/g0;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v7, [J

    .line 27
    .line 28
    const/4 v8, 0x1

    .line 29
    add-int/2addr v5, v8

    .line 30
    const/16 v9, 0x14

    .line 31
    .line 32
    rem-int/2addr v5, v9

    .line 33
    iput v5, v4, Lbb/g0;->e:I

    .line 34
    .line 35
    aput-wide v1, v7, v5

    .line 36
    .line 37
    aput v3, v6, v5

    .line 38
    .line 39
    new-instance v1, Lr6/e;

    .line 40
    .line 41
    new-instance v2, Lk1/f;

    .line 42
    .line 43
    const/4 v3, 0x4

    .line 44
    invoke-direct {v2, v3}, Lk1/f;-><init>(I)V

    .line 45
    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    iput v3, v2, Lk1/f;->e:F

    .line 49
    .line 50
    invoke-direct {v1, v2}, Lr6/e;-><init>(Lk1/f;)V

    .line 51
    .line 52
    .line 53
    iput-object v1, v0, Lbb/u;->d:Lr6/e;

    .line 54
    .line 55
    new-instance v1, Lr6/f;

    .line 56
    .line 57
    invoke-direct {v1}, Lr6/f;-><init>()V

    .line 58
    .line 59
    .line 60
    const/high16 v2, 0x3f800000    # 1.0f

    .line 61
    .line 62
    invoke-virtual {v1, v2}, Lr6/f;->a(F)V

    .line 63
    .line 64
    .line 65
    const/high16 v2, 0x43480000    # 200.0f

    .line 66
    .line 67
    invoke-virtual {v1, v2}, Lr6/f;->b(F)V

    .line 68
    .line 69
    .line 70
    iget-object v2, v0, Lbb/u;->d:Lr6/e;

    .line 71
    .line 72
    iput-object v1, v2, Lr6/e;->m:Lr6/f;

    .line 73
    .line 74
    iget-wide v10, v0, Lbb/u;->a:J

    .line 75
    .line 76
    long-to-float v1, v10

    .line 77
    iput v1, v2, Lr6/e;->b:F

    .line 78
    .line 79
    iput-boolean v8, v2, Lr6/e;->c:Z

    .line 80
    .line 81
    iget-object v1, v2, Lr6/e;->l:Ljava/util/ArrayList;

    .line 82
    .line 83
    iget-boolean v2, v2, Lr6/e;->f:Z

    .line 84
    .line 85
    if-nez v2, :cond_10

    .line 86
    .line 87
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    if-nez v2, :cond_1

    .line 92
    .line 93
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    :cond_1
    iget-object v1, v0, Lbb/u;->d:Lr6/e;

    .line 97
    .line 98
    iget v2, v4, Lbb/g0;->e:I

    .line 99
    .line 100
    const-wide/high16 v10, -0x8000000000000000L

    .line 101
    .line 102
    if-nez v2, :cond_2

    .line 103
    .line 104
    aget-wide v12, v7, v2

    .line 105
    .line 106
    cmp-long v5, v12, v10

    .line 107
    .line 108
    if-nez v5, :cond_2

    .line 109
    .line 110
    goto/16 :goto_5

    .line 111
    .line 112
    :cond_2
    aget-wide v12, v7, v2

    .line 113
    .line 114
    const/4 v5, 0x0

    .line 115
    move-wide v14, v12

    .line 116
    :goto_0
    aget-wide v16, v7, v2

    .line 117
    .line 118
    cmp-long v18, v16, v10

    .line 119
    .line 120
    if-nez v18, :cond_3

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_3
    sub-long v10, v12, v16

    .line 124
    .line 125
    long-to-float v10, v10

    .line 126
    sub-long v14, v16, v14

    .line 127
    .line 128
    invoke-static {v14, v15}, Ljava/lang/Math;->abs(J)J

    .line 129
    .line 130
    .line 131
    move-result-wide v14

    .line 132
    long-to-float v11, v14

    .line 133
    const/high16 v14, 0x42c80000    # 100.0f

    .line 134
    .line 135
    cmpl-float v10, v10, v14

    .line 136
    .line 137
    if-gtz v10, :cond_7

    .line 138
    .line 139
    const/high16 v10, 0x42200000    # 40.0f

    .line 140
    .line 141
    cmpl-float v10, v11, v10

    .line 142
    .line 143
    if-lez v10, :cond_4

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_4
    if-nez v2, :cond_5

    .line 147
    .line 148
    move v2, v9

    .line 149
    :cond_5
    sub-int/2addr v2, v8

    .line 150
    add-int/lit8 v5, v5, 0x1

    .line 151
    .line 152
    if-lt v5, v9, :cond_6

    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_6
    move-wide/from16 v14, v16

    .line 156
    .line 157
    const-wide/high16 v10, -0x8000000000000000L

    .line 158
    .line 159
    goto :goto_0

    .line 160
    :cond_7
    :goto_1
    const/4 v2, 0x2

    .line 161
    if-ge v5, v2, :cond_8

    .line 162
    .line 163
    goto/16 :goto_5

    .line 164
    .line 165
    :cond_8
    const/high16 v10, 0x447a0000    # 1000.0f

    .line 166
    .line 167
    if-ne v5, v2, :cond_b

    .line 168
    .line 169
    iget v2, v4, Lbb/g0;->e:I

    .line 170
    .line 171
    if-nez v2, :cond_9

    .line 172
    .line 173
    const/16 v4, 0x13

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_9
    add-int/lit8 v4, v2, -0x1

    .line 177
    .line 178
    :goto_2
    aget-wide v8, v7, v2

    .line 179
    .line 180
    aget-wide v11, v7, v4

    .line 181
    .line 182
    sub-long/2addr v8, v11

    .line 183
    long-to-float v5, v8

    .line 184
    cmpl-float v7, v5, v3

    .line 185
    .line 186
    if-nez v7, :cond_a

    .line 187
    .line 188
    goto/16 :goto_5

    .line 189
    .line 190
    :cond_a
    aget v2, v6, v2

    .line 191
    .line 192
    aget v3, v6, v4

    .line 193
    .line 194
    sub-float/2addr v2, v3

    .line 195
    div-float/2addr v2, v5

    .line 196
    mul-float v3, v2, v10

    .line 197
    .line 198
    goto/16 :goto_5

    .line 199
    .line 200
    :cond_b
    iget v2, v4, Lbb/g0;->e:I

    .line 201
    .line 202
    sub-int v4, v2, v5

    .line 203
    .line 204
    add-int/lit8 v4, v4, 0x15

    .line 205
    .line 206
    rem-int/2addr v4, v9

    .line 207
    add-int/lit8 v2, v2, 0x15

    .line 208
    .line 209
    rem-int/2addr v2, v9

    .line 210
    aget-wide v11, v7, v4

    .line 211
    .line 212
    aget v5, v6, v4

    .line 213
    .line 214
    add-int/2addr v4, v8

    .line 215
    rem-int/lit8 v8, v4, 0x14

    .line 216
    .line 217
    move v13, v3

    .line 218
    :goto_3
    const/high16 v14, 0x40000000    # 2.0f

    .line 219
    .line 220
    if-eq v8, v2, :cond_e

    .line 221
    .line 222
    aget-wide v15, v7, v8

    .line 223
    .line 224
    move/from16 v17, v9

    .line 225
    .line 226
    move/from16 v18, v10

    .line 227
    .line 228
    sub-long v9, v15, v11

    .line 229
    .line 230
    long-to-float v9, v9

    .line 231
    cmpl-float v10, v9, v3

    .line 232
    .line 233
    if-nez v10, :cond_c

    .line 234
    .line 235
    move v3, v4

    .line 236
    goto :goto_4

    .line 237
    :cond_c
    aget v10, v6, v8

    .line 238
    .line 239
    invoke-static {v13}, Ljava/lang/Math;->signum(F)F

    .line 240
    .line 241
    .line 242
    move-result v11

    .line 243
    float-to-double v11, v11

    .line 244
    invoke-static {v13}, Ljava/lang/Math;->abs(F)F

    .line 245
    .line 246
    .line 247
    move-result v19

    .line 248
    mul-float v14, v14, v19

    .line 249
    .line 250
    move/from16 v20, v4

    .line 251
    .line 252
    float-to-double v3, v14

    .line 253
    invoke-static {v3, v4}, Ljava/lang/Math;->sqrt(D)D

    .line 254
    .line 255
    .line 256
    move-result-wide v3

    .line 257
    mul-double/2addr v3, v11

    .line 258
    double-to-float v3, v3

    .line 259
    sub-float v4, v10, v5

    .line 260
    .line 261
    div-float/2addr v4, v9

    .line 262
    sub-float v3, v4, v3

    .line 263
    .line 264
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    .line 265
    .line 266
    .line 267
    move-result v4

    .line 268
    mul-float/2addr v4, v3

    .line 269
    add-float/2addr v4, v13

    .line 270
    move/from16 v3, v20

    .line 271
    .line 272
    if-ne v8, v3, :cond_d

    .line 273
    .line 274
    const/high16 v5, 0x3f000000    # 0.5f

    .line 275
    .line 276
    mul-float/2addr v4, v5

    .line 277
    :cond_d
    move v13, v4

    .line 278
    move v5, v10

    .line 279
    move-wide v11, v15

    .line 280
    :goto_4
    add-int/lit8 v8, v8, 0x1

    .line 281
    .line 282
    rem-int/lit8 v8, v8, 0x14

    .line 283
    .line 284
    move v4, v3

    .line 285
    move/from16 v9, v17

    .line 286
    .line 287
    move/from16 v10, v18

    .line 288
    .line 289
    const/4 v3, 0x0

    .line 290
    goto :goto_3

    .line 291
    :cond_e
    move/from16 v18, v10

    .line 292
    .line 293
    invoke-static {v13}, Ljava/lang/Math;->signum(F)F

    .line 294
    .line 295
    .line 296
    move-result v2

    .line 297
    float-to-double v2, v2

    .line 298
    invoke-static {v13}, Ljava/lang/Math;->abs(F)F

    .line 299
    .line 300
    .line 301
    move-result v4

    .line 302
    mul-float/2addr v4, v14

    .line 303
    float-to-double v4, v4

    .line 304
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 305
    .line 306
    .line 307
    move-result-wide v4

    .line 308
    mul-double/2addr v4, v2

    .line 309
    double-to-float v2, v4

    .line 310
    mul-float v3, v2, v18

    .line 311
    .line 312
    :goto_5
    iput v3, v1, Lr6/e;->a:F

    .line 313
    .line 314
    iget-object v1, v0, Lbb/u;->d:Lr6/e;

    .line 315
    .line 316
    iget-object v2, v0, Lbb/u;->g:Lbb/d0;

    .line 317
    .line 318
    iget-wide v2, v2, Lbb/x;->A:J

    .line 319
    .line 320
    const-wide/16 v4, 0x1

    .line 321
    .line 322
    add-long/2addr v2, v4

    .line 323
    long-to-float v2, v2

    .line 324
    iput v2, v1, Lr6/e;->g:F

    .line 325
    .line 326
    const/high16 v2, -0x40800000    # -1.0f

    .line 327
    .line 328
    iput v2, v1, Lr6/e;->h:F

    .line 329
    .line 330
    const/high16 v2, 0x40800000    # 4.0f

    .line 331
    .line 332
    iput v2, v1, Lr6/e;->j:F

    .line 333
    .line 334
    new-instance v2, Lbb/t;

    .line 335
    .line 336
    invoke-direct {v2, v0}, Lbb/t;-><init>(Lbb/u;)V

    .line 337
    .line 338
    .line 339
    iget-object v0, v1, Lr6/e;->k:Ljava/util/ArrayList;

    .line 340
    .line 341
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result v1

    .line 345
    if-nez v1, :cond_f

    .line 346
    .line 347
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    :cond_f
    :goto_6
    return-void

    .line 351
    :cond_10
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 352
    .line 353
    const-string v1, "Error: Update listeners must be added beforethe animation."

    .line 354
    .line 355
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    throw v0
.end method
