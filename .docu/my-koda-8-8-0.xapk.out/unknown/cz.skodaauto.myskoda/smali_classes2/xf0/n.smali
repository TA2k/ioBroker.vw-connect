.class public final synthetic Lxf0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:J

.field public final synthetic j:J

.field public final synthetic k:J

.field public final synthetic l:J

.field public final synthetic m:J

.field public final synthetic n:Lxf0/v0;

.field public final synthetic o:Lxf0/a1;


# direct methods
.method public synthetic constructor <init>(ZZJJJJJJJJLxf0/v0;Lxf0/a1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lxf0/n;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lxf0/n;->e:Z

    .line 7
    .line 8
    iput-wide p3, p0, Lxf0/n;->f:J

    .line 9
    .line 10
    iput-wide p5, p0, Lxf0/n;->g:J

    .line 11
    .line 12
    iput-wide p7, p0, Lxf0/n;->h:J

    .line 13
    .line 14
    iput-wide p9, p0, Lxf0/n;->i:J

    .line 15
    .line 16
    iput-wide p11, p0, Lxf0/n;->j:J

    .line 17
    .line 18
    iput-wide p13, p0, Lxf0/n;->k:J

    .line 19
    .line 20
    move-wide p1, p15

    .line 21
    iput-wide p1, p0, Lxf0/n;->l:J

    .line 22
    .line 23
    move-wide/from16 p1, p17

    .line 24
    .line 25
    iput-wide p1, p0, Lxf0/n;->m:J

    .line 26
    .line 27
    move-object/from16 p1, p19

    .line 28
    .line 29
    iput-object p1, p0, Lxf0/n;->n:Lxf0/v0;

    .line 30
    .line 31
    move-object/from16 p1, p20

    .line 32
    .line 33
    iput-object p1, p0, Lxf0/n;->o:Lxf0/a1;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    const-string v2, "$this$drawBehind"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {v1}, Lg3/d;->e()J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    const/high16 v3, 0x40000000    # 2.0f

    .line 21
    .line 22
    div-float/2addr v2, v3

    .line 23
    iget-object v9, v0, Lxf0/n;->o:Lxf0/a1;

    .line 24
    .line 25
    iget v15, v9, Lxf0/a1;->a:F

    .line 26
    .line 27
    const/4 v4, 0x2

    .line 28
    int-to-float v10, v4

    .line 29
    div-float v4, v15, v10

    .line 30
    .line 31
    sub-float/2addr v2, v4

    .line 32
    add-float/2addr v4, v2

    .line 33
    iget v5, v9, Lxf0/a1;->b:F

    .line 34
    .line 35
    mul-float v6, v5, v10

    .line 36
    .line 37
    sub-float/2addr v4, v6

    .line 38
    div-float v16, v5, v10

    .line 39
    .line 40
    sub-float v4, v4, v16

    .line 41
    .line 42
    iget-object v11, v0, Lxf0/n;->n:Lxf0/v0;

    .line 43
    .line 44
    iput v4, v11, Lxf0/v0;->i:F

    .line 45
    .line 46
    iput v2, v11, Lxf0/v0;->j:F

    .line 47
    .line 48
    invoke-interface {v1}, Lg3/d;->e()J

    .line 49
    .line 50
    .line 51
    move-result-wide v4

    .line 52
    invoke-static {v4, v5}, Ld3/e;->c(J)F

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    div-float v4, v2, v3

    .line 57
    .line 58
    iget-boolean v2, v0, Lxf0/n;->d:Z

    .line 59
    .line 60
    iget-boolean v12, v0, Lxf0/n;->e:Z

    .line 61
    .line 62
    if-eqz v2, :cond_0

    .line 63
    .line 64
    if-eqz v12, :cond_0

    .line 65
    .line 66
    new-instance v17, Lg3/h;

    .line 67
    .line 68
    iget v2, v9, Lxf0/a1;->c:F

    .line 69
    .line 70
    const/16 v22, 0x0

    .line 71
    .line 72
    const/16 v23, 0x1e

    .line 73
    .line 74
    const/16 v19, 0x0

    .line 75
    .line 76
    const/16 v20, 0x0

    .line 77
    .line 78
    const/16 v21, 0x0

    .line 79
    .line 80
    move/from16 v18, v2

    .line 81
    .line 82
    invoke-direct/range {v17 .. v23}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 83
    .line 84
    .line 85
    const-wide/16 v5, 0x0

    .line 86
    .line 87
    const/16 v8, 0x6c

    .line 88
    .line 89
    iget-wide v2, v0, Lxf0/n;->f:J

    .line 90
    .line 91
    move-object/from16 v7, v17

    .line 92
    .line 93
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 94
    .line 95
    .line 96
    :cond_0
    new-instance v4, Lxf0/k;

    .line 97
    .line 98
    const/4 v14, 0x1

    .line 99
    move-object v6, v9

    .line 100
    iget-wide v8, v0, Lxf0/n;->i:J

    .line 101
    .line 102
    move v2, v10

    .line 103
    move-object v7, v11

    .line 104
    iget-wide v10, v0, Lxf0/n;->j:J

    .line 105
    .line 106
    move v5, v12

    .line 107
    iget-wide v12, v0, Lxf0/n;->k:J

    .line 108
    .line 109
    move/from16 v17, v2

    .line 110
    .line 111
    invoke-direct/range {v4 .. v14}, Lxf0/k;-><init>(ZLxf0/a1;Lxf0/v0;JJJI)V

    .line 112
    .line 113
    .line 114
    move-object v9, v4

    .line 115
    move-object v11, v6

    .line 116
    move-object v10, v7

    .line 117
    new-instance v2, Lg3/h;

    .line 118
    .line 119
    iget v3, v11, Lxf0/a1;->a:F

    .line 120
    .line 121
    const/4 v7, 0x0

    .line 122
    const/16 v8, 0x1e

    .line 123
    .line 124
    const/4 v4, 0x0

    .line 125
    const/4 v5, 0x0

    .line 126
    const/4 v6, 0x0

    .line 127
    invoke-direct/range {v2 .. v8}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 128
    .line 129
    .line 130
    iget v4, v10, Lxf0/v0;->j:F

    .line 131
    .line 132
    const-wide/16 v5, 0x0

    .line 133
    .line 134
    const/16 v8, 0x6c

    .line 135
    .line 136
    move-object v7, v2

    .line 137
    iget-wide v2, v0, Lxf0/n;->h:J

    .line 138
    .line 139
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 140
    .line 141
    .line 142
    new-instance v2, Lg3/h;

    .line 143
    .line 144
    iget v3, v11, Lxf0/a1;->a:F

    .line 145
    .line 146
    const/4 v7, 0x0

    .line 147
    const/16 v8, 0x1e

    .line 148
    .line 149
    const/4 v4, 0x0

    .line 150
    const/4 v5, 0x0

    .line 151
    const/4 v6, 0x0

    .line 152
    invoke-direct/range {v2 .. v8}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 153
    .line 154
    .line 155
    iget v4, v10, Lxf0/v0;->j:F

    .line 156
    .line 157
    const-wide/16 v5, 0x0

    .line 158
    .line 159
    const/16 v8, 0x6c

    .line 160
    .line 161
    move-object v7, v2

    .line 162
    iget-wide v2, v0, Lxf0/n;->g:J

    .line 163
    .line 164
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v9, v1}, Lxf0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    iget-object v2, v10, Lxf0/v0;->b:Ljava/lang/Integer;

    .line 171
    .line 172
    if-eqz v2, :cond_2

    .line 173
    .line 174
    iget v3, v10, Lxf0/v0;->a:I

    .line 175
    .line 176
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 177
    .line 178
    .line 179
    move-result v4

    .line 180
    if-le v3, v4, :cond_1

    .line 181
    .line 182
    iget-wide v3, v0, Lxf0/n;->m:J

    .line 183
    .line 184
    goto :goto_0

    .line 185
    :cond_1
    iget-wide v3, v0, Lxf0/n;->l:J

    .line 186
    .line 187
    :goto_0
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    iget v2, v10, Lxf0/v0;->i:F

    .line 192
    .line 193
    sub-float v2, v2, v16

    .line 194
    .line 195
    iget v5, v10, Lxf0/v0;->j:F

    .line 196
    .line 197
    div-float v15, v15, v17

    .line 198
    .line 199
    add-float/2addr v15, v5

    .line 200
    iget v7, v11, Lxf0/a1;->e:F

    .line 201
    .line 202
    const/16 v5, 0x168

    .line 203
    .line 204
    int-to-float v5, v5

    .line 205
    int-to-float v0, v0

    .line 206
    const/high16 v6, 0x42c80000    # 100.0f

    .line 207
    .line 208
    div-float/2addr v0, v6

    .line 209
    mul-float/2addr v0, v5

    .line 210
    invoke-interface {v1}, Lg3/d;->e()J

    .line 211
    .line 212
    .line 213
    move-result-wide v5

    .line 214
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 215
    .line 216
    .line 217
    move-result-wide v5

    .line 218
    const/16 v8, 0x20

    .line 219
    .line 220
    shr-long/2addr v5, v8

    .line 221
    long-to-int v5, v5

    .line 222
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 223
    .line 224
    .line 225
    move-result v5

    .line 226
    float-to-double v9, v0

    .line 227
    const-wide v11, 0x4056800000000000L    # 90.0

    .line 228
    .line 229
    .line 230
    .line 231
    .line 232
    sub-double/2addr v9, v11

    .line 233
    invoke-static {v9, v10}, Ljava/lang/Math;->toRadians(D)D

    .line 234
    .line 235
    .line 236
    move-result-wide v11

    .line 237
    double-to-float v0, v11

    .line 238
    float-to-double v11, v0

    .line 239
    invoke-static {v11, v12}, Ljava/lang/Math;->cos(D)D

    .line 240
    .line 241
    .line 242
    move-result-wide v11

    .line 243
    double-to-float v0, v11

    .line 244
    mul-float/2addr v0, v15

    .line 245
    add-float/2addr v0, v5

    .line 246
    invoke-interface {v1}, Lg3/d;->e()J

    .line 247
    .line 248
    .line 249
    move-result-wide v5

    .line 250
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 251
    .line 252
    .line 253
    move-result-wide v5

    .line 254
    const-wide v11, 0xffffffffL

    .line 255
    .line 256
    .line 257
    .line 258
    .line 259
    and-long/2addr v5, v11

    .line 260
    long-to-int v5, v5

    .line 261
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 262
    .line 263
    .line 264
    move-result v5

    .line 265
    invoke-static {v9, v10}, Ljava/lang/Math;->toRadians(D)D

    .line 266
    .line 267
    .line 268
    move-result-wide v13

    .line 269
    double-to-float v6, v13

    .line 270
    float-to-double v13, v6

    .line 271
    invoke-static {v13, v14}, Ljava/lang/Math;->sin(D)D

    .line 272
    .line 273
    .line 274
    move-result-wide v13

    .line 275
    double-to-float v6, v13

    .line 276
    mul-float/2addr v15, v6

    .line 277
    add-float/2addr v15, v5

    .line 278
    invoke-interface {v1}, Lg3/d;->e()J

    .line 279
    .line 280
    .line 281
    move-result-wide v5

    .line 282
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 283
    .line 284
    .line 285
    move-result-wide v5

    .line 286
    shr-long/2addr v5, v8

    .line 287
    long-to-int v5, v5

    .line 288
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 289
    .line 290
    .line 291
    move-result v5

    .line 292
    invoke-static {v9, v10}, Ljava/lang/Math;->toRadians(D)D

    .line 293
    .line 294
    .line 295
    move-result-wide v13

    .line 296
    double-to-float v6, v13

    .line 297
    float-to-double v13, v6

    .line 298
    invoke-static {v13, v14}, Ljava/lang/Math;->cos(D)D

    .line 299
    .line 300
    .line 301
    move-result-wide v13

    .line 302
    double-to-float v6, v13

    .line 303
    mul-float/2addr v6, v2

    .line 304
    add-float/2addr v6, v5

    .line 305
    invoke-interface {v1}, Lg3/d;->e()J

    .line 306
    .line 307
    .line 308
    move-result-wide v13

    .line 309
    invoke-static {v13, v14}, Ljp/ef;->d(J)J

    .line 310
    .line 311
    .line 312
    move-result-wide v13

    .line 313
    and-long/2addr v13, v11

    .line 314
    long-to-int v5, v13

    .line 315
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 316
    .line 317
    .line 318
    move-result v5

    .line 319
    invoke-static {v9, v10}, Ljava/lang/Math;->toRadians(D)D

    .line 320
    .line 321
    .line 322
    move-result-wide v9

    .line 323
    double-to-float v9, v9

    .line 324
    float-to-double v9, v9

    .line 325
    invoke-static {v9, v10}, Ljava/lang/Math;->sin(D)D

    .line 326
    .line 327
    .line 328
    move-result-wide v9

    .line 329
    double-to-float v9, v9

    .line 330
    mul-float/2addr v2, v9

    .line 331
    add-float/2addr v2, v5

    .line 332
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 333
    .line 334
    .line 335
    move-result v0

    .line 336
    int-to-long v9, v0

    .line 337
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 338
    .line 339
    .line 340
    move-result v0

    .line 341
    int-to-long v13, v0

    .line 342
    shl-long/2addr v9, v8

    .line 343
    and-long/2addr v13, v11

    .line 344
    or-long/2addr v9, v13

    .line 345
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 346
    .line 347
    .line 348
    move-result v0

    .line 349
    int-to-long v5, v0

    .line 350
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 351
    .line 352
    .line 353
    move-result v0

    .line 354
    int-to-long v13, v0

    .line 355
    shl-long/2addr v5, v8

    .line 356
    and-long/2addr v11, v13

    .line 357
    or-long/2addr v5, v11

    .line 358
    move-object v0, v1

    .line 359
    move-wide v1, v3

    .line 360
    move-wide v3, v9

    .line 361
    const/4 v9, 0x0

    .line 362
    const/16 v10, 0x1f0

    .line 363
    .line 364
    const/4 v8, 0x0

    .line 365
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 366
    .line 367
    .line 368
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 369
    .line 370
    return-object v0
.end method
