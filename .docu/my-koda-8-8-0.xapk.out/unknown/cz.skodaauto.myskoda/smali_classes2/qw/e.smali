.class public final Lqw/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final p:Lfv/b;


# instance fields
.field public final a:I

.field public final b:Landroid/graphics/Typeface;

.field public final c:F

.field public final d:Landroid/text/Layout$Alignment;

.field public final e:Ljava/lang/Float;

.field public final f:I

.field public final g:Landroid/text/TextUtils$TruncateAt;

.field public final h:Lpw/c;

.field public final i:Lpw/c;

.field public final j:Lqw/b;

.field public final k:Lqw/c;

.field public final l:Landroid/text/TextPaint;

.field public m:Landroid/text/StaticLayout;

.field public n:Landroid/text/Layout;

.field public final o:Landroid/graphics/RectF;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfv/b;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfv/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lqw/e;->p:Lfv/b;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(II)V
    .locals 6

    .line 1
    sget-object v0, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    .line 2
    .line 3
    and-int/lit8 p2, p2, 0x4

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    const/high16 p2, 0x41400000    # 12.0f

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p2, 0x0

    .line 11
    :goto_0
    sget-object v0, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 12
    .line 13
    sget-object v0, Landroid/text/TextUtils$TruncateAt;->END:Landroid/text/TextUtils$TruncateAt;

    .line 14
    .line 15
    new-instance v0, Lqw/c;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    sget-object v1, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    .line 21
    .line 22
    sget-object v2, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 23
    .line 24
    sget-object v3, Landroid/text/TextUtils$TruncateAt;->END:Landroid/text/TextUtils$TruncateAt;

    .line 25
    .line 26
    const-string v4, "typeface"

    .line 27
    .line 28
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v4, "textAlignment"

    .line 32
    .line 33
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v4, "margins"

    .line 37
    .line 38
    sget-object v5, Lpw/c;->e:Lpw/c;

    .line 39
    .line 40
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string v4, "padding"

    .line 44
    .line 45
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 49
    .line 50
    .line 51
    iput p1, p0, Lqw/e;->a:I

    .line 52
    .line 53
    iput-object v1, p0, Lqw/e;->b:Landroid/graphics/Typeface;

    .line 54
    .line 55
    iput p2, p0, Lqw/e;->c:F

    .line 56
    .line 57
    iput-object v2, p0, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 58
    .line 59
    const/4 p2, 0x0

    .line 60
    iput-object p2, p0, Lqw/e;->e:Ljava/lang/Float;

    .line 61
    .line 62
    const/4 p2, 0x1

    .line 63
    iput p2, p0, Lqw/e;->f:I

    .line 64
    .line 65
    iput-object v3, p0, Lqw/e;->g:Landroid/text/TextUtils$TruncateAt;

    .line 66
    .line 67
    iput-object v5, p0, Lqw/e;->h:Lpw/c;

    .line 68
    .line 69
    iput-object v5, p0, Lqw/e;->i:Lpw/c;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    iput-object v2, p0, Lqw/e;->j:Lqw/b;

    .line 73
    .line 74
    iput-object v0, p0, Lqw/e;->k:Lqw/c;

    .line 75
    .line 76
    new-instance v0, Landroid/text/TextPaint;

    .line 77
    .line 78
    invoke-direct {v0, p2}, Landroid/text/TextPaint;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setColor(I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 85
    .line 86
    .line 87
    const/4 p1, 0x0

    .line 88
    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 89
    .line 90
    .line 91
    iput-object v0, p0, Lqw/e;->l:Landroid/text/TextPaint;

    .line 92
    .line 93
    new-instance p1, Landroid/graphics/RectF;

    .line 94
    .line 95
    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    .line 96
    .line 97
    .line 98
    iput-object p1, p0, Lqw/e;->o:Landroid/graphics/RectF;

    .line 99
    .line 100
    return-void
.end method

.method public static a(Lqw/e;Lc1/h2;Ljava/lang/CharSequence;FFLpw/e;Lpw/i;IIFI)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v6, p3

    .line 6
    .line 7
    move/from16 v2, p10

    .line 8
    .line 9
    and-int/lit8 v3, v2, 0x10

    .line 10
    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    sget-object v3, Lpw/e;->e:Lpw/e;

    .line 14
    .line 15
    move-object v7, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move-object/from16 v7, p5

    .line 18
    .line 19
    :goto_0
    and-int/lit8 v3, v2, 0x40

    .line 20
    .line 21
    const v4, 0x186a0

    .line 22
    .line 23
    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    move v3, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move/from16 v3, p7

    .line 29
    .line 30
    :goto_1
    and-int/lit16 v5, v2, 0x80

    .line 31
    .line 32
    if-eqz v5, :cond_2

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move/from16 v4, p8

    .line 36
    .line 37
    :goto_2
    and-int/lit16 v2, v2, 0x100

    .line 38
    .line 39
    const/4 v8, 0x0

    .line 40
    if-eqz v2, :cond_3

    .line 41
    .line 42
    move v5, v8

    .line 43
    goto :goto_3

    .line 44
    :cond_3
    move/from16 v5, p9

    .line 45
    .line 46
    :goto_3
    iget-object v9, v0, Lqw/e;->i:Lpw/c;

    .line 47
    .line 48
    iget-object v10, v0, Lqw/e;->i:Lpw/c;

    .line 49
    .line 50
    iget-object v11, v0, Lqw/e;->h:Lpw/c;

    .line 51
    .line 52
    const-string v2, "context"

    .line 53
    .line 54
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v2, "text"

    .line 58
    .line 59
    move-object/from16 v12, p2

    .line 60
    .line 61
    invoke-static {v12, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-static {v12}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-eqz v2, :cond_4

    .line 69
    .line 70
    return-void

    .line 71
    :cond_4
    move-object v2, v12

    .line 72
    invoke-virtual/range {v0 .. v5}, Lqw/e;->d(Lpw/f;Ljava/lang/CharSequence;IIF)Landroid/text/StaticLayout;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    iput-object v2, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 77
    .line 78
    const/high16 v3, 0x43b40000    # 360.0f

    .line 79
    .line 80
    rem-float v3, v5, v3

    .line 81
    .line 82
    cmpg-float v3, v3, v8

    .line 83
    .line 84
    const/4 v12, 0x1

    .line 85
    if-nez v3, :cond_5

    .line 86
    .line 87
    move v3, v12

    .line 88
    goto :goto_4

    .line 89
    :cond_5
    const/4 v3, 0x0

    .line 90
    :goto_4
    invoke-static {v2}, Ljp/be;->a(Landroid/text/Layout;)F

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 95
    .line 96
    .line 97
    move-result v13

    .line 98
    const/4 v14, 0x2

    .line 99
    if-eqz v13, :cond_b

    .line 100
    .line 101
    if-eq v13, v12, :cond_a

    .line 102
    .line 103
    if-ne v13, v14, :cond_9

    .line 104
    .line 105
    iget-object v13, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v13, Lkw/g;

    .line 108
    .line 109
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 110
    .line 111
    .line 112
    move-result v15

    .line 113
    if-eqz v15, :cond_8

    .line 114
    .line 115
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-eqz v2, :cond_6

    .line 120
    .line 121
    iget v2, v10, Lpw/c;->a:F

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_6
    iget v2, v10, Lpw/c;->c:F

    .line 125
    .line 126
    :goto_5
    invoke-interface {v13, v2}, Lpw/f;->c(F)F

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    add-float/2addr v2, v6

    .line 131
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    if-eqz v6, :cond_7

    .line 136
    .line 137
    iget v6, v11, Lpw/c;->a:F

    .line 138
    .line 139
    goto :goto_6

    .line 140
    :cond_7
    iget v6, v11, Lpw/c;->c:F

    .line 141
    .line 142
    :goto_6
    invoke-interface {v13, v6}, Lpw/f;->c(F)F

    .line 143
    .line 144
    .line 145
    move-result v6

    .line 146
    :goto_7
    add-float/2addr v6, v2

    .line 147
    goto :goto_a

    .line 148
    :cond_8
    invoke-virtual {v0, v1, v6, v2}, Lqw/e;->e(Lc1/h2;FF)F

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    goto :goto_a

    .line 153
    :cond_9
    new-instance v0, La8/r0;

    .line 154
    .line 155
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 156
    .line 157
    .line 158
    throw v0

    .line 159
    :cond_a
    int-to-float v10, v14

    .line 160
    div-float/2addr v2, v10

    .line 161
    sub-float/2addr v6, v2

    .line 162
    goto :goto_a

    .line 163
    :cond_b
    iget-object v13, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v13, Lkw/g;

    .line 166
    .line 167
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 168
    .line 169
    .line 170
    move-result v15

    .line 171
    if-eqz v15, :cond_c

    .line 172
    .line 173
    invoke-virtual {v0, v1, v6, v2}, Lqw/e;->e(Lc1/h2;FF)F

    .line 174
    .line 175
    .line 176
    move-result v6

    .line 177
    goto :goto_a

    .line 178
    :cond_c
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    if-eqz v2, :cond_d

    .line 183
    .line 184
    iget v2, v10, Lpw/c;->a:F

    .line 185
    .line 186
    goto :goto_8

    .line 187
    :cond_d
    iget v2, v10, Lpw/c;->c:F

    .line 188
    .line 189
    :goto_8
    invoke-interface {v13, v2}, Lpw/f;->c(F)F

    .line 190
    .line 191
    .line 192
    move-result v2

    .line 193
    add-float/2addr v2, v6

    .line 194
    invoke-interface {v13}, Lpw/f;->e()Z

    .line 195
    .line 196
    .line 197
    move-result v6

    .line 198
    if-eqz v6, :cond_e

    .line 199
    .line 200
    iget v6, v11, Lpw/c;->a:F

    .line 201
    .line 202
    goto :goto_9

    .line 203
    :cond_e
    iget v6, v11, Lpw/c;->c:F

    .line 204
    .line 205
    :goto_9
    invoke-interface {v13, v6}, Lpw/f;->c(F)F

    .line 206
    .line 207
    .line 208
    move-result v6

    .line 209
    goto :goto_7

    .line 210
    :goto_a
    iget-object v2, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 211
    .line 212
    const-string v13, "layout"

    .line 213
    .line 214
    if-eqz v2, :cond_2b

    .line 215
    .line 216
    invoke-virtual {v2}, Landroid/text/Layout;->getHeight()I

    .line 217
    .line 218
    .line 219
    move-result v15

    .line 220
    int-to-float v15, v15

    .line 221
    invoke-virtual {v2}, Landroid/text/Layout;->getSpacingAdd()F

    .line 222
    .line 223
    .line 224
    move-result v2

    .line 225
    add-float/2addr v2, v15

    .line 226
    invoke-virtual/range {p6 .. p6}, Ljava/lang/Enum;->ordinal()I

    .line 227
    .line 228
    .line 229
    move-result v15

    .line 230
    if-eqz v15, :cond_11

    .line 231
    .line 232
    if-eq v15, v12, :cond_10

    .line 233
    .line 234
    if-ne v15, v14, :cond_f

    .line 235
    .line 236
    iget v2, v9, Lpw/c;->b:F

    .line 237
    .line 238
    iget-object v15, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 239
    .line 240
    check-cast v15, Lkw/g;

    .line 241
    .line 242
    invoke-interface {v15, v2}, Lpw/f;->c(F)F

    .line 243
    .line 244
    .line 245
    move-result v2

    .line 246
    iget v11, v11, Lpw/c;->b:F

    .line 247
    .line 248
    invoke-interface {v15, v11}, Lpw/f;->c(F)F

    .line 249
    .line 250
    .line 251
    move-result v11

    .line 252
    add-float/2addr v11, v2

    .line 253
    :goto_b
    const/16 p8, 0x0

    .line 254
    .line 255
    goto :goto_c

    .line 256
    :cond_f
    new-instance v0, La8/r0;

    .line 257
    .line 258
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 259
    .line 260
    .line 261
    throw v0

    .line 262
    :cond_10
    int-to-float v11, v14

    .line 263
    div-float/2addr v2, v11

    .line 264
    neg-float v11, v2

    .line 265
    goto :goto_b

    .line 266
    :cond_11
    neg-float v2, v2

    .line 267
    iget v15, v9, Lpw/c;->d:F

    .line 268
    .line 269
    const/16 p8, 0x0

    .line 270
    .line 271
    iget-object v10, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 272
    .line 273
    check-cast v10, Lkw/g;

    .line 274
    .line 275
    invoke-interface {v10, v15}, Lpw/f;->c(F)F

    .line 276
    .line 277
    .line 278
    move-result v15

    .line 279
    sub-float/2addr v2, v15

    .line 280
    iget v11, v11, Lpw/c;->d:F

    .line 281
    .line 282
    invoke-interface {v10, v11}, Lpw/f;->c(F)F

    .line 283
    .line 284
    .line 285
    move-result v10

    .line 286
    sub-float v11, v2, v10

    .line 287
    .line 288
    :goto_c
    add-float v2, p4, v11

    .line 289
    .line 290
    iget-object v10, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v10, Lkw/g;

    .line 293
    .line 294
    iget-object v11, v1, Lc1/h2;->d:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v11, Landroid/graphics/Canvas;

    .line 297
    .line 298
    invoke-virtual {v11}, Landroid/graphics/Canvas;->save()I

    .line 299
    .line 300
    .line 301
    iget-object v11, v1, Lc1/h2;->d:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast v11, Landroid/graphics/Canvas;

    .line 304
    .line 305
    iget-object v15, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 306
    .line 307
    if-eqz v15, :cond_2a

    .line 308
    .line 309
    iget-object v12, v0, Lqw/e;->o:Landroid/graphics/RectF;

    .line 310
    .line 311
    const-string v4, "outBounds"

    .line 312
    .line 313
    invoke-static {v12, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    iput v8, v12, Landroid/graphics/RectF;->left:F

    .line 317
    .line 318
    iput v8, v12, Landroid/graphics/RectF;->top:F

    .line 319
    .line 320
    invoke-static {v15}, Ljp/be;->a(Landroid/text/Layout;)F

    .line 321
    .line 322
    .line 323
    move-result v4

    .line 324
    iput v4, v12, Landroid/graphics/RectF;->right:F

    .line 325
    .line 326
    invoke-virtual {v15}, Landroid/text/Layout;->getHeight()I

    .line 327
    .line 328
    .line 329
    move-result v4

    .line 330
    int-to-float v4, v4

    .line 331
    invoke-virtual {v15}, Landroid/text/Layout;->getSpacingAdd()F

    .line 332
    .line 333
    .line 334
    move-result v15

    .line 335
    add-float/2addr v15, v4

    .line 336
    iput v15, v12, Landroid/graphics/RectF;->bottom:F

    .line 337
    .line 338
    invoke-interface {v10}, Lpw/f;->e()Z

    .line 339
    .line 340
    .line 341
    move-result v4

    .line 342
    if-eqz v4, :cond_12

    .line 343
    .line 344
    iget v4, v9, Lpw/c;->a:F

    .line 345
    .line 346
    goto :goto_d

    .line 347
    :cond_12
    iget v4, v9, Lpw/c;->c:F

    .line 348
    .line 349
    :goto_d
    iget v15, v9, Lpw/c;->b:F

    .line 350
    .line 351
    invoke-interface {v10, v4}, Lpw/f;->c(F)F

    .line 352
    .line 353
    .line 354
    move-result v4

    .line 355
    invoke-interface {v10}, Lpw/f;->e()Z

    .line 356
    .line 357
    .line 358
    move-result v16

    .line 359
    if-eqz v16, :cond_13

    .line 360
    .line 361
    iget v14, v9, Lpw/c;->c:F

    .line 362
    .line 363
    goto :goto_e

    .line 364
    :cond_13
    iget v14, v9, Lpw/c;->a:F

    .line 365
    .line 366
    :goto_e
    invoke-interface {v10, v14}, Lpw/f;->c(F)F

    .line 367
    .line 368
    .line 369
    move-result v14

    .line 370
    move/from16 p3, v2

    .line 371
    .line 372
    iget-object v2, v0, Lqw/e;->k:Lqw/c;

    .line 373
    .line 374
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 375
    .line 376
    .line 377
    invoke-virtual {v1, v8}, Lc1/h2;->c(F)F

    .line 378
    .line 379
    .line 380
    move-result v2

    .line 381
    move/from16 p10, v8

    .line 382
    .line 383
    invoke-virtual {v9}, Lpw/c;->a()F

    .line 384
    .line 385
    .line 386
    move-result v8

    .line 387
    invoke-interface {v10, v8}, Lpw/f;->c(F)F

    .line 388
    .line 389
    .line 390
    move-result v8

    .line 391
    sub-float/2addr v2, v8

    .line 392
    iget-object v8, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 393
    .line 394
    if-eqz v8, :cond_29

    .line 395
    .line 396
    invoke-virtual {v8}, Landroid/text/Layout;->getWidth()I

    .line 397
    .line 398
    .line 399
    move-result v8

    .line 400
    int-to-float v8, v8

    .line 401
    cmpl-float v16, v2, v8

    .line 402
    .line 403
    if-lez v16, :cond_14

    .line 404
    .line 405
    move v2, v8

    .line 406
    :cond_14
    invoke-virtual {v12}, Landroid/graphics/RectF;->width()F

    .line 407
    .line 408
    .line 409
    move-result v8

    .line 410
    sub-float/2addr v2, v8

    .line 411
    cmpg-float v8, v2, p10

    .line 412
    .line 413
    if-gez v8, :cond_15

    .line 414
    .line 415
    move/from16 v2, p10

    .line 416
    .line 417
    :cond_15
    iget v8, v12, Landroid/graphics/RectF;->left:F

    .line 418
    .line 419
    move/from16 p4, v2

    .line 420
    .line 421
    const/4 v1, 0x2

    .line 422
    int-to-float v2, v1

    .line 423
    div-float v1, p4, v2

    .line 424
    .line 425
    sub-float/2addr v8, v1

    .line 426
    iput v8, v12, Landroid/graphics/RectF;->left:F

    .line 427
    .line 428
    iget v8, v12, Landroid/graphics/RectF;->right:F

    .line 429
    .line 430
    add-float/2addr v8, v1

    .line 431
    iput v8, v12, Landroid/graphics/RectF;->right:F

    .line 432
    .line 433
    invoke-virtual {v12}, Landroid/graphics/RectF;->width()F

    .line 434
    .line 435
    .line 436
    move-result v1

    .line 437
    iget-object v8, v0, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 438
    .line 439
    move/from16 p4, v1

    .line 440
    .line 441
    iget-object v1, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 442
    .line 443
    if-eqz v1, :cond_28

    .line 444
    .line 445
    move/from16 v16, v2

    .line 446
    .line 447
    const/4 v2, 0x0

    .line 448
    invoke-virtual {v1, v2}, Landroid/text/Layout;->getParagraphDirection(I)I

    .line 449
    .line 450
    .line 451
    move-result v1

    .line 452
    const/4 v2, 0x1

    .line 453
    if-ne v1, v2, :cond_16

    .line 454
    .line 455
    goto :goto_f

    .line 456
    :cond_16
    sget-object v1, Lqw/d;->a:[I

    .line 457
    .line 458
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 459
    .line 460
    .line 461
    move-result v8

    .line 462
    aget v1, v1, v8

    .line 463
    .line 464
    if-eq v1, v2, :cond_19

    .line 465
    .line 466
    const/4 v2, 0x2

    .line 467
    if-eq v1, v2, :cond_18

    .line 468
    .line 469
    const/4 v2, 0x3

    .line 470
    if-ne v1, v2, :cond_17

    .line 471
    .line 472
    sget-object v8, Landroid/text/Layout$Alignment;->ALIGN_CENTER:Landroid/text/Layout$Alignment;

    .line 473
    .line 474
    goto :goto_f

    .line 475
    :cond_17
    new-instance v0, La8/r0;

    .line 476
    .line 477
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 478
    .line 479
    .line 480
    throw v0

    .line 481
    :cond_18
    sget-object v8, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 482
    .line 483
    goto :goto_f

    .line 484
    :cond_19
    sget-object v8, Landroid/text/Layout$Alignment;->ALIGN_OPPOSITE:Landroid/text/Layout$Alignment;

    .line 485
    .line 486
    :goto_f
    sget-object v1, Lqw/d;->a:[I

    .line 487
    .line 488
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 489
    .line 490
    .line 491
    move-result v2

    .line 492
    aget v1, v1, v2

    .line 493
    .line 494
    const/4 v2, 0x1

    .line 495
    if-eq v1, v2, :cond_1e

    .line 496
    .line 497
    const/4 v2, 0x2

    .line 498
    if-eq v1, v2, :cond_1c

    .line 499
    .line 500
    const/4 v2, 0x3

    .line 501
    if-ne v1, v2, :cond_1b

    .line 502
    .line 503
    iget-object v1, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 504
    .line 505
    if-eqz v1, :cond_1a

    .line 506
    .line 507
    invoke-virtual {v1}, Landroid/text/Layout;->getWidth()I

    .line 508
    .line 509
    .line 510
    move-result v1

    .line 511
    int-to-float v1, v1

    .line 512
    sub-float v1, p4, v1

    .line 513
    .line 514
    div-float v1, v1, v16

    .line 515
    .line 516
    goto :goto_10

    .line 517
    :cond_1a
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    throw p8

    .line 521
    :cond_1b
    new-instance v0, La8/r0;

    .line 522
    .line 523
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 524
    .line 525
    .line 526
    throw v0

    .line 527
    :cond_1c
    iget-object v1, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 528
    .line 529
    if-eqz v1, :cond_1d

    .line 530
    .line 531
    invoke-virtual {v1}, Landroid/text/Layout;->getWidth()I

    .line 532
    .line 533
    .line 534
    move-result v1

    .line 535
    int-to-float v1, v1

    .line 536
    sub-float v1, p4, v1

    .line 537
    .line 538
    goto :goto_10

    .line 539
    :cond_1d
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    throw p8

    .line 543
    :cond_1e
    move/from16 v1, p10

    .line 544
    .line 545
    :goto_10
    iget v2, v12, Landroid/graphics/RectF;->left:F

    .line 546
    .line 547
    sub-float/2addr v2, v4

    .line 548
    iput v2, v12, Landroid/graphics/RectF;->left:F

    .line 549
    .line 550
    iget v2, v12, Landroid/graphics/RectF;->top:F

    .line 551
    .line 552
    invoke-interface {v10, v15}, Lpw/f;->c(F)F

    .line 553
    .line 554
    .line 555
    move-result v8

    .line 556
    sub-float/2addr v2, v8

    .line 557
    iput v2, v12, Landroid/graphics/RectF;->top:F

    .line 558
    .line 559
    iget v2, v12, Landroid/graphics/RectF;->right:F

    .line 560
    .line 561
    add-float/2addr v2, v14

    .line 562
    iput v2, v12, Landroid/graphics/RectF;->right:F

    .line 563
    .line 564
    iget v2, v12, Landroid/graphics/RectF;->bottom:F

    .line 565
    .line 566
    iget v8, v9, Lpw/c;->d:F

    .line 567
    .line 568
    invoke-interface {v10, v8}, Lpw/f;->c(F)F

    .line 569
    .line 570
    .line 571
    move-result v8

    .line 572
    add-float/2addr v8, v2

    .line 573
    iput v8, v12, Landroid/graphics/RectF;->bottom:F

    .line 574
    .line 575
    if-nez v3, :cond_23

    .line 576
    .line 577
    new-instance v2, Landroid/graphics/RectF;

    .line 578
    .line 579
    invoke-direct {v2, v12}, Landroid/graphics/RectF;-><init>(Landroid/graphics/RectF;)V

    .line 580
    .line 581
    .line 582
    invoke-static {v2, v5}, Ljp/ae;->b(Landroid/graphics/RectF;F)V

    .line 583
    .line 584
    .line 585
    invoke-virtual {v12}, Landroid/graphics/RectF;->height()F

    .line 586
    .line 587
    .line 588
    move-result v8

    .line 589
    invoke-virtual {v2}, Landroid/graphics/RectF;->height()F

    .line 590
    .line 591
    .line 592
    move-result v9

    .line 593
    sub-float/2addr v8, v9

    .line 594
    invoke-virtual {v12}, Landroid/graphics/RectF;->width()F

    .line 595
    .line 596
    .line 597
    move-result v9

    .line 598
    invoke-virtual {v2}, Landroid/graphics/RectF;->width()F

    .line 599
    .line 600
    .line 601
    move-result v2

    .line 602
    sub-float/2addr v9, v2

    .line 603
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 604
    .line 605
    .line 606
    move-result v2

    .line 607
    if-eqz v2, :cond_20

    .line 608
    .line 609
    const/4 v7, 0x2

    .line 610
    if-eq v2, v7, :cond_1f

    .line 611
    .line 612
    move/from16 v2, p10

    .line 613
    .line 614
    goto :goto_11

    .line 615
    :cond_1f
    div-float v9, v9, v16

    .line 616
    .line 617
    neg-float v2, v9

    .line 618
    goto :goto_11

    .line 619
    :cond_20
    const/4 v7, 0x2

    .line 620
    div-float v2, v9, v16

    .line 621
    .line 622
    :goto_11
    invoke-interface {v10}, Lpw/f;->h()F

    .line 623
    .line 624
    .line 625
    move-result v9

    .line 626
    mul-float/2addr v9, v2

    .line 627
    invoke-virtual/range {p6 .. p6}, Ljava/lang/Enum;->ordinal()I

    .line 628
    .line 629
    .line 630
    move-result v2

    .line 631
    if-eqz v2, :cond_22

    .line 632
    .line 633
    if-eq v2, v7, :cond_21

    .line 634
    .line 635
    move/from16 v8, p10

    .line 636
    .line 637
    goto :goto_12

    .line 638
    :cond_21
    div-float v8, v8, v16

    .line 639
    .line 640
    neg-float v8, v8

    .line 641
    goto :goto_12

    .line 642
    :cond_22
    div-float v8, v8, v16

    .line 643
    .line 644
    :goto_12
    move v2, v8

    .line 645
    move v8, v9

    .line 646
    goto :goto_13

    .line 647
    :cond_23
    move/from16 v2, p10

    .line 648
    .line 649
    move v8, v2

    .line 650
    :goto_13
    add-float/2addr v6, v8

    .line 651
    add-float v2, p3, v2

    .line 652
    .line 653
    invoke-static {v12, v6, v2}, Ljp/ae;->d(Landroid/graphics/RectF;FF)V

    .line 654
    .line 655
    .line 656
    if-nez v3, :cond_24

    .line 657
    .line 658
    invoke-virtual {v12}, Landroid/graphics/RectF;->centerX()F

    .line 659
    .line 660
    .line 661
    move-result v2

    .line 662
    invoke-virtual {v12}, Landroid/graphics/RectF;->centerY()F

    .line 663
    .line 664
    .line 665
    move-result v3

    .line 666
    invoke-virtual {v11, v5, v2, v3}, Landroid/graphics/Canvas;->rotate(FFF)V

    .line 667
    .line 668
    .line 669
    :cond_24
    iget-object v2, v0, Lqw/e;->j:Lqw/b;

    .line 670
    .line 671
    if-eqz v2, :cond_25

    .line 672
    .line 673
    iget v3, v12, Landroid/graphics/RectF;->left:F

    .line 674
    .line 675
    iget v5, v12, Landroid/graphics/RectF;->top:F

    .line 676
    .line 677
    iget v6, v12, Landroid/graphics/RectF;->right:F

    .line 678
    .line 679
    iget v7, v12, Landroid/graphics/RectF;->bottom:F

    .line 680
    .line 681
    move-object/from16 p3, p1

    .line 682
    .line 683
    move-object/from16 p2, v2

    .line 684
    .line 685
    move/from16 p4, v3

    .line 686
    .line 687
    move/from16 p5, v5

    .line 688
    .line 689
    move/from16 p6, v6

    .line 690
    .line 691
    move/from16 p7, v7

    .line 692
    .line 693
    invoke-virtual/range {p2 .. p7}, Lqw/b;->a(Lc1/h2;FFFF)V

    .line 694
    .line 695
    .line 696
    move-object/from16 v2, p3

    .line 697
    .line 698
    goto :goto_14

    .line 699
    :cond_25
    move-object/from16 v2, p1

    .line 700
    .line 701
    :goto_14
    iget v3, v12, Landroid/graphics/RectF;->left:F

    .line 702
    .line 703
    add-float/2addr v3, v4

    .line 704
    add-float/2addr v3, v1

    .line 705
    iget v1, v12, Landroid/graphics/RectF;->top:F

    .line 706
    .line 707
    invoke-interface {v10, v15}, Lpw/f;->c(F)F

    .line 708
    .line 709
    .line 710
    move-result v4

    .line 711
    add-float/2addr v4, v1

    .line 712
    iget-object v1, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 713
    .line 714
    if-eqz v1, :cond_27

    .line 715
    .line 716
    invoke-virtual {v1}, Landroid/text/Layout;->getSpacingAdd()F

    .line 717
    .line 718
    .line 719
    move-result v1

    .line 720
    div-float v1, v1, v16

    .line 721
    .line 722
    add-float/2addr v1, v4

    .line 723
    invoke-virtual {v11, v3, v1}, Landroid/graphics/Canvas;->translate(FF)V

    .line 724
    .line 725
    .line 726
    iget-object v0, v0, Lqw/e;->m:Landroid/text/StaticLayout;

    .line 727
    .line 728
    if-eqz v0, :cond_26

    .line 729
    .line 730
    invoke-virtual {v0, v11}, Landroid/text/Layout;->draw(Landroid/graphics/Canvas;)V

    .line 731
    .line 732
    .line 733
    iget-object v0, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 734
    .line 735
    check-cast v0, Landroid/graphics/Canvas;

    .line 736
    .line 737
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 738
    .line 739
    .line 740
    return-void

    .line 741
    :cond_26
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 742
    .line 743
    .line 744
    throw p8

    .line 745
    :cond_27
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 746
    .line 747
    .line 748
    throw p8

    .line 749
    :cond_28
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 750
    .line 751
    .line 752
    throw p8

    .line 753
    :cond_29
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 754
    .line 755
    .line 756
    throw p8

    .line 757
    :cond_2a
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 758
    .line 759
    .line 760
    throw p8

    .line 761
    :cond_2b
    const/16 p8, 0x0

    .line 762
    .line 763
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 764
    .line 765
    .line 766
    throw p8
.end method

.method public static b(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IILandroid/graphics/RectF;FZI)Landroid/graphics/RectF;
    .locals 6

    .line 1
    and-int/lit8 v0, p8, 0x4

    .line 2
    .line 3
    const v1, 0x186a0

    .line 4
    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move p3, v1

    .line 9
    :cond_0
    and-int/lit8 v0, p8, 0x8

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    move p4, v1

    .line 14
    :cond_1
    and-int/lit8 v0, p8, 0x10

    .line 15
    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    iget-object p5, p0, Lqw/e;->o:Landroid/graphics/RectF;

    .line 19
    .line 20
    :cond_2
    move-object v0, p5

    .line 21
    and-int/lit8 p5, p8, 0x40

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    if-eqz p5, :cond_3

    .line 25
    .line 26
    move p5, v1

    .line 27
    goto :goto_0

    .line 28
    :cond_3
    move p5, p6

    .line 29
    :goto_0
    and-int/lit16 p6, p8, 0x80

    .line 30
    .line 31
    const/4 p8, 0x0

    .line 32
    if-eqz p6, :cond_5

    .line 33
    .line 34
    if-nez p2, :cond_4

    .line 35
    .line 36
    const/4 p6, 0x1

    .line 37
    move p7, p6

    .line 38
    goto :goto_1

    .line 39
    :cond_4
    move p7, p8

    .line 40
    :cond_5
    :goto_1
    iget-object p6, p0, Lqw/e;->h:Lpw/c;

    .line 41
    .line 42
    iget-object v2, p0, Lqw/e;->i:Lpw/c;

    .line 43
    .line 44
    const-string v3, "context"

    .line 45
    .line 46
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const-string v3, "outRect"

    .line 50
    .line 51
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    if-nez p2, :cond_6

    .line 55
    .line 56
    const-string p2, ""

    .line 57
    .line 58
    :cond_6
    if-eqz p7, :cond_c

    .line 59
    .line 60
    new-instance p7, Landroid/text/SpannableStringBuilder;

    .line 61
    .line 62
    invoke-direct {p7, p2}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    .line 63
    .line 64
    .line 65
    iget p2, p0, Lqw/e;->f:I

    .line 66
    .line 67
    new-instance v3, Lly0/h;

    .line 68
    .line 69
    invoke-direct {v3, p7}, Lly0/h;-><init>(Ljava/lang/CharSequence;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v3}, Lly0/h;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    if-nez v4, :cond_7

    .line 77
    .line 78
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_7
    invoke-virtual {v3}, Lly0/h;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    invoke-virtual {v3}, Lly0/h;->hasNext()Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-nez v5, :cond_8

    .line 90
    .line 91
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    goto :goto_3

    .line 96
    :cond_8
    new-instance v5, Ljava/util/ArrayList;

    .line 97
    .line 98
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    :goto_2
    invoke-virtual {v3}, Lly0/h;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result v4

    .line 108
    if-eqz v4, :cond_9

    .line 109
    .line 110
    invoke-virtual {v3}, Lly0/h;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_9
    move-object v3, v5

    .line 119
    :goto_3
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    sub-int/2addr p2, v3

    .line 124
    if-gez p2, :cond_a

    .line 125
    .line 126
    move p2, p8

    .line 127
    :cond_a
    :goto_4
    if-ge p8, p2, :cond_b

    .line 128
    .line 129
    const/16 v3, 0xa

    .line 130
    .line 131
    invoke-virtual {p7, v3}, Landroid/text/SpannableStringBuilder;->append(C)Landroid/text/SpannableStringBuilder;

    .line 132
    .line 133
    .line 134
    add-int/lit8 p8, p8, 0x1

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_b
    move-object p2, p7

    .line 138
    :cond_c
    check-cast p2, Ljava/lang/CharSequence;

    .line 139
    .line 140
    invoke-virtual/range {p0 .. p5}, Lqw/e;->d(Lpw/f;Ljava/lang/CharSequence;IIF)Landroid/text/StaticLayout;

    .line 141
    .line 142
    .line 143
    move-result-object p2

    .line 144
    iput v1, v0, Landroid/graphics/RectF;->left:F

    .line 145
    .line 146
    iput v1, v0, Landroid/graphics/RectF;->top:F

    .line 147
    .line 148
    invoke-static {p2}, Ljp/be;->a(Landroid/text/Layout;)F

    .line 149
    .line 150
    .line 151
    move-result p3

    .line 152
    iput p3, v0, Landroid/graphics/RectF;->right:F

    .line 153
    .line 154
    invoke-virtual {p2}, Landroid/text/Layout;->getHeight()I

    .line 155
    .line 156
    .line 157
    move-result p3

    .line 158
    int-to-float p3, p3

    .line 159
    invoke-virtual {p2}, Landroid/text/Layout;->getSpacingAdd()F

    .line 160
    .line 161
    .line 162
    move-result p4

    .line 163
    add-float/2addr p4, p3

    .line 164
    iput p4, v0, Landroid/graphics/RectF;->bottom:F

    .line 165
    .line 166
    iget-object p0, p0, Lqw/e;->k:Lqw/c;

    .line 167
    .line 168
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    invoke-interface {p1, v1}, Lpw/f;->c(F)F

    .line 172
    .line 173
    .line 174
    move-result p0

    .line 175
    invoke-virtual {v2}, Lpw/c;->a()F

    .line 176
    .line 177
    .line 178
    move-result p3

    .line 179
    invoke-interface {p1, p3}, Lpw/f;->c(F)F

    .line 180
    .line 181
    .line 182
    move-result p3

    .line 183
    sub-float/2addr p0, p3

    .line 184
    iget p3, v0, Landroid/graphics/RectF;->right:F

    .line 185
    .line 186
    cmpg-float p4, p3, p0

    .line 187
    .line 188
    if-gez p4, :cond_d

    .line 189
    .line 190
    goto :goto_5

    .line 191
    :cond_d
    move p0, p3

    .line 192
    :goto_5
    invoke-virtual {p2}, Landroid/text/Layout;->getWidth()I

    .line 193
    .line 194
    .line 195
    move-result p2

    .line 196
    int-to-float p2, p2

    .line 197
    cmpl-float p3, p0, p2

    .line 198
    .line 199
    if-lez p3, :cond_e

    .line 200
    .line 201
    move p0, p2

    .line 202
    :cond_e
    iput p0, v0, Landroid/graphics/RectF;->right:F

    .line 203
    .line 204
    invoke-virtual {v2}, Lpw/c;->a()F

    .line 205
    .line 206
    .line 207
    move-result p2

    .line 208
    invoke-interface {p1, p2}, Lpw/f;->c(F)F

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    add-float/2addr p2, p0

    .line 213
    iput p2, v0, Landroid/graphics/RectF;->right:F

    .line 214
    .line 215
    iget p0, v0, Landroid/graphics/RectF;->bottom:F

    .line 216
    .line 217
    iget p2, v2, Lpw/c;->b:F

    .line 218
    .line 219
    iget p3, v2, Lpw/c;->d:F

    .line 220
    .line 221
    add-float/2addr p2, p3

    .line 222
    invoke-interface {p1, p2}, Lpw/f;->c(F)F

    .line 223
    .line 224
    .line 225
    move-result p2

    .line 226
    add-float/2addr p2, p0

    .line 227
    iput p2, v0, Landroid/graphics/RectF;->bottom:F

    .line 228
    .line 229
    invoke-static {v0, p5}, Ljp/ae;->b(Landroid/graphics/RectF;F)V

    .line 230
    .line 231
    .line 232
    iget p0, v0, Landroid/graphics/RectF;->right:F

    .line 233
    .line 234
    invoke-virtual {p6}, Lpw/c;->a()F

    .line 235
    .line 236
    .line 237
    move-result p2

    .line 238
    invoke-interface {p1, p2}, Lpw/f;->c(F)F

    .line 239
    .line 240
    .line 241
    move-result p2

    .line 242
    add-float/2addr p2, p0

    .line 243
    iput p2, v0, Landroid/graphics/RectF;->right:F

    .line 244
    .line 245
    iget p0, v0, Landroid/graphics/RectF;->bottom:F

    .line 246
    .line 247
    iget p2, p6, Lpw/c;->b:F

    .line 248
    .line 249
    iget p3, p6, Lpw/c;->d:F

    .line 250
    .line 251
    add-float/2addr p2, p3

    .line 252
    invoke-interface {p1, p2}, Lpw/f;->c(F)F

    .line 253
    .line 254
    .line 255
    move-result p1

    .line 256
    add-float/2addr p1, p0

    .line 257
    iput p1, v0, Landroid/graphics/RectF;->bottom:F

    .line 258
    .line 259
    return-object v0
.end method

.method public static c(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IFI)F
    .locals 9

    .line 1
    and-int/lit8 v0, p5, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    :cond_0
    move-object v2, p2

    .line 7
    and-int/lit8 p2, p5, 0x4

    .line 8
    .line 9
    if-eqz p2, :cond_1

    .line 10
    .line 11
    const p3, 0x186a0

    .line 12
    .line 13
    .line 14
    :cond_1
    move v3, p3

    .line 15
    and-int/lit8 p2, p5, 0x10

    .line 16
    .line 17
    if-eqz p2, :cond_2

    .line 18
    .line 19
    const/4 p4, 0x0

    .line 20
    :cond_2
    move v6, p4

    .line 21
    and-int/lit8 p2, p5, 0x20

    .line 22
    .line 23
    const/4 p3, 0x1

    .line 24
    if-eqz p2, :cond_4

    .line 25
    .line 26
    if-nez v2, :cond_3

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_3
    const/4 p3, 0x0

    .line 30
    :cond_4
    :goto_0
    move v7, p3

    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const-string p2, "context"

    .line 35
    .line 36
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    const/16 v8, 0x30

    .line 41
    .line 42
    const v4, 0x186a0

    .line 43
    .line 44
    .line 45
    move-object v0, p0

    .line 46
    move-object v1, p1

    .line 47
    invoke-static/range {v0 .. v8}, Lqw/e;->b(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IILandroid/graphics/RectF;FZI)Landroid/graphics/RectF;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    return p0
.end method

.method public static f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F
    .locals 9

    .line 1
    and-int/lit8 v0, p5, 0x8

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const p3, 0x186a0

    .line 6
    .line 7
    .line 8
    :cond_0
    move v4, p3

    .line 9
    and-int/lit8 p3, p5, 0x20

    .line 10
    .line 11
    const/4 p5, 0x1

    .line 12
    if-eqz p3, :cond_2

    .line 13
    .line 14
    if-nez p2, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    const/4 p5, 0x0

    .line 18
    :cond_2
    :goto_0
    move v7, p5

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    const/4 v5, 0x0

    .line 23
    const/16 v8, 0x30

    .line 24
    .line 25
    const v3, 0x186a0

    .line 26
    .line 27
    .line 28
    move-object v0, p0

    .line 29
    move-object v1, p1

    .line 30
    move-object v2, p2

    .line 31
    move v6, p4

    .line 32
    invoke-static/range {v0 .. v8}, Lqw/e;->b(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IILandroid/graphics/RectF;FZI)Landroid/graphics/RectF;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method


# virtual methods
.method public final d(Lpw/f;Ljava/lang/CharSequence;IIF)Landroid/text/StaticLayout;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p5

    .line 6
    .line 7
    iget v3, v0, Lqw/e;->c:F

    .line 8
    .line 9
    invoke-interface {v1, v3}, Lpw/f;->b(F)F

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    iget-object v5, v0, Lqw/e;->l:Landroid/text/TextPaint;

    .line 14
    .line 15
    invoke-virtual {v5, v3}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v1}, Lpw/f;->i()Lc2/k;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-virtual {v5}, Landroid/graphics/Paint;->getTypeface()Landroid/graphics/Typeface;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    invoke-virtual {v4}, Landroid/graphics/Typeface;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-virtual {v5}, Landroid/graphics/Paint;->getTextSize()F

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    filled-new-array {v4, v6}, [Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v12

    .line 46
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    array-length v4, v12

    .line 50
    invoke-static {v12, v4}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    sget-object v13, Lqw/e;->p:Lfv/b;

    .line 55
    .line 56
    invoke-virtual {v3, v13, v4}, Lc2/k;->w(Lfv/b;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    if-nez v4, :cond_0

    .line 61
    .line 62
    const/4 v10, 0x0

    .line 63
    const/16 v11, 0xff8

    .line 64
    .line 65
    const-string v4, ""

    .line 66
    .line 67
    const v6, 0x186a0

    .line 68
    .line 69
    .line 70
    const/4 v7, 0x0

    .line 71
    const/4 v8, 0x0

    .line 72
    const/4 v9, 0x0

    .line 73
    invoke-static/range {v4 .. v11}, Ljp/be;->b(Ljava/lang/CharSequence;Landroid/text/TextPaint;IIFLandroid/text/TextUtils$TruncateAt;Landroid/text/Layout$Alignment;I)Landroid/text/StaticLayout;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    array-length v6, v12

    .line 78
    invoke-static {v12, v6}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    invoke-virtual {v3, v13, v6, v4}, Lc2/k;->A(Lfv/b;[Ljava/lang/Object;Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_0
    check-cast v4, Landroid/text/Layout;

    .line 86
    .line 87
    iput-object v4, v0, Lqw/e;->n:Landroid/text/Layout;

    .line 88
    .line 89
    iget-object v3, v0, Lqw/e;->h:Lpw/c;

    .line 90
    .line 91
    invoke-virtual {v3}, Lpw/c;->a()F

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    invoke-interface {v1, v4}, Lpw/f;->k(F)I

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    sub-int v4, p3, v4

    .line 100
    .line 101
    iget v6, v3, Lpw/c;->b:F

    .line 102
    .line 103
    iget v3, v3, Lpw/c;->d:F

    .line 104
    .line 105
    add-float/2addr v6, v3

    .line 106
    invoke-interface {v1, v6}, Lpw/f;->k(F)I

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    sub-int v3, p4, v3

    .line 111
    .line 112
    const/4 v6, 0x0

    .line 113
    const/4 v7, 0x0

    .line 114
    const-string v8, "measuringLayout"

    .line 115
    .line 116
    iget-object v9, v0, Lqw/e;->e:Ljava/lang/Float;

    .line 117
    .line 118
    if-eqz v9, :cond_4

    .line 119
    .line 120
    invoke-virtual {v9}, Ljava/lang/Float;->floatValue()F

    .line 121
    .line 122
    .line 123
    move-result v9

    .line 124
    invoke-interface {v1, v9}, Lpw/f;->b(F)F

    .line 125
    .line 126
    .line 127
    move-result v9

    .line 128
    iget-object v10, v0, Lqw/e;->n:Landroid/text/Layout;

    .line 129
    .line 130
    if-eqz v10, :cond_3

    .line 131
    .line 132
    invoke-virtual {v10}, Landroid/text/Layout;->getHeight()I

    .line 133
    .line 134
    .line 135
    move-result v10

    .line 136
    int-to-float v10, v10

    .line 137
    sub-float/2addr v9, v10

    .line 138
    iget-object v10, v0, Lqw/e;->n:Landroid/text/Layout;

    .line 139
    .line 140
    if-eqz v10, :cond_2

    .line 141
    .line 142
    invoke-virtual {v10}, Landroid/text/Layout;->getTopPadding()I

    .line 143
    .line 144
    .line 145
    move-result v10

    .line 146
    int-to-float v10, v10

    .line 147
    sub-float/2addr v9, v10

    .line 148
    iget-object v10, v0, Lqw/e;->n:Landroid/text/Layout;

    .line 149
    .line 150
    if-eqz v10, :cond_1

    .line 151
    .line 152
    invoke-virtual {v10}, Landroid/text/Layout;->getBottomPadding()I

    .line 153
    .line 154
    .line 155
    move-result v10

    .line 156
    int-to-float v10, v10

    .line 157
    sub-float/2addr v9, v10

    .line 158
    goto :goto_0

    .line 159
    :cond_1
    invoke-static {v8}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw v6

    .line 163
    :cond_2
    invoke-static {v8}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw v6

    .line 167
    :cond_3
    invoke-static {v8}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw v6

    .line 171
    :cond_4
    move v9, v7

    .line 172
    :goto_0
    const/high16 v10, 0x43340000    # 180.0f

    .line 173
    .line 174
    rem-float v10, v2, v10

    .line 175
    .line 176
    cmpg-float v10, v10, v7

    .line 177
    .line 178
    iget-object v11, v0, Lqw/e;->i:Lpw/c;

    .line 179
    .line 180
    iget v12, v0, Lqw/e;->f:I

    .line 181
    .line 182
    if-nez v10, :cond_5

    .line 183
    .line 184
    :goto_1
    move-object/from16 p5, v5

    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_5
    const/high16 v10, 0x42b40000    # 90.0f

    .line 188
    .line 189
    rem-float v10, v2, v10

    .line 190
    .line 191
    cmpg-float v7, v10, v7

    .line 192
    .line 193
    if-nez v7, :cond_6

    .line 194
    .line 195
    move v4, v3

    .line 196
    goto :goto_1

    .line 197
    :cond_6
    int-to-float v7, v12

    .line 198
    iget-object v10, v0, Lqw/e;->n:Landroid/text/Layout;

    .line 199
    .line 200
    if-eqz v10, :cond_9

    .line 201
    .line 202
    invoke-virtual {v10}, Landroid/text/Layout;->getHeight()I

    .line 203
    .line 204
    .line 205
    move-result v6

    .line 206
    int-to-float v6, v6

    .line 207
    add-float/2addr v6, v9

    .line 208
    mul-float/2addr v6, v7

    .line 209
    iget v7, v11, Lpw/c;->b:F

    .line 210
    .line 211
    iget v8, v11, Lpw/c;->d:F

    .line 212
    .line 213
    add-float/2addr v7, v8

    .line 214
    invoke-interface {v1, v7}, Lpw/f;->k(F)I

    .line 215
    .line 216
    .line 217
    move-result v7

    .line 218
    int-to-float v7, v7

    .line 219
    add-float/2addr v6, v7

    .line 220
    float-to-double v7, v2

    .line 221
    invoke-static {v7, v8}, Ljava/lang/Math;->toRadians(D)D

    .line 222
    .line 223
    .line 224
    move-result-wide v7

    .line 225
    invoke-static {v7, v8}, Ljava/lang/Math;->sin(D)D

    .line 226
    .line 227
    .line 228
    move-result-wide v14

    .line 229
    invoke-static {v14, v15}, Ljava/lang/Math;->abs(D)D

    .line 230
    .line 231
    .line 232
    move-result-wide v14

    .line 233
    invoke-static {v7, v8}, Ljava/lang/Math;->cos(D)D

    .line 234
    .line 235
    .line 236
    move-result-wide v7

    .line 237
    invoke-static {v7, v8}, Ljava/lang/Math;->abs(D)D

    .line 238
    .line 239
    .line 240
    move-result-wide v7

    .line 241
    move-object v2, v5

    .line 242
    int-to-double v4, v4

    .line 243
    move-wide/from16 p3, v4

    .line 244
    .line 245
    float-to-double v4, v6

    .line 246
    mul-double v16, v4, v14

    .line 247
    .line 248
    sub-double v16, p3, v16

    .line 249
    .line 250
    move-wide/from16 p3, v4

    .line 251
    .line 252
    div-double v4, v16, v7

    .line 253
    .line 254
    move-object/from16 p5, v2

    .line 255
    .line 256
    int-to-double v2, v3

    .line 257
    mul-double v6, p3, v7

    .line 258
    .line 259
    sub-double/2addr v2, v6

    .line 260
    div-double/2addr v2, v14

    .line 261
    invoke-static {v4, v5, v2, v3}, Ljava/lang/Math;->min(DD)D

    .line 262
    .line 263
    .line 264
    move-result-wide v2

    .line 265
    double-to-int v4, v2

    .line 266
    :goto_2
    invoke-virtual {v11}, Lpw/c;->a()F

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    invoke-interface {v1, v2}, Lpw/f;->k(F)I

    .line 271
    .line 272
    .line 273
    move-result v2

    .line 274
    sub-int/2addr v4, v2

    .line 275
    if-gez v4, :cond_7

    .line 276
    .line 277
    const/4 v4, 0x0

    .line 278
    :cond_7
    move v6, v4

    .line 279
    invoke-interface {v1}, Lpw/f;->i()Lc2/k;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Object;->hashCode()I

    .line 284
    .line 285
    .line 286
    move-result v2

    .line 287
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 288
    .line 289
    .line 290
    move-result-object v14

    .line 291
    invoke-virtual/range {p5 .. p5}, Landroid/graphics/Paint;->getColor()I

    .line 292
    .line 293
    .line 294
    move-result v2

    .line 295
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 296
    .line 297
    .line 298
    move-result-object v15

    .line 299
    invoke-virtual/range {p5 .. p5}, Landroid/graphics/Paint;->getTypeface()Landroid/graphics/Typeface;

    .line 300
    .line 301
    .line 302
    move-result-object v2

    .line 303
    invoke-virtual {v2}, Landroid/graphics/Typeface;->hashCode()I

    .line 304
    .line 305
    .line 306
    move-result v2

    .line 307
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 308
    .line 309
    .line 310
    move-result-object v16

    .line 311
    invoke-virtual/range {p5 .. p5}, Landroid/graphics/Paint;->getTextSize()F

    .line 312
    .line 313
    .line 314
    move-result v2

    .line 315
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 316
    .line 317
    .line 318
    move-result-object v17

    .line 319
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 320
    .line 321
    .line 322
    move-result-object v18

    .line 323
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 324
    .line 325
    .line 326
    move-result-object v19

    .line 327
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 328
    .line 329
    .line 330
    move-result-object v20

    .line 331
    iget-object v2, v0, Lqw/e;->g:Landroid/text/TextUtils$TruncateAt;

    .line 332
    .line 333
    iget-object v3, v0, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 334
    .line 335
    move-object/from16 v21, v2

    .line 336
    .line 337
    move-object/from16 v22, v3

    .line 338
    .line 339
    filled-new-array/range {v14 .. v22}, [Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object v2

    .line 343
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 344
    .line 345
    .line 346
    array-length v3, v2

    .line 347
    invoke-static {v2, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v3

    .line 351
    invoke-virtual {v1, v13, v3}, Lc2/k;->w(Lfv/b;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v3

    .line 355
    if-nez v3, :cond_8

    .line 356
    .line 357
    iget-object v10, v0, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 358
    .line 359
    const/16 v11, 0x570

    .line 360
    .line 361
    iget v7, v0, Lqw/e;->f:I

    .line 362
    .line 363
    iget-object v0, v0, Lqw/e;->g:Landroid/text/TextUtils$TruncateAt;

    .line 364
    .line 365
    move-object/from16 v4, p2

    .line 366
    .line 367
    move-object/from16 v5, p5

    .line 368
    .line 369
    move v8, v9

    .line 370
    move-object v9, v0

    .line 371
    invoke-static/range {v4 .. v11}, Ljp/be;->b(Ljava/lang/CharSequence;Landroid/text/TextPaint;IIFLandroid/text/TextUtils$TruncateAt;Landroid/text/Layout$Alignment;I)Landroid/text/StaticLayout;

    .line 372
    .line 373
    .line 374
    move-result-object v3

    .line 375
    array-length v0, v2

    .line 376
    invoke-static {v2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    invoke-virtual {v1, v13, v0, v3}, Lc2/k;->A(Lfv/b;[Ljava/lang/Object;Ljava/lang/Object;)V

    .line 381
    .line 382
    .line 383
    :cond_8
    check-cast v3, Landroid/text/StaticLayout;

    .line 384
    .line 385
    return-object v3

    .line 386
    :cond_9
    invoke-static {v8}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 387
    .line 388
    .line 389
    throw v6
.end method

.method public final e(Lc1/h2;FF)F
    .locals 2

    .line 1
    iget-object v0, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lkw/g;

    .line 4
    .line 5
    invoke-interface {v0}, Lpw/f;->e()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lqw/e;->i:Lpw/c;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget v0, v1, Lpw/c;->c:F

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget v0, v1, Lpw/c;->a:F

    .line 17
    .line 18
    :goto_0
    iget-object p1, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Lkw/g;

    .line 21
    .line 22
    invoke-interface {p1, v0}, Lpw/f;->c(F)F

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    sub-float/2addr p2, v0

    .line 27
    invoke-interface {p1}, Lpw/f;->e()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    iget-object p0, p0, Lqw/e;->h:Lpw/c;

    .line 32
    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    iget p0, p0, Lpw/c;->c:F

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    iget p0, p0, Lpw/c;->a:F

    .line 39
    .line 40
    :goto_1
    invoke-interface {p1, p0}, Lpw/f;->c(F)F

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    sub-float/2addr p2, p0

    .line 45
    sub-float/2addr p2, p3

    .line 46
    return p2
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_2

    .line 2
    .line 3
    instance-of v0, p1, Lqw/e;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    check-cast p1, Lqw/e;

    .line 8
    .line 9
    iget v0, p1, Lqw/e;->a:I

    .line 10
    .line 11
    iget v1, p0, Lqw/e;->a:I

    .line 12
    .line 13
    if-ne v1, v0, :cond_1

    .line 14
    .line 15
    iget-object v0, p0, Lqw/e;->b:Landroid/graphics/Typeface;

    .line 16
    .line 17
    iget-object v1, p1, Lqw/e;->b:Landroid/graphics/Typeface;

    .line 18
    .line 19
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    iget v0, p0, Lqw/e;->c:F

    .line 26
    .line 27
    iget v1, p1, Lqw/e;->c:F

    .line 28
    .line 29
    cmpg-float v0, v0, v1

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    iget-object v0, p1, Lqw/e;->e:Ljava/lang/Float;

    .line 34
    .line 35
    iget-object v1, p0, Lqw/e;->e:Ljava/lang/Float;

    .line 36
    .line 37
    if-nez v1, :cond_0

    .line 38
    .line 39
    if-nez v0, :cond_1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    if-eqz v0, :cond_1

    .line 43
    .line 44
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    cmpl-float v0, v1, v0

    .line 53
    .line 54
    if-nez v0, :cond_1

    .line 55
    .line 56
    :goto_0
    iget-object v0, p0, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 57
    .line 58
    iget-object v1, p1, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 59
    .line 60
    if-ne v0, v1, :cond_1

    .line 61
    .line 62
    iget v0, p0, Lqw/e;->f:I

    .line 63
    .line 64
    iget v1, p1, Lqw/e;->f:I

    .line 65
    .line 66
    if-ne v0, v1, :cond_1

    .line 67
    .line 68
    iget-object v0, p0, Lqw/e;->g:Landroid/text/TextUtils$TruncateAt;

    .line 69
    .line 70
    iget-object v1, p1, Lqw/e;->g:Landroid/text/TextUtils$TruncateAt;

    .line 71
    .line 72
    if-ne v0, v1, :cond_1

    .line 73
    .line 74
    iget-object v0, p0, Lqw/e;->h:Lpw/c;

    .line 75
    .line 76
    iget-object v1, p1, Lqw/e;->h:Lpw/c;

    .line 77
    .line 78
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_1

    .line 83
    .line 84
    iget-object v0, p0, Lqw/e;->i:Lpw/c;

    .line 85
    .line 86
    iget-object v1, p1, Lqw/e;->i:Lpw/c;

    .line 87
    .line 88
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_1

    .line 93
    .line 94
    iget-object v0, p0, Lqw/e;->j:Lqw/b;

    .line 95
    .line 96
    iget-object v1, p1, Lqw/e;->j:Lqw/b;

    .line 97
    .line 98
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-eqz v0, :cond_1

    .line 103
    .line 104
    iget-object p0, p0, Lqw/e;->k:Lqw/c;

    .line 105
    .line 106
    iget-object p1, p1, Lqw/e;->k:Lqw/c;

    .line 107
    .line 108
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    if-eqz p0, :cond_1

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_1
    const/4 p0, 0x0

    .line 116
    return p0

    .line 117
    :cond_2
    :goto_1
    const/4 p0, 0x1

    .line 118
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lqw/e;->a:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    mul-int/2addr v0, v1

    .line 6
    iget-object v2, p0, Lqw/e;->b:Landroid/graphics/Typeface;

    .line 7
    .line 8
    invoke-virtual {v2}, Landroid/graphics/Typeface;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    add-int/2addr v2, v0

    .line 13
    mul-int/2addr v2, v1

    .line 14
    iget v0, p0, Lqw/e;->c:F

    .line 15
    .line 16
    invoke-static {v0, v2, v1}, La7/g0;->c(FII)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v2, 0x0

    .line 21
    iget-object v3, p0, Lqw/e;->e:Ljava/lang/Float;

    .line 22
    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v3, v2

    .line 31
    :goto_0
    add-int/2addr v0, v3

    .line 32
    mul-int/2addr v0, v1

    .line 33
    iget-object v3, p0, Lqw/e;->d:Landroid/text/Layout$Alignment;

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    add-int/2addr v3, v0

    .line 40
    mul-int/2addr v3, v1

    .line 41
    iget v0, p0, Lqw/e;->f:I

    .line 42
    .line 43
    add-int/2addr v3, v0

    .line 44
    mul-int/2addr v3, v1

    .line 45
    iget-object v0, p0, Lqw/e;->g:Landroid/text/TextUtils$TruncateAt;

    .line 46
    .line 47
    if-eqz v0, :cond_1

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    move v0, v2

    .line 55
    :goto_1
    add-int/2addr v3, v0

    .line 56
    mul-int/2addr v3, v1

    .line 57
    iget-object v0, p0, Lqw/e;->h:Lpw/c;

    .line 58
    .line 59
    invoke-virtual {v0}, Lpw/c;->hashCode()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    add-int/2addr v0, v3

    .line 64
    mul-int/2addr v0, v1

    .line 65
    iget-object v3, p0, Lqw/e;->i:Lpw/c;

    .line 66
    .line 67
    invoke-virtual {v3}, Lpw/c;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    add-int/2addr v3, v0

    .line 72
    mul-int/2addr v3, v1

    .line 73
    iget-object v0, p0, Lqw/e;->j:Lqw/b;

    .line 74
    .line 75
    if-eqz v0, :cond_2

    .line 76
    .line 77
    invoke-virtual {v0}, Lqw/b;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    :cond_2
    add-int/2addr v3, v2

    .line 82
    mul-int/2addr v3, v1

    .line 83
    iget-object p0, p0, Lqw/e;->k:Lqw/c;

    .line 84
    .line 85
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    const/4 p0, 0x0

    .line 89
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    add-int/2addr p0, v3

    .line 94
    return p0
.end method
