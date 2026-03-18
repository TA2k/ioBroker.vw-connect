.class public final Lcb/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final p:Landroid/graphics/Matrix;


# instance fields
.field public final a:Landroid/graphics/Path;

.field public final b:Landroid/graphics/Path;

.field public final c:Landroid/graphics/Matrix;

.field public d:Landroid/graphics/Paint;

.field public e:Landroid/graphics/Paint;

.field public f:Landroid/graphics/PathMeasure;

.field public final g:Lcb/j;

.field public h:F

.field public i:F

.field public j:F

.field public k:F

.field public l:I

.field public m:Ljava/lang/String;

.field public n:Ljava/lang/Boolean;

.field public final o:Landroidx/collection/f;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroid/graphics/Matrix;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcb/m;->p:Landroid/graphics/Matrix;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Landroid/graphics/Matrix;

    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    iput-object v0, p0, Lcb/m;->c:Landroid/graphics/Matrix;

    const/4 v0, 0x0

    .line 3
    iput v0, p0, Lcb/m;->h:F

    .line 4
    iput v0, p0, Lcb/m;->i:F

    .line 5
    iput v0, p0, Lcb/m;->j:F

    .line 6
    iput v0, p0, Lcb/m;->k:F

    const/16 v0, 0xff

    .line 7
    iput v0, p0, Lcb/m;->l:I

    const/4 v0, 0x0

    .line 8
    iput-object v0, p0, Lcb/m;->m:Ljava/lang/String;

    .line 9
    iput-object v0, p0, Lcb/m;->n:Ljava/lang/Boolean;

    .line 10
    new-instance v0, Landroidx/collection/f;

    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 12
    iput-object v0, p0, Lcb/m;->o:Landroidx/collection/f;

    .line 13
    new-instance v0, Lcb/j;

    invoke-direct {v0}, Lcb/j;-><init>()V

    iput-object v0, p0, Lcb/m;->g:Lcb/j;

    .line 14
    new-instance v0, Landroid/graphics/Path;

    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    iput-object v0, p0, Lcb/m;->a:Landroid/graphics/Path;

    .line 15
    new-instance v0, Landroid/graphics/Path;

    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    iput-object v0, p0, Lcb/m;->b:Landroid/graphics/Path;

    return-void
.end method

.method public constructor <init>(Lcb/m;)V
    .locals 3

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    new-instance v0, Landroid/graphics/Matrix;

    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    iput-object v0, p0, Lcb/m;->c:Landroid/graphics/Matrix;

    const/4 v0, 0x0

    .line 18
    iput v0, p0, Lcb/m;->h:F

    .line 19
    iput v0, p0, Lcb/m;->i:F

    .line 20
    iput v0, p0, Lcb/m;->j:F

    .line 21
    iput v0, p0, Lcb/m;->k:F

    const/16 v0, 0xff

    .line 22
    iput v0, p0, Lcb/m;->l:I

    const/4 v0, 0x0

    .line 23
    iput-object v0, p0, Lcb/m;->m:Ljava/lang/String;

    .line 24
    iput-object v0, p0, Lcb/m;->n:Ljava/lang/Boolean;

    .line 25
    new-instance v0, Landroidx/collection/f;

    const/4 v1, 0x0

    .line 26
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 27
    iput-object v0, p0, Lcb/m;->o:Landroidx/collection/f;

    .line 28
    new-instance v1, Lcb/j;

    iget-object v2, p1, Lcb/m;->g:Lcb/j;

    invoke-direct {v1, v2, v0}, Lcb/j;-><init>(Lcb/j;Landroidx/collection/f;)V

    iput-object v1, p0, Lcb/m;->g:Lcb/j;

    .line 29
    new-instance v1, Landroid/graphics/Path;

    iget-object v2, p1, Lcb/m;->a:Landroid/graphics/Path;

    invoke-direct {v1, v2}, Landroid/graphics/Path;-><init>(Landroid/graphics/Path;)V

    iput-object v1, p0, Lcb/m;->a:Landroid/graphics/Path;

    .line 30
    new-instance v1, Landroid/graphics/Path;

    iget-object v2, p1, Lcb/m;->b:Landroid/graphics/Path;

    invoke-direct {v1, v2}, Landroid/graphics/Path;-><init>(Landroid/graphics/Path;)V

    iput-object v1, p0, Lcb/m;->b:Landroid/graphics/Path;

    .line 31
    iget v1, p1, Lcb/m;->h:F

    iput v1, p0, Lcb/m;->h:F

    .line 32
    iget v1, p1, Lcb/m;->i:F

    iput v1, p0, Lcb/m;->i:F

    .line 33
    iget v1, p1, Lcb/m;->j:F

    iput v1, p0, Lcb/m;->j:F

    .line 34
    iget v1, p1, Lcb/m;->k:F

    iput v1, p0, Lcb/m;->k:F

    .line 35
    iget v1, p1, Lcb/m;->l:I

    iput v1, p0, Lcb/m;->l:I

    .line 36
    iget-object v1, p1, Lcb/m;->m:Ljava/lang/String;

    iput-object v1, p0, Lcb/m;->m:Ljava/lang/String;

    .line 37
    iget-object v1, p1, Lcb/m;->m:Ljava/lang/String;

    if-eqz v1, :cond_0

    .line 38
    invoke-virtual {v0, v1, p0}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    :cond_0
    iget-object p1, p1, Lcb/m;->n:Ljava/lang/Boolean;

    iput-object p1, p0, Lcb/m;->n:Ljava/lang/Boolean;

    return-void
.end method


# virtual methods
.method public final a(Lcb/j;Landroid/graphics/Matrix;Landroid/graphics/Canvas;II)V
    .locals 20

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    iget-object v1, v0, Lcb/j;->a:Landroid/graphics/Matrix;

    .line 4
    .line 5
    iget-object v6, v0, Lcb/j;->b:Ljava/util/ArrayList;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, v0, Lcb/j;->a:Landroid/graphics/Matrix;

    .line 13
    .line 14
    iget-object v0, v0, Lcb/j;->j:Landroid/graphics/Matrix;

    .line 15
    .line 16
    invoke-virtual {v2, v0}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    .line 17
    .line 18
    .line 19
    invoke-virtual/range {p3 .. p3}, Landroid/graphics/Canvas;->save()I

    .line 20
    .line 21
    .line 22
    const/4 v7, 0x0

    .line 23
    move v8, v7

    .line 24
    :goto_0
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-ge v8, v0, :cond_16

    .line 29
    .line 30
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Lcb/k;

    .line 35
    .line 36
    instance-of v1, v0, Lcb/j;

    .line 37
    .line 38
    if-eqz v1, :cond_0

    .line 39
    .line 40
    move-object v1, v0

    .line 41
    check-cast v1, Lcb/j;

    .line 42
    .line 43
    move-object/from16 v0, p0

    .line 44
    .line 45
    move-object/from16 v3, p3

    .line 46
    .line 47
    move/from16 v4, p4

    .line 48
    .line 49
    move/from16 v5, p5

    .line 50
    .line 51
    invoke-virtual/range {v0 .. v5}, Lcb/m;->a(Lcb/j;Landroid/graphics/Matrix;Landroid/graphics/Canvas;II)V

    .line 52
    .line 53
    .line 54
    move-object v1, v0

    .line 55
    :goto_1
    move/from16 v9, p5

    .line 56
    .line 57
    move/from16 v18, v8

    .line 58
    .line 59
    goto/16 :goto_c

    .line 60
    .line 61
    :cond_0
    move-object/from16 v1, p0

    .line 62
    .line 63
    move-object/from16 v3, p3

    .line 64
    .line 65
    instance-of v4, v0, Lcb/l;

    .line 66
    .line 67
    if-eqz v4, :cond_14

    .line 68
    .line 69
    check-cast v0, Lcb/l;

    .line 70
    .line 71
    move/from16 v4, p4

    .line 72
    .line 73
    int-to-float v5, v4

    .line 74
    iget v9, v1, Lcb/m;->j:F

    .line 75
    .line 76
    div-float/2addr v5, v9

    .line 77
    move/from16 v9, p5

    .line 78
    .line 79
    int-to-float v10, v9

    .line 80
    iget v11, v1, Lcb/m;->k:F

    .line 81
    .line 82
    div-float/2addr v10, v11

    .line 83
    invoke-static {v5, v10}, Ljava/lang/Math;->min(FF)F

    .line 84
    .line 85
    .line 86
    move-result v11

    .line 87
    iget-object v12, v1, Lcb/m;->c:Landroid/graphics/Matrix;

    .line 88
    .line 89
    invoke-virtual {v12, v2}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v12, v5, v10}, Landroid/graphics/Matrix;->postScale(FF)Z

    .line 93
    .line 94
    .line 95
    const/4 v5, 0x4

    .line 96
    new-array v5, v5, [F

    .line 97
    .line 98
    fill-array-data v5, :array_0

    .line 99
    .line 100
    .line 101
    invoke-virtual {v2, v5}, Landroid/graphics/Matrix;->mapVectors([F)V

    .line 102
    .line 103
    .line 104
    aget v10, v5, v7

    .line 105
    .line 106
    float-to-double v13, v10

    .line 107
    const/4 v10, 0x1

    .line 108
    aget v15, v5, v10

    .line 109
    .line 110
    move/from16 p2, v10

    .line 111
    .line 112
    move/from16 p1, v11

    .line 113
    .line 114
    float-to-double v10, v15

    .line 115
    invoke-static {v13, v14, v10, v11}, Ljava/lang/Math;->hypot(DD)D

    .line 116
    .line 117
    .line 118
    move-result-wide v10

    .line 119
    double-to-float v10, v10

    .line 120
    const/4 v11, 0x2

    .line 121
    aget v13, v5, v11

    .line 122
    .line 123
    float-to-double v13, v13

    .line 124
    const/4 v15, 0x3

    .line 125
    move/from16 v16, v11

    .line 126
    .line 127
    aget v11, v5, v15

    .line 128
    .line 129
    move/from16 v17, v7

    .line 130
    .line 131
    move/from16 v18, v8

    .line 132
    .line 133
    float-to-double v7, v11

    .line 134
    invoke-static {v13, v14, v7, v8}, Ljava/lang/Math;->hypot(DD)D

    .line 135
    .line 136
    .line 137
    move-result-wide v7

    .line 138
    double-to-float v7, v7

    .line 139
    aget v8, v5, v17

    .line 140
    .line 141
    aget v11, v5, p2

    .line 142
    .line 143
    aget v13, v5, v16

    .line 144
    .line 145
    aget v5, v5, v15

    .line 146
    .line 147
    mul-float/2addr v8, v5

    .line 148
    mul-float/2addr v11, v13

    .line 149
    sub-float/2addr v8, v11

    .line 150
    invoke-static {v10, v7}, Ljava/lang/Math;->max(FF)F

    .line 151
    .line 152
    .line 153
    move-result v5

    .line 154
    const/4 v7, 0x0

    .line 155
    cmpl-float v10, v5, v7

    .line 156
    .line 157
    if-lez v10, :cond_1

    .line 158
    .line 159
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 160
    .line 161
    .line 162
    move-result v8

    .line 163
    div-float/2addr v8, v5

    .line 164
    goto :goto_2

    .line 165
    :cond_1
    move v8, v7

    .line 166
    :goto_2
    cmpl-float v5, v8, v7

    .line 167
    .line 168
    if-nez v5, :cond_2

    .line 169
    .line 170
    goto/16 :goto_c

    .line 171
    .line 172
    :cond_2
    iget-object v5, v1, Lcb/m;->a:Landroid/graphics/Path;

    .line 173
    .line 174
    invoke-virtual {v5}, Landroid/graphics/Path;->reset()V

    .line 175
    .line 176
    .line 177
    iget-object v10, v0, Lcb/l;->a:[Ls5/d;

    .line 178
    .line 179
    if-eqz v10, :cond_3

    .line 180
    .line 181
    invoke-static {v10, v5}, Ls5/d;->b([Ls5/d;Landroid/graphics/Path;)V

    .line 182
    .line 183
    .line 184
    :cond_3
    iget-object v10, v1, Lcb/m;->b:Landroid/graphics/Path;

    .line 185
    .line 186
    invoke-virtual {v10}, Landroid/graphics/Path;->reset()V

    .line 187
    .line 188
    .line 189
    instance-of v11, v0, Lcb/h;

    .line 190
    .line 191
    if-eqz v11, :cond_5

    .line 192
    .line 193
    iget v0, v0, Lcb/l;->c:I

    .line 194
    .line 195
    if-nez v0, :cond_4

    .line 196
    .line 197
    sget-object v0, Landroid/graphics/Path$FillType;->WINDING:Landroid/graphics/Path$FillType;

    .line 198
    .line 199
    goto :goto_3

    .line 200
    :cond_4
    sget-object v0, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 201
    .line 202
    :goto_3
    invoke-virtual {v10, v0}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v10, v5, v12}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;Landroid/graphics/Matrix;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v3, v10}, Landroid/graphics/Canvas;->clipPath(Landroid/graphics/Path;)Z

    .line 209
    .line 210
    .line 211
    goto/16 :goto_c

    .line 212
    .line 213
    :cond_5
    check-cast v0, Lcb/i;

    .line 214
    .line 215
    iget v11, v0, Lcb/i;->i:F

    .line 216
    .line 217
    cmpl-float v13, v11, v7

    .line 218
    .line 219
    const/high16 v14, 0x3f800000    # 1.0f

    .line 220
    .line 221
    if-nez v13, :cond_6

    .line 222
    .line 223
    iget v13, v0, Lcb/i;->j:F

    .line 224
    .line 225
    cmpl-float v13, v13, v14

    .line 226
    .line 227
    if-eqz v13, :cond_9

    .line 228
    .line 229
    :cond_6
    iget v13, v0, Lcb/i;->k:F

    .line 230
    .line 231
    add-float/2addr v11, v13

    .line 232
    rem-float/2addr v11, v14

    .line 233
    iget v15, v0, Lcb/i;->j:F

    .line 234
    .line 235
    add-float/2addr v15, v13

    .line 236
    rem-float/2addr v15, v14

    .line 237
    iget-object v13, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 238
    .line 239
    if-nez v13, :cond_7

    .line 240
    .line 241
    new-instance v13, Landroid/graphics/PathMeasure;

    .line 242
    .line 243
    invoke-direct {v13}, Landroid/graphics/PathMeasure;-><init>()V

    .line 244
    .line 245
    .line 246
    iput-object v13, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 247
    .line 248
    :cond_7
    iget-object v13, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 249
    .line 250
    move/from16 v14, v17

    .line 251
    .line 252
    invoke-virtual {v13, v5, v14}, Landroid/graphics/PathMeasure;->setPath(Landroid/graphics/Path;Z)V

    .line 253
    .line 254
    .line 255
    iget-object v13, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 256
    .line 257
    invoke-virtual {v13}, Landroid/graphics/PathMeasure;->getLength()F

    .line 258
    .line 259
    .line 260
    move-result v13

    .line 261
    mul-float/2addr v11, v13

    .line 262
    mul-float/2addr v15, v13

    .line 263
    invoke-virtual {v5}, Landroid/graphics/Path;->reset()V

    .line 264
    .line 265
    .line 266
    cmpl-float v16, v11, v15

    .line 267
    .line 268
    if-lez v16, :cond_8

    .line 269
    .line 270
    iget-object v14, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 271
    .line 272
    move/from16 v7, p2

    .line 273
    .line 274
    invoke-virtual {v14, v11, v13, v5, v7}, Landroid/graphics/PathMeasure;->getSegment(FFLandroid/graphics/Path;Z)Z

    .line 275
    .line 276
    .line 277
    iget-object v11, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 278
    .line 279
    const/4 v13, 0x0

    .line 280
    invoke-virtual {v11, v13, v15, v5, v7}, Landroid/graphics/PathMeasure;->getSegment(FFLandroid/graphics/Path;Z)Z

    .line 281
    .line 282
    .line 283
    goto :goto_4

    .line 284
    :cond_8
    move v13, v7

    .line 285
    move/from16 v7, p2

    .line 286
    .line 287
    iget-object v14, v1, Lcb/m;->f:Landroid/graphics/PathMeasure;

    .line 288
    .line 289
    invoke-virtual {v14, v11, v15, v5, v7}, Landroid/graphics/PathMeasure;->getSegment(FFLandroid/graphics/Path;Z)Z

    .line 290
    .line 291
    .line 292
    :goto_4
    invoke-virtual {v5, v13, v13}, Landroid/graphics/Path;->rLineTo(FF)V

    .line 293
    .line 294
    .line 295
    :cond_9
    invoke-virtual {v10, v5, v12}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;Landroid/graphics/Matrix;)V

    .line 296
    .line 297
    .line 298
    iget-object v5, v0, Lcb/i;->f:Lbb/g0;

    .line 299
    .line 300
    iget-object v7, v5, Lbb/g0;->f:Ljava/lang/Object;

    .line 301
    .line 302
    check-cast v7, Landroid/graphics/Shader;

    .line 303
    .line 304
    const/4 v13, 0x0

    .line 305
    const/16 v14, 0xff

    .line 306
    .line 307
    const/high16 v15, 0x437f0000    # 255.0f

    .line 308
    .line 309
    if-eqz v7, :cond_a

    .line 310
    .line 311
    goto :goto_5

    .line 312
    :cond_a
    iget v7, v5, Lbb/g0;->e:I

    .line 313
    .line 314
    if-eqz v7, :cond_e

    .line 315
    .line 316
    :goto_5
    iget-object v7, v1, Lcb/m;->e:Landroid/graphics/Paint;

    .line 317
    .line 318
    if-nez v7, :cond_b

    .line 319
    .line 320
    new-instance v7, Landroid/graphics/Paint;

    .line 321
    .line 322
    const/4 v11, 0x1

    .line 323
    const v16, 0xffffff

    .line 324
    .line 325
    .line 326
    invoke-direct {v7, v11}, Landroid/graphics/Paint;-><init>(I)V

    .line 327
    .line 328
    .line 329
    iput-object v7, v1, Lcb/m;->e:Landroid/graphics/Paint;

    .line 330
    .line 331
    sget-object v11, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 332
    .line 333
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 334
    .line 335
    .line 336
    goto :goto_6

    .line 337
    :cond_b
    const v16, 0xffffff

    .line 338
    .line 339
    .line 340
    :goto_6
    iget-object v7, v1, Lcb/m;->e:Landroid/graphics/Paint;

    .line 341
    .line 342
    iget-object v11, v5, Lbb/g0;->f:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast v11, Landroid/graphics/Shader;

    .line 345
    .line 346
    if-eqz v11, :cond_c

    .line 347
    .line 348
    invoke-virtual {v11, v12}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 349
    .line 350
    .line 351
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 352
    .line 353
    .line 354
    iget v5, v0, Lcb/i;->h:F

    .line 355
    .line 356
    mul-float/2addr v5, v15

    .line 357
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    invoke-virtual {v7, v5}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 362
    .line 363
    .line 364
    move/from16 v19, v15

    .line 365
    .line 366
    goto :goto_7

    .line 367
    :cond_c
    invoke-virtual {v7, v13}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 368
    .line 369
    .line 370
    invoke-virtual {v7, v14}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 371
    .line 372
    .line 373
    iget v5, v5, Lbb/g0;->e:I

    .line 374
    .line 375
    iget v11, v0, Lcb/i;->h:F

    .line 376
    .line 377
    sget-object v19, Lcb/p;->m:Landroid/graphics/PorterDuff$Mode;

    .line 378
    .line 379
    move/from16 v19, v15

    .line 380
    .line 381
    invoke-static {v5}, Landroid/graphics/Color;->alpha(I)I

    .line 382
    .line 383
    .line 384
    move-result v15

    .line 385
    and-int v5, v5, v16

    .line 386
    .line 387
    int-to-float v15, v15

    .line 388
    mul-float/2addr v15, v11

    .line 389
    float-to-int v11, v15

    .line 390
    shl-int/lit8 v11, v11, 0x18

    .line 391
    .line 392
    or-int/2addr v5, v11

    .line 393
    invoke-virtual {v7, v5}, Landroid/graphics/Paint;->setColor(I)V

    .line 394
    .line 395
    .line 396
    :goto_7
    invoke-virtual {v7, v13}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 397
    .line 398
    .line 399
    iget v5, v0, Lcb/l;->c:I

    .line 400
    .line 401
    if-nez v5, :cond_d

    .line 402
    .line 403
    sget-object v5, Landroid/graphics/Path$FillType;->WINDING:Landroid/graphics/Path$FillType;

    .line 404
    .line 405
    goto :goto_8

    .line 406
    :cond_d
    sget-object v5, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    .line 407
    .line 408
    :goto_8
    invoke-virtual {v10, v5}, Landroid/graphics/Path;->setFillType(Landroid/graphics/Path$FillType;)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {v3, v10, v7}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 412
    .line 413
    .line 414
    goto :goto_9

    .line 415
    :cond_e
    move/from16 v19, v15

    .line 416
    .line 417
    const v16, 0xffffff

    .line 418
    .line 419
    .line 420
    :goto_9
    iget-object v5, v0, Lcb/i;->d:Lbb/g0;

    .line 421
    .line 422
    iget-object v7, v5, Lbb/g0;->f:Ljava/lang/Object;

    .line 423
    .line 424
    check-cast v7, Landroid/graphics/Shader;

    .line 425
    .line 426
    if-eqz v7, :cond_f

    .line 427
    .line 428
    goto :goto_a

    .line 429
    :cond_f
    iget v7, v5, Lbb/g0;->e:I

    .line 430
    .line 431
    if-eqz v7, :cond_15

    .line 432
    .line 433
    :goto_a
    iget-object v7, v1, Lcb/m;->d:Landroid/graphics/Paint;

    .line 434
    .line 435
    if-nez v7, :cond_10

    .line 436
    .line 437
    new-instance v7, Landroid/graphics/Paint;

    .line 438
    .line 439
    const/4 v11, 0x1

    .line 440
    invoke-direct {v7, v11}, Landroid/graphics/Paint;-><init>(I)V

    .line 441
    .line 442
    .line 443
    iput-object v7, v1, Lcb/m;->d:Landroid/graphics/Paint;

    .line 444
    .line 445
    sget-object v11, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 446
    .line 447
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 448
    .line 449
    .line 450
    :cond_10
    iget-object v7, v1, Lcb/m;->d:Landroid/graphics/Paint;

    .line 451
    .line 452
    iget-object v11, v0, Lcb/i;->m:Landroid/graphics/Paint$Join;

    .line 453
    .line 454
    if-eqz v11, :cond_11

    .line 455
    .line 456
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setStrokeJoin(Landroid/graphics/Paint$Join;)V

    .line 457
    .line 458
    .line 459
    :cond_11
    iget-object v11, v0, Lcb/i;->l:Landroid/graphics/Paint$Cap;

    .line 460
    .line 461
    if-eqz v11, :cond_12

    .line 462
    .line 463
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setStrokeCap(Landroid/graphics/Paint$Cap;)V

    .line 464
    .line 465
    .line 466
    :cond_12
    iget v11, v0, Lcb/i;->n:F

    .line 467
    .line 468
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setStrokeMiter(F)V

    .line 469
    .line 470
    .line 471
    iget-object v11, v5, Lbb/g0;->f:Ljava/lang/Object;

    .line 472
    .line 473
    check-cast v11, Landroid/graphics/Shader;

    .line 474
    .line 475
    if-eqz v11, :cond_13

    .line 476
    .line 477
    invoke-virtual {v11, v12}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 478
    .line 479
    .line 480
    invoke-virtual {v7, v11}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 481
    .line 482
    .line 483
    iget v5, v0, Lcb/i;->g:F

    .line 484
    .line 485
    mul-float v5, v5, v19

    .line 486
    .line 487
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 488
    .line 489
    .line 490
    move-result v5

    .line 491
    invoke-virtual {v7, v5}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 492
    .line 493
    .line 494
    goto :goto_b

    .line 495
    :cond_13
    invoke-virtual {v7, v13}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 496
    .line 497
    .line 498
    invoke-virtual {v7, v14}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 499
    .line 500
    .line 501
    iget v5, v5, Lbb/g0;->e:I

    .line 502
    .line 503
    iget v11, v0, Lcb/i;->g:F

    .line 504
    .line 505
    sget-object v12, Lcb/p;->m:Landroid/graphics/PorterDuff$Mode;

    .line 506
    .line 507
    invoke-static {v5}, Landroid/graphics/Color;->alpha(I)I

    .line 508
    .line 509
    .line 510
    move-result v12

    .line 511
    and-int v5, v5, v16

    .line 512
    .line 513
    int-to-float v12, v12

    .line 514
    mul-float/2addr v12, v11

    .line 515
    float-to-int v11, v12

    .line 516
    shl-int/lit8 v11, v11, 0x18

    .line 517
    .line 518
    or-int/2addr v5, v11

    .line 519
    invoke-virtual {v7, v5}, Landroid/graphics/Paint;->setColor(I)V

    .line 520
    .line 521
    .line 522
    :goto_b
    invoke-virtual {v7, v13}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 523
    .line 524
    .line 525
    mul-float v11, p1, v8

    .line 526
    .line 527
    iget v0, v0, Lcb/i;->e:F

    .line 528
    .line 529
    mul-float/2addr v0, v11

    .line 530
    invoke-virtual {v7, v0}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 531
    .line 532
    .line 533
    invoke-virtual {v3, v10, v7}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 534
    .line 535
    .line 536
    goto :goto_c

    .line 537
    :cond_14
    move/from16 v4, p4

    .line 538
    .line 539
    goto/16 :goto_1

    .line 540
    .line 541
    :cond_15
    :goto_c
    add-int/lit8 v8, v18, 0x1

    .line 542
    .line 543
    const/4 v7, 0x0

    .line 544
    goto/16 :goto_0

    .line 545
    .line 546
    :cond_16
    move-object/from16 v3, p3

    .line 547
    .line 548
    invoke-virtual {v3}, Landroid/graphics/Canvas;->restore()V

    .line 549
    .line 550
    .line 551
    return-void

    .line 552
    nop

    .line 553
    :array_0
    .array-data 4
        0x0
        0x3f800000    # 1.0f
        0x3f800000    # 1.0f
        0x0
    .end array-data
.end method

.method public getAlpha()F
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcb/m;->getRootAlpha()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    int-to-float p0, p0

    .line 6
    const/high16 v0, 0x437f0000    # 255.0f

    .line 7
    .line 8
    div-float/2addr p0, v0

    .line 9
    return p0
.end method

.method public getRootAlpha()I
    .locals 0

    .line 1
    iget p0, p0, Lcb/m;->l:I

    .line 2
    .line 3
    return p0
.end method

.method public setAlpha(F)V
    .locals 1

    .line 1
    const/high16 v0, 0x437f0000    # 255.0f

    .line 2
    .line 3
    mul-float/2addr p1, v0

    .line 4
    float-to-int p1, p1

    .line 5
    invoke-virtual {p0, p1}, Lcb/m;->setRootAlpha(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setRootAlpha(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcb/m;->l:I

    .line 2
    .line 3
    return-void
.end method
