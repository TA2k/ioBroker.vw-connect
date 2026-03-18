.class public final Llw/q;
.super Llw/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Llw/e;

.field public final j:Llw/n;

.field public final k:Llw/p;

.field public final l:Llw/k;

.field public m:Ljava/lang/Float;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Llw/e;Lqw/a;Lqw/e;Llw/n;Llw/p;Lmw/e;Lqw/a;Lqw/a;Llw/k;Llw/h;)V
    .locals 7

    .line 1
    move-object v0, p0

    .line 2
    move-object v1, p2

    .line 3
    move-object v2, p3

    .line 4
    move-object v3, p6

    .line 5
    move-object v4, p7

    .line 6
    move-object v5, p8

    .line 7
    move-object/from16 v6, p10

    .line 8
    .line 9
    invoke-direct/range {v0 .. v6}, Llw/i;-><init>(Lqw/a;Lqw/e;Lmw/e;Lqw/a;Lqw/a;Llw/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Llw/q;->i:Llw/e;

    .line 13
    .line 14
    iput-object p4, p0, Llw/q;->j:Llw/n;

    .line 15
    .line 16
    iput-object p5, p0, Llw/q;->k:Llw/p;

    .line 17
    .line 18
    move-object/from16 p1, p9

    .line 19
    .line 20
    iput-object p1, p0, Llw/q;->l:Llw/k;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V
    .locals 3

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    const-string v0, "horizontalDimensions"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p2, "model"

    .line 9
    .line 10
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string p2, "insets"

    .line 14
    .line 15
    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, p1}, Llw/q;->q(Lkw/g;)F

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    invoke-virtual {p0, p1}, Llw/i;->f(Lpw/f;)F

    .line 23
    .line 24
    .line 25
    move-result p3

    .line 26
    invoke-virtual {p0, p1}, Llw/i;->i(Lkw/g;)F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-static {p3, p1}, Ljava/lang/Math;->max(FF)F

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    iget-object p3, p0, Llw/q;->l:Llw/k;

    .line 35
    .line 36
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const-string p3, "verticalLabelPosition"

    .line 40
    .line 41
    iget-object p0, p0, Llw/q;->k:Llw/p;

    .line 42
    .line 43
    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    sget-object p3, Llw/p;->f:Llw/p;

    .line 47
    .line 48
    const/4 v0, 0x2

    .line 49
    if-ne p0, p3, :cond_0

    .line 50
    .line 51
    int-to-float v1, v0

    .line 52
    div-float v1, p1, v1

    .line 53
    .line 54
    add-float/2addr v1, p2

    .line 55
    goto :goto_0

    .line 56
    :cond_0
    sget-object v1, Llw/p;->e:Llw/p;

    .line 57
    .line 58
    if-ne p0, v1, :cond_1

    .line 59
    .line 60
    invoke-static {p2, p1}, Ljava/lang/Math;->max(FF)F

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    add-float/2addr v1, p1

    .line 65
    int-to-float v2, v0

    .line 66
    div-float/2addr v1, v2

    .line 67
    goto :goto_0

    .line 68
    :cond_1
    move v1, p1

    .line 69
    :goto_0
    if-ne p0, p3, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    sget-object p3, Llw/p;->e:Llw/p;

    .line 73
    .line 74
    if-ne p0, p3, :cond_3

    .line 75
    .line 76
    invoke-static {p2, p1}, Ljava/lang/Math;->max(FF)F

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    add-float/2addr p0, p1

    .line 81
    int-to-float p1, v0

    .line 82
    div-float p1, p0, p1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_3
    int-to-float p0, v0

    .line 86
    div-float/2addr p1, p0

    .line 87
    add-float/2addr p1, p2

    .line 88
    :goto_1
    const/4 p0, 0x5

    .line 89
    invoke-static {p4, v1, p1, p0}, Ld3/a;->a(Ld3/a;FFI)V

    .line 90
    .line 91
    .line 92
    return-void
.end method

.method public final bridge synthetic b(Lkw/g;FLjava/lang/Object;Ld3/a;)V
    .locals 0

    .line 1
    check-cast p3, Lmw/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3, p4}, Llw/q;->n(Lkw/g;FLmw/a;Ld3/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Lc1/h2;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    iget-object v1, v2, Lc1/h2;->b:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lkw/g;

    .line 8
    .line 9
    iget-object v12, v0, Llw/i;->h:Landroid/graphics/RectF;

    .line 10
    .line 11
    invoke-virtual {v12}, Landroid/graphics/RectF;->height()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-virtual/range {p0 .. p1}, Llw/q;->q(Lkw/g;)F

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    iget-object v5, v0, Llw/q;->l:Llw/k;

    .line 20
    .line 21
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const-string v6, "position"

    .line 25
    .line 26
    iget-object v13, v0, Llw/q;->i:Llw/e;

    .line 27
    .line 28
    invoke-static {v13, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v5, v2, v3, v4, v13}, Llw/k;->b(Lkw/g;FFLlw/e;)Ljava/util/ArrayList;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-static {v13, v2}, Lnv/c;->a(Llw/e;Lc1/h2;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-eqz v4, :cond_0

    .line 40
    .line 41
    iget v5, v12, Landroid/graphics/RectF;->right:F

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    iget v5, v12, Landroid/graphics/RectF;->left:F

    .line 45
    .line 46
    :goto_0
    iget-object v14, v0, Llw/q;->j:Llw/n;

    .line 47
    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    sget-object v6, Llw/n;->d:Llw/n;

    .line 51
    .line 52
    if-ne v14, v6, :cond_1

    .line 53
    .line 54
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    sub-float/2addr v5, v4

    .line 59
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    :goto_1
    sub-float/2addr v5, v4

    .line 64
    :goto_2
    move v15, v5

    .line 65
    goto :goto_3

    .line 66
    :cond_1
    if-eqz v4, :cond_2

    .line 67
    .line 68
    sget-object v4, Llw/n;->e:Llw/n;

    .line 69
    .line 70
    if-ne v14, v4, :cond_2

    .line 71
    .line 72
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    goto :goto_1

    .line 77
    :cond_2
    sget-object v4, Llw/n;->d:Llw/n;

    .line 78
    .line 79
    if-ne v14, v4, :cond_3

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    sget-object v4, Llw/n;->e:Llw/n;

    .line 83
    .line 84
    if-ne v14, v4, :cond_b

    .line 85
    .line 86
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    goto :goto_1

    .line 91
    :goto_3
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    add-float/2addr v4, v15

    .line 96
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    add-float v10, v5, v4

    .line 101
    .line 102
    invoke-virtual {v0}, Llw/q;->o()Z

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    invoke-interface {v1}, Lpw/f;->e()Z

    .line 107
    .line 108
    .line 109
    move-result v5

    .line 110
    if-ne v4, v5, :cond_4

    .line 111
    .line 112
    move v11, v15

    .line 113
    goto :goto_4

    .line 114
    :cond_4
    move v11, v10

    .line 115
    :goto_4
    invoke-interface {v1}, Lkw/g;->j()Lmw/b;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    invoke-interface {v1, v13}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 124
    .line 125
    .line 126
    move-result-object v16

    .line 127
    :goto_5
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->hasNext()Z

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    if-eqz v3, :cond_a

    .line 132
    .line 133
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    check-cast v3, Ljava/lang/Number;

    .line 138
    .line 139
    invoke-virtual {v3}, Ljava/lang/Number;->doubleValue()D

    .line 140
    .line 141
    .line 142
    move-result-wide v3

    .line 143
    iget v5, v12, Landroid/graphics/RectF;->bottom:F

    .line 144
    .line 145
    invoke-virtual {v12}, Landroid/graphics/RectF;->height()F

    .line 146
    .line 147
    .line 148
    move-result v6

    .line 149
    iget-wide v7, v1, Lmw/k;->a:D

    .line 150
    .line 151
    sub-double v7, v3, v7

    .line 152
    .line 153
    invoke-virtual {v1}, Lmw/k;->a()D

    .line 154
    .line 155
    .line 156
    move-result-wide v17

    .line 157
    div-double v7, v7, v17

    .line 158
    .line 159
    double-to-float v7, v7

    .line 160
    mul-float/2addr v6, v7

    .line 161
    sub-float/2addr v5, v6

    .line 162
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    invoke-virtual {v0, v2, v6, v3, v4}, Llw/q;->p(Lc1/h2;FD)F

    .line 167
    .line 168
    .line 169
    move-result v6

    .line 170
    add-float/2addr v5, v6

    .line 171
    iget-object v6, v0, Llw/i;->d:Lqw/a;

    .line 172
    .line 173
    if-eqz v6, :cond_5

    .line 174
    .line 175
    invoke-static {v6, v2, v15, v10, v5}, Lqw/a;->b(Lqw/a;Lc1/h2;FFF)V

    .line 176
    .line 177
    .line 178
    :cond_5
    iget-object v6, v0, Llw/i;->c:Lmw/e;

    .line 179
    .line 180
    invoke-static {v6, v2, v3, v4, v13}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    const/4 v8, 0x0

    .line 185
    const/16 v9, 0xbc

    .line 186
    .line 187
    move-object v4, v1

    .line 188
    iget-object v1, v0, Llw/i;->b:Lqw/e;

    .line 189
    .line 190
    move-object v6, v4

    .line 191
    const/4 v4, 0x0

    .line 192
    move v7, v5

    .line 193
    const/4 v5, 0x0

    .line 194
    move-object/from16 v17, v6

    .line 195
    .line 196
    const/4 v6, 0x0

    .line 197
    move/from16 v18, v7

    .line 198
    .line 199
    const/4 v7, 0x0

    .line 200
    invoke-static/range {v1 .. v9}, Lqw/e;->b(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IILandroid/graphics/RectF;FZI)Landroid/graphics/RectF;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    invoke-virtual {v4}, Landroid/graphics/RectF;->centerY()F

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    sub-float v5, v18, v5

    .line 209
    .line 210
    invoke-static {v4, v11, v5}, Ljp/ae;->d(Landroid/graphics/RectF;FF)V

    .line 211
    .line 212
    .line 213
    sget-object v5, Llw/n;->d:Llw/n;

    .line 214
    .line 215
    if-eq v14, v5, :cond_7

    .line 216
    .line 217
    iget v5, v4, Landroid/graphics/RectF;->left:F

    .line 218
    .line 219
    iget v6, v4, Landroid/graphics/RectF;->top:F

    .line 220
    .line 221
    iget v7, v4, Landroid/graphics/RectF;->right:F

    .line 222
    .line 223
    iget v4, v4, Landroid/graphics/RectF;->bottom:F

    .line 224
    .line 225
    invoke-virtual {v0, v5, v6, v7, v4}, Llw/i;->j(FFFF)Z

    .line 226
    .line 227
    .line 228
    move-result v4

    .line 229
    if-eqz v4, :cond_6

    .line 230
    .line 231
    goto :goto_6

    .line 232
    :cond_6
    move/from16 v18, v10

    .line 233
    .line 234
    move v4, v11

    .line 235
    goto :goto_a

    .line 236
    :cond_7
    :goto_6
    invoke-virtual {v0}, Llw/q;->o()Z

    .line 237
    .line 238
    .line 239
    move-result v4

    .line 240
    if-eqz v4, :cond_8

    .line 241
    .line 242
    sget-object v4, Lpw/e;->d:Lpw/e;

    .line 243
    .line 244
    :goto_7
    move-object v6, v4

    .line 245
    goto :goto_8

    .line 246
    :cond_8
    sget-object v4, Lpw/e;->f:Lpw/e;

    .line 247
    .line 248
    goto :goto_7

    .line 249
    :goto_8
    iget-object v4, v0, Llw/q;->k:Llw/p;

    .line 250
    .line 251
    iget-object v7, v4, Llw/p;->d:Lpw/i;

    .line 252
    .line 253
    iget-object v4, v0, Llw/q;->m:Ljava/lang/Float;

    .line 254
    .line 255
    if-eqz v4, :cond_9

    .line 256
    .line 257
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    goto :goto_9

    .line 262
    :cond_9
    iget-object v4, v2, Lc1/h2;->c:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v4, Landroid/graphics/RectF;

    .line 265
    .line 266
    invoke-virtual {v4}, Landroid/graphics/RectF;->width()F

    .line 267
    .line 268
    .line 269
    move-result v4

    .line 270
    const/4 v5, 0x2

    .line 271
    int-to-float v5, v5

    .line 272
    div-float/2addr v4, v5

    .line 273
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 274
    .line 275
    .line 276
    move-result v5

    .line 277
    sub-float/2addr v4, v5

    .line 278
    :goto_9
    float-to-int v8, v4

    .line 279
    const/4 v9, 0x0

    .line 280
    move v4, v11

    .line 281
    const/16 v11, 0x80

    .line 282
    .line 283
    move v5, v10

    .line 284
    const/4 v10, 0x0

    .line 285
    move/from16 v19, v18

    .line 286
    .line 287
    move/from16 v18, v5

    .line 288
    .line 289
    move/from16 v5, v19

    .line 290
    .line 291
    invoke-static/range {v1 .. v11}, Lqw/e;->a(Lqw/e;Lc1/h2;Ljava/lang/CharSequence;FFLpw/e;Lpw/i;IIFI)V

    .line 292
    .line 293
    .line 294
    :goto_a
    move-object/from16 v2, p1

    .line 295
    .line 296
    move v11, v4

    .line 297
    move-object/from16 v1, v17

    .line 298
    .line 299
    move/from16 v10, v18

    .line 300
    .line 301
    goto/16 :goto_5

    .line 302
    .line 303
    :cond_a
    return-void

    .line 304
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 305
    .line 306
    const-string v1, "Unexpected combination of axis position and label position"

    .line 307
    .line 308
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    throw v0
.end method

.method public final d(Lc1/h2;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lc1/h2;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Landroid/graphics/RectF;

    .line 8
    .line 9
    iget-object v3, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Lkw/g;

    .line 12
    .line 13
    invoke-interface {v3}, Lkw/g;->j()Lmw/b;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iget-object v4, v0, Llw/q;->i:Llw/e;

    .line 18
    .line 19
    invoke-interface {v3, v4}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual/range {p0 .. p1}, Llw/q;->q(Lkw/g;)F

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    iget-object v6, v0, Llw/i;->h:Landroid/graphics/RectF;

    .line 28
    .line 29
    invoke-virtual {v6}, Landroid/graphics/RectF;->height()F

    .line 30
    .line 31
    .line 32
    iget-object v7, v0, Llw/q;->l:Llw/k;

    .line 33
    .line 34
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    const-string v8, "position"

    .line 38
    .line 39
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v6}, Landroid/graphics/RectF;->height()F

    .line 43
    .line 44
    .line 45
    move-result v8

    .line 46
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v7, v1, v8, v5, v4}, Llw/k;->b(Lkw/g;FFLlw/e;)Ljava/util/ArrayList;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    :cond_0
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    const/4 v9, 0x2

    .line 62
    if-eqz v8, :cond_2

    .line 63
    .line 64
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    check-cast v8, Ljava/lang/Number;

    .line 69
    .line 70
    invoke-virtual {v8}, Ljava/lang/Number;->doubleValue()D

    .line 71
    .line 72
    .line 73
    move-result-wide v10

    .line 74
    iget v8, v6, Landroid/graphics/RectF;->bottom:F

    .line 75
    .line 76
    invoke-virtual {v6}, Landroid/graphics/RectF;->height()F

    .line 77
    .line 78
    .line 79
    move-result v12

    .line 80
    iget-wide v13, v3, Lmw/k;->a:D

    .line 81
    .line 82
    sub-double v13, v10, v13

    .line 83
    .line 84
    invoke-virtual {v3}, Lmw/k;->a()D

    .line 85
    .line 86
    .line 87
    move-result-wide v15

    .line 88
    div-double/2addr v13, v15

    .line 89
    double-to-float v13, v13

    .line 90
    mul-float/2addr v12, v13

    .line 91
    sub-float/2addr v8, v12

    .line 92
    invoke-virtual/range {p0 .. p1}, Llw/i;->e(Lc1/h2;)F

    .line 93
    .line 94
    .line 95
    move-result v12

    .line 96
    invoke-virtual {v0, v1, v12, v10, v11}, Llw/q;->p(Lc1/h2;FD)F

    .line 97
    .line 98
    .line 99
    move-result v10

    .line 100
    add-float/2addr v10, v8

    .line 101
    iget-object v8, v0, Llw/i;->e:Lqw/a;

    .line 102
    .line 103
    if-eqz v8, :cond_0

    .line 104
    .line 105
    iget v11, v2, Landroid/graphics/RectF;->left:F

    .line 106
    .line 107
    invoke-virtual/range {p0 .. p1}, Llw/i;->e(Lc1/h2;)F

    .line 108
    .line 109
    .line 110
    move-result v12

    .line 111
    int-to-float v9, v9

    .line 112
    div-float/2addr v12, v9

    .line 113
    sub-float v12, v10, v12

    .line 114
    .line 115
    iget v13, v2, Landroid/graphics/RectF;->right:F

    .line 116
    .line 117
    invoke-virtual/range {p0 .. p1}, Llw/i;->e(Lc1/h2;)F

    .line 118
    .line 119
    .line 120
    move-result v14

    .line 121
    div-float/2addr v14, v9

    .line 122
    add-float/2addr v14, v10

    .line 123
    invoke-virtual {v0, v11, v12, v13, v14}, Llw/i;->j(FFFF)Z

    .line 124
    .line 125
    .line 126
    move-result v9

    .line 127
    if-eqz v9, :cond_1

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_1
    const/4 v8, 0x0

    .line 131
    :goto_1
    if-eqz v8, :cond_0

    .line 132
    .line 133
    iget v9, v2, Landroid/graphics/RectF;->left:F

    .line 134
    .line 135
    iget v11, v2, Landroid/graphics/RectF;->right:F

    .line 136
    .line 137
    invoke-static {v8, v1, v9, v11, v10}, Lqw/a;->b(Lqw/a;Lc1/h2;FFF)V

    .line 138
    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_2
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    invoke-virtual/range {p0 .. p1}, Llw/i;->i(Lkw/g;)F

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    iget-object v3, v0, Llw/i;->a:Lqw/a;

    .line 149
    .line 150
    if-eqz v3, :cond_4

    .line 151
    .line 152
    iget v5, v6, Landroid/graphics/RectF;->top:F

    .line 153
    .line 154
    sub-float/2addr v5, v2

    .line 155
    iget v7, v6, Landroid/graphics/RectF;->bottom:F

    .line 156
    .line 157
    add-float/2addr v7, v2

    .line 158
    invoke-static {v4, v1}, Lnv/c;->a(Llw/e;Lc1/h2;)Z

    .line 159
    .line 160
    .line 161
    move-result v2

    .line 162
    if-eqz v2, :cond_3

    .line 163
    .line 164
    iget v2, v6, Landroid/graphics/RectF;->right:F

    .line 165
    .line 166
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    int-to-float v4, v9

    .line 171
    div-float/2addr v0, v4

    .line 172
    sub-float/2addr v2, v0

    .line 173
    goto :goto_2

    .line 174
    :cond_3
    iget v2, v6, Landroid/graphics/RectF;->left:F

    .line 175
    .line 176
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    int-to-float v4, v9

    .line 181
    div-float/2addr v0, v4

    .line 182
    add-float/2addr v2, v0

    .line 183
    :goto_2
    invoke-static {v3, v1, v5, v7, v2}, Lqw/a;->c(Lqw/a;Lc1/h2;FFF)V

    .line 184
    .line 185
    .line 186
    :cond_4
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    invoke-super {p0, p1}, Llw/i;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    instance-of v0, p1, Llw/q;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast p1, Llw/q;

    .line 12
    .line 13
    iget-object v0, p1, Llw/q;->j:Llw/n;

    .line 14
    .line 15
    iget-object v1, p0, Llw/q;->j:Llw/n;

    .line 16
    .line 17
    if-ne v1, v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Llw/q;->k:Llw/p;

    .line 20
    .line 21
    iget-object v1, p1, Llw/q;->k:Llw/p;

    .line 22
    .line 23
    if-ne v0, v1, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Llw/q;->l:Llw/k;

    .line 26
    .line 27
    iget-object p1, p1, Llw/q;->l:Llw/k;

    .line 28
    .line 29
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eqz p0, :cond_0

    .line 34
    .line 35
    const/4 p0, 0x1

    .line 36
    return p0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method public final g()Llw/f;
    .locals 0

    .line 1
    iget-object p0, p0, Llw/q;->i:Llw/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    invoke-super {p0}, Llw/i;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    mul-int/lit8 v0, v0, 0x1f

    .line 6
    .line 7
    iget-object v1, p0, Llw/q;->j:Llw/n;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, v0

    .line 14
    mul-int/lit8 v1, v1, 0x1f

    .line 15
    .line 16
    iget-object v0, p0, Llw/q;->k:Llw/p;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    add-int/2addr v0, v1

    .line 23
    mul-int/lit8 v0, v0, 0x1f

    .line 24
    .line 25
    iget-object p0, p0, Llw/q;->l:Llw/k;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    add-int/2addr p0, v0

    .line 32
    return p0
.end method

.method public final m(Lkw/g;Lkw/i;)V
    .locals 0

    .line 1
    const-string p0, "horizontalDimensions"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final n(Lkw/g;FLmw/a;Ld3/a;)V
    .locals 14

    .line 1
    move-object/from16 v6, p4

    .line 2
    .line 3
    const-string v0, "model"

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "insets"

    .line 11
    .line 12
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object v7, p0, Llw/i;->f:Llw/h;

    .line 16
    .line 17
    instance-of v0, v7, Llw/h;

    .line 18
    .line 19
    if-eqz v0, :cond_7

    .line 20
    .line 21
    iget-object v0, p0, Llw/q;->j:Llw/n;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    iget-object v8, p0, Llw/q;->i:Llw/e;

    .line 28
    .line 29
    const/4 v9, 0x1

    .line 30
    const/4 v10, 0x0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    if-ne v0, v9, :cond_0

    .line 34
    .line 35
    move v2, v10

    .line 36
    goto/16 :goto_3

    .line 37
    .line 38
    :cond_0
    new-instance p0, La8/r0;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-virtual/range {p0 .. p1}, Llw/q;->q(Lkw/g;)F

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-object v2, p0, Llw/q;->l:Llw/k;

    .line 49
    .line 50
    move/from16 v3, p2

    .line 51
    .line 52
    invoke-virtual {v2, p1, v3, v0, v8}, Llw/k;->b(Lkw/g;FFLlw/e;)Ljava/util/ArrayList;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object v11

    .line 60
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_2

    .line 65
    .line 66
    const/4 v0, 0x0

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    check-cast v0, Ljava/lang/Number;

    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 75
    .line 76
    .line 77
    move-result-wide v2

    .line 78
    iget-object v12, p0, Llw/i;->c:Lmw/e;

    .line 79
    .line 80
    invoke-static {v12, p1, v2, v3, v8}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    const/4 v4, 0x0

    .line 85
    const/16 v5, 0x2c

    .line 86
    .line 87
    iget-object v0, p0, Llw/i;->b:Lqw/e;

    .line 88
    .line 89
    const/4 v3, 0x0

    .line 90
    move-object v1, p1

    .line 91
    invoke-static/range {v0 .. v5}, Lqw/e;->f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    move v13, v2

    .line 96
    :goto_0
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    if-eqz v2, :cond_3

    .line 101
    .line 102
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    check-cast v2, Ljava/lang/Number;

    .line 107
    .line 108
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 109
    .line 110
    .line 111
    move-result-wide v2

    .line 112
    invoke-static {v12, p1, v2, v3, v8}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    const/4 v4, 0x0

    .line 117
    const/16 v5, 0x2c

    .line 118
    .line 119
    const/4 v3, 0x0

    .line 120
    move-object v1, p1

    .line 121
    invoke-static/range {v0 .. v5}, Lqw/e;->f(Lqw/e;Lkw/g;Ljava/lang/CharSequence;IFI)F

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    invoke-static {v13, v2}, Ljava/lang/Math;->max(FF)F

    .line 126
    .line 127
    .line 128
    move-result v13

    .line 129
    goto :goto_0

    .line 130
    :cond_3
    invoke-static {v13}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    :goto_1
    if-eqz v0, :cond_4

    .line 135
    .line 136
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    goto :goto_2

    .line 141
    :cond_4
    move v0, v10

    .line 142
    :goto_2
    float-to-double v2, v0

    .line 143
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 144
    .line 145
    .line 146
    move-result-wide v2

    .line 147
    double-to-float v0, v2

    .line 148
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    iput-object v2, p0, Llw/q;->m:Ljava/lang/Float;

    .line 153
    .line 154
    invoke-virtual/range {p0 .. p1}, Llw/i;->h(Lkw/g;)F

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    add-float/2addr v2, v0

    .line 159
    :goto_3
    add-float/2addr v2, v10

    .line 160
    invoke-virtual/range {p0 .. p1}, Llw/i;->f(Lpw/f;)F

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    add-float/2addr p0, v2

    .line 165
    iget v0, v7, Llw/h;->a:F

    .line 166
    .line 167
    invoke-interface {p1, v0}, Lpw/f;->c(F)F

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    const v2, 0x7f7fffff    # Float.MAX_VALUE

    .line 172
    .line 173
    .line 174
    invoke-interface {p1, v2}, Lpw/f;->c(F)F

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    invoke-static {p0, v0, v1}, Lkp/r9;->d(FFF)F

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    sget-object v0, Llw/d;->a:Llw/d;

    .line 183
    .line 184
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    if-eqz v0, :cond_5

    .line 189
    .line 190
    const/4 v0, 0x2

    .line 191
    invoke-static {v6, p0, v10, v0}, Ljp/yd;->a(Ld3/a;FFI)V

    .line 192
    .line 193
    .line 194
    return-void

    .line 195
    :cond_5
    sget-object v0, Llw/c;->a:Llw/c;

    .line 196
    .line 197
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    if-eqz v0, :cond_6

    .line 202
    .line 203
    invoke-static {v6, v10, p0, v9}, Ljp/yd;->a(Ld3/a;FFI)V

    .line 204
    .line 205
    .line 206
    :cond_6
    return-void

    .line 207
    :cond_7
    new-instance p0, La8/r0;

    .line 208
    .line 209
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 210
    .line 211
    .line 212
    throw p0
.end method

.method public final o()Z
    .locals 2

    .line 1
    sget-object v0, Llw/d;->a:Llw/d;

    .line 2
    .line 3
    iget-object v1, p0, Llw/q;->i:Llw/e;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object p0, p0, Llw/q;->j:Llw/n;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    sget-object v0, Llw/n;->d:Llw/n;

    .line 14
    .line 15
    if-eq p0, v0, :cond_1

    .line 16
    .line 17
    :cond_0
    sget-object v0, Llw/c;->a:Llw/c;

    .line 18
    .line 19
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    sget-object v0, Llw/n;->e:Llw/n;

    .line 26
    .line 27
    if-ne p0, v0, :cond_2

    .line 28
    .line 29
    :cond_1
    const/4 p0, 0x1

    .line 30
    return p0

    .line 31
    :cond_2
    const/4 p0, 0x0

    .line 32
    return p0
.end method

.method public final p(Lc1/h2;FD)F
    .locals 2

    .line 1
    iget-object p1, p1, Lc1/h2;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lkw/g;

    .line 4
    .line 5
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object v0, p0, Llw/q;->i:Llw/e;

    .line 10
    .line 11
    invoke-interface {p1, v0}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-wide v0, p1, Lmw/k;->b:D

    .line 16
    .line 17
    cmpg-double p1, p3, v0

    .line 18
    .line 19
    const/4 p3, 0x2

    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    iget-object p0, p0, Llw/q;->l:Llw/k;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    int-to-float p0, p3

    .line 28
    div-float/2addr p2, p0

    .line 29
    neg-float p0, p2

    .line 30
    return p0

    .line 31
    :cond_0
    int-to-float p0, p3

    .line 32
    div-float/2addr p2, p0

    .line 33
    return p2
.end method

.method public final q(Lkw/g;)F
    .locals 10

    .line 1
    iget-object v2, p0, Llw/q;->l:Llw/k;

    .line 2
    .line 3
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v2, "position"

    .line 7
    .line 8
    iget-object v6, p0, Llw/q;->i:Llw/e;

    .line 9
    .line 10
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p1}, Lkw/g;->j()Lmw/b;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-interface {v2, v6}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    iget-wide v3, v2, Lmw/k;->a:D

    .line 22
    .line 23
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    iget-wide v4, v2, Lmw/k;->a:D

    .line 28
    .line 29
    iget-wide v7, v2, Lmw/k;->b:D

    .line 30
    .line 31
    add-double/2addr v4, v7

    .line 32
    const/4 v7, 0x2

    .line 33
    int-to-double v7, v7

    .line 34
    div-double/2addr v4, v7

    .line 35
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    iget-wide v7, v2, Lmw/k;->b:D

    .line 40
    .line 41
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    filled-new-array {v3, v4, v2}, [Ljava/lang/Double;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    check-cast v2, Ljava/lang/Iterable;

    .line 54
    .line 55
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v7

    .line 59
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-nez v2, :cond_0

    .line 64
    .line 65
    const/4 v0, 0x0

    .line 66
    goto :goto_1

    .line 67
    :cond_0
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    check-cast v2, Ljava/lang/Number;

    .line 72
    .line 73
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 74
    .line 75
    .line 76
    move-result-wide v2

    .line 77
    iget-object v8, p0, Llw/i;->c:Lmw/e;

    .line 78
    .line 79
    invoke-static {v8, p1, v2, v3, v6}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    const/4 v4, 0x0

    .line 84
    const/16 v5, 0x2c

    .line 85
    .line 86
    iget-object v0, p0, Llw/i;->b:Lqw/e;

    .line 87
    .line 88
    const/4 v3, 0x0

    .line 89
    move-object v1, p1

    .line 90
    invoke-static/range {v0 .. v5}, Lqw/e;->c(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IFI)F

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    move v9, v2

    .line 95
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    if-eqz v2, :cond_1

    .line 100
    .line 101
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Ljava/lang/Number;

    .line 106
    .line 107
    invoke-virtual {v2}, Ljava/lang/Number;->doubleValue()D

    .line 108
    .line 109
    .line 110
    move-result-wide v2

    .line 111
    invoke-static {v8, p1, v2, v3, v6}, Ljp/j1;->a(Lmw/e;Lkw/g;DLlw/e;)Ljava/lang/CharSequence;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    const/4 v4, 0x0

    .line 116
    const/16 v5, 0x2c

    .line 117
    .line 118
    const/4 v3, 0x0

    .line 119
    move-object v1, p1

    .line 120
    invoke-static/range {v0 .. v5}, Lqw/e;->c(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IFI)F

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    invoke-static {v9, v2}, Ljava/lang/Math;->max(FF)F

    .line 125
    .line 126
    .line 127
    move-result v9

    .line 128
    goto :goto_0

    .line 129
    :cond_1
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    :goto_1
    if-eqz v0, :cond_2

    .line 134
    .line 135
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    return v0

    .line 140
    :cond_2
    const/4 v0, 0x0

    .line 141
    return v0
.end method
