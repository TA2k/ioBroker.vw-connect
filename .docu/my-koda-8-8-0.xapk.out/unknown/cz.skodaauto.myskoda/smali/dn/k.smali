.class public final Ldn/k;
.super Ldn/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Ljava/lang/StringBuilder;

.field public final B:Ljava/lang/StringBuilder;

.field public final C:Ljava/lang/StringBuilder;

.field public final D:Ljava/lang/StringBuilder;

.field public final E:Landroid/graphics/RectF;

.field public final F:Landroid/graphics/Matrix;

.field public final G:Ldn/i;

.field public final H:Ldn/i;

.field public final I:Ljava/util/HashMap;

.field public final J:Landroidx/collection/u;

.field public final K:Ljava/util/ArrayList;

.field public final L:Ljava/util/ArrayList;

.field public final M:Lxm/f;

.field public final N:Lum/j;

.field public final O:Lum/a;

.field public final P:I

.field public final Q:Lxm/f;

.field public final R:Lxm/f;

.field public final S:Lxm/f;

.field public final T:Lxm/f;

.field public final U:Lxm/f;

.field public final V:Lxm/f;

.field public final W:Lxm/f;

.field public final X:Lxm/f;


# direct methods
.method public constructor <init>(Lum/j;Ldn/e;)V
    .locals 4

    .line 1
    invoke-direct {p0, p1, p2}, Ldn/b;-><init>(Lum/j;Ldn/e;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ldn/k;->A:Ljava/lang/StringBuilder;

    .line 11
    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ldn/k;->B:Ljava/lang/StringBuilder;

    .line 19
    .line 20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Ldn/k;->C:Ljava/lang/StringBuilder;

    .line 26
    .line 27
    new-instance v0, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Ldn/k;->D:Ljava/lang/StringBuilder;

    .line 33
    .line 34
    new-instance v0, Landroid/graphics/RectF;

    .line 35
    .line 36
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Ldn/k;->E:Landroid/graphics/RectF;

    .line 40
    .line 41
    new-instance v0, Landroid/graphics/Matrix;

    .line 42
    .line 43
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 44
    .line 45
    .line 46
    iput-object v0, p0, Ldn/k;->F:Landroid/graphics/Matrix;

    .line 47
    .line 48
    new-instance v0, Ldn/i;

    .line 49
    .line 50
    const/4 v3, 0x1

    .line 51
    invoke-direct {v0, v3, v2}, Ldn/i;-><init>(II)V

    .line 52
    .line 53
    .line 54
    sget-object v2, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 55
    .line 56
    invoke-virtual {v0, v2}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 57
    .line 58
    .line 59
    iput-object v0, p0, Ldn/k;->G:Ldn/i;

    .line 60
    .line 61
    new-instance v0, Ldn/i;

    .line 62
    .line 63
    const/4 v2, 0x1

    .line 64
    invoke-direct {v0, v3, v2}, Ldn/i;-><init>(II)V

    .line 65
    .line 66
    .line 67
    sget-object v2, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 68
    .line 69
    invoke-virtual {v0, v2}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 70
    .line 71
    .line 72
    iput-object v0, p0, Ldn/k;->H:Ldn/i;

    .line 73
    .line 74
    new-instance v0, Ljava/util/HashMap;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 77
    .line 78
    .line 79
    iput-object v0, p0, Ldn/k;->I:Ljava/util/HashMap;

    .line 80
    .line 81
    new-instance v0, Landroidx/collection/u;

    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-direct {v0, v2}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iput-object v0, p0, Ldn/k;->J:Landroidx/collection/u;

    .line 88
    .line 89
    new-instance v0, Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 92
    .line 93
    .line 94
    iput-object v0, p0, Ldn/k;->K:Ljava/util/ArrayList;

    .line 95
    .line 96
    new-instance v0, Ljava/util/ArrayList;

    .line 97
    .line 98
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 99
    .line 100
    .line 101
    iput-object v0, p0, Ldn/k;->L:Ljava/util/ArrayList;

    .line 102
    .line 103
    iput v1, p0, Ldn/k;->P:I

    .line 104
    .line 105
    iput-object p1, p0, Ldn/k;->N:Lum/j;

    .line 106
    .line 107
    iget-object p1, p2, Ldn/e;->b:Lum/a;

    .line 108
    .line 109
    iput-object p1, p0, Ldn/k;->O:Lum/a;

    .line 110
    .line 111
    iget-object p1, p2, Ldn/e;->q:Lbn/a;

    .line 112
    .line 113
    new-instance v0, Lxm/f;

    .line 114
    .line 115
    iget-object p1, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p1, Ljava/util/List;

    .line 118
    .line 119
    const/4 v1, 0x3

    .line 120
    invoke-direct {v0, p1, v1}, Lxm/f;-><init>(Ljava/util/List;I)V

    .line 121
    .line 122
    .line 123
    iput-object v0, p0, Ldn/k;->M:Lxm/f;

    .line 124
    .line 125
    invoke-virtual {v0, p0}, Lxm/e;->a(Lxm/a;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p0, v0}, Ldn/b;->f(Lxm/e;)V

    .line 129
    .line 130
    .line 131
    iget-object p1, p2, Ldn/e;->r:Lb81/c;

    .line 132
    .line 133
    if-eqz p1, :cond_0

    .line 134
    .line 135
    iget-object p2, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p2, Landroidx/lifecycle/c1;

    .line 138
    .line 139
    if-eqz p2, :cond_0

    .line 140
    .line 141
    iget-object p2, p2, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p2, Lbn/a;

    .line 144
    .line 145
    if-eqz p2, :cond_0

    .line 146
    .line 147
    invoke-virtual {p2}, Lbn/a;->p()Lxm/e;

    .line 148
    .line 149
    .line 150
    move-result-object p2

    .line 151
    move-object v0, p2

    .line 152
    check-cast v0, Lxm/f;

    .line 153
    .line 154
    iput-object v0, p0, Ldn/k;->Q:Lxm/f;

    .line 155
    .line 156
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 160
    .line 161
    .line 162
    :cond_0
    if-eqz p1, :cond_1

    .line 163
    .line 164
    iget-object p2, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p2, Landroidx/lifecycle/c1;

    .line 167
    .line 168
    if-eqz p2, :cond_1

    .line 169
    .line 170
    iget-object p2, p2, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast p2, Lbn/a;

    .line 173
    .line 174
    if-eqz p2, :cond_1

    .line 175
    .line 176
    invoke-virtual {p2}, Lbn/a;->p()Lxm/e;

    .line 177
    .line 178
    .line 179
    move-result-object p2

    .line 180
    move-object v0, p2

    .line 181
    check-cast v0, Lxm/f;

    .line 182
    .line 183
    iput-object v0, p0, Ldn/k;->R:Lxm/f;

    .line 184
    .line 185
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 189
    .line 190
    .line 191
    :cond_1
    if-eqz p1, :cond_2

    .line 192
    .line 193
    iget-object p2, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast p2, Landroidx/lifecycle/c1;

    .line 196
    .line 197
    if-eqz p2, :cond_2

    .line 198
    .line 199
    iget-object p2, p2, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast p2, Lbn/b;

    .line 202
    .line 203
    if-eqz p2, :cond_2

    .line 204
    .line 205
    invoke-virtual {p2}, Lbn/b;->b0()Lxm/f;

    .line 206
    .line 207
    .line 208
    move-result-object p2

    .line 209
    iput-object p2, p0, Ldn/k;->S:Lxm/f;

    .line 210
    .line 211
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 215
    .line 216
    .line 217
    :cond_2
    if-eqz p1, :cond_3

    .line 218
    .line 219
    iget-object p2, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast p2, Landroidx/lifecycle/c1;

    .line 222
    .line 223
    if-eqz p2, :cond_3

    .line 224
    .line 225
    iget-object p2, p2, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast p2, Lbn/b;

    .line 228
    .line 229
    if-eqz p2, :cond_3

    .line 230
    .line 231
    invoke-virtual {p2}, Lbn/b;->b0()Lxm/f;

    .line 232
    .line 233
    .line 234
    move-result-object p2

    .line 235
    iput-object p2, p0, Ldn/k;->T:Lxm/f;

    .line 236
    .line 237
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 241
    .line 242
    .line 243
    :cond_3
    if-eqz p1, :cond_4

    .line 244
    .line 245
    iget-object p2, p1, Lb81/c;->e:Ljava/lang/Object;

    .line 246
    .line 247
    check-cast p2, Landroidx/lifecycle/c1;

    .line 248
    .line 249
    if-eqz p2, :cond_4

    .line 250
    .line 251
    iget-object p2, p2, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p2, Lbn/a;

    .line 254
    .line 255
    if-eqz p2, :cond_4

    .line 256
    .line 257
    invoke-virtual {p2}, Lbn/a;->p()Lxm/e;

    .line 258
    .line 259
    .line 260
    move-result-object p2

    .line 261
    move-object v0, p2

    .line 262
    check-cast v0, Lxm/f;

    .line 263
    .line 264
    iput-object v0, p0, Ldn/k;->U:Lxm/f;

    .line 265
    .line 266
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 270
    .line 271
    .line 272
    :cond_4
    if-eqz p1, :cond_5

    .line 273
    .line 274
    iget-object p2, p1, Lb81/c;->f:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast p2, Lio/o;

    .line 277
    .line 278
    if-eqz p2, :cond_5

    .line 279
    .line 280
    iget-object p2, p2, Lio/o;->e:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast p2, Lbn/a;

    .line 283
    .line 284
    if-eqz p2, :cond_5

    .line 285
    .line 286
    invoke-virtual {p2}, Lbn/a;->p()Lxm/e;

    .line 287
    .line 288
    .line 289
    move-result-object p2

    .line 290
    move-object v0, p2

    .line 291
    check-cast v0, Lxm/f;

    .line 292
    .line 293
    iput-object v0, p0, Ldn/k;->V:Lxm/f;

    .line 294
    .line 295
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 299
    .line 300
    .line 301
    :cond_5
    if-eqz p1, :cond_6

    .line 302
    .line 303
    iget-object p2, p1, Lb81/c;->f:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast p2, Lio/o;

    .line 306
    .line 307
    if-eqz p2, :cond_6

    .line 308
    .line 309
    iget-object p2, p2, Lio/o;->f:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast p2, Lbn/a;

    .line 312
    .line 313
    if-eqz p2, :cond_6

    .line 314
    .line 315
    invoke-virtual {p2}, Lbn/a;->p()Lxm/e;

    .line 316
    .line 317
    .line 318
    move-result-object p2

    .line 319
    move-object v0, p2

    .line 320
    check-cast v0, Lxm/f;

    .line 321
    .line 322
    iput-object v0, p0, Ldn/k;->W:Lxm/f;

    .line 323
    .line 324
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 328
    .line 329
    .line 330
    :cond_6
    if-eqz p1, :cond_7

    .line 331
    .line 332
    iget-object p2, p1, Lb81/c;->f:Ljava/lang/Object;

    .line 333
    .line 334
    check-cast p2, Lio/o;

    .line 335
    .line 336
    if-eqz p2, :cond_7

    .line 337
    .line 338
    iget-object p2, p2, Lio/o;->g:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast p2, Lbn/a;

    .line 341
    .line 342
    if-eqz p2, :cond_7

    .line 343
    .line 344
    invoke-virtual {p2}, Lbn/a;->p()Lxm/e;

    .line 345
    .line 346
    .line 347
    move-result-object p2

    .line 348
    move-object v0, p2

    .line 349
    check-cast v0, Lxm/f;

    .line 350
    .line 351
    iput-object v0, p0, Ldn/k;->X:Lxm/f;

    .line 352
    .line 353
    invoke-virtual {p2, p0}, Lxm/e;->a(Lxm/a;)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {p0, p2}, Ldn/b;->f(Lxm/e;)V

    .line 357
    .line 358
    .line 359
    :cond_7
    if-eqz p1, :cond_8

    .line 360
    .line 361
    iget-object p1, p1, Lb81/c;->f:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast p1, Lio/o;

    .line 364
    .line 365
    if-eqz p1, :cond_8

    .line 366
    .line 367
    iget p1, p1, Lio/o;->d:I

    .line 368
    .line 369
    iput p1, p0, Ldn/k;->P:I

    .line 370
    .line 371
    :cond_8
    return-void
.end method

.method public static o(Ljava/lang/String;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Landroid/graphics/Paint;->getColor()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/Paint;->getStyle()Landroid/graphics/Paint$Style;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sget-object v1, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 13
    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v1, 0x0

    .line 21
    cmpl-float v0, v0, v1

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    :goto_0
    return-void

    .line 26
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    const/4 v5, 0x0

    .line 31
    const/4 v6, 0x0

    .line 32
    const/4 v3, 0x0

    .line 33
    move-object v2, p0

    .line 34
    move-object v7, p1

    .line 35
    move-object v1, p2

    .line 36
    invoke-virtual/range {v1 .. v7}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;IIFFLandroid/graphics/Paint;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public static p(Landroid/graphics/Path;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/graphics/Paint;->getColor()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/Paint;->getStyle()Landroid/graphics/Paint$Style;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sget-object v1, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 13
    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v1, 0x0

    .line 21
    cmpl-float v0, v0, v1

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    :goto_0
    return-void

    .line 26
    :cond_1
    invoke-virtual {p2, p0, p1}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Ldn/k;->O:Lum/a;

    .line 5
    .line 6
    iget-object p2, p0, Lum/a;->k:Landroid/graphics/Rect;

    .line 7
    .line 8
    invoke-virtual {p2}, Landroid/graphics/Rect;->width()I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    int-to-float p2, p2

    .line 13
    iget-object p0, p0, Lum/a;->k:Landroid/graphics/Rect;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    int-to-float p0, p0

    .line 20
    const/4 p3, 0x0

    .line 21
    invoke-virtual {p1, p3, p3, p2, p0}, Landroid/graphics/RectF;->set(FFFF)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move/from16 v8, p3

    .line 6
    .line 7
    iget-object v1, v0, Ldn/k;->M:Lxm/f;

    .line 8
    .line 9
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    move-object v9, v1

    .line 14
    check-cast v9, Lan/b;

    .line 15
    .line 16
    iget-object v10, v0, Ldn/k;->O:Lum/a;

    .line 17
    .line 18
    iget-object v1, v10, Lum/a;->f:Ljava/util/HashMap;

    .line 19
    .line 20
    iget-object v2, v9, Lan/b;->b:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    move-object v3, v1

    .line 27
    check-cast v3, Lan/c;

    .line 28
    .line 29
    if-nez v3, :cond_0

    .line 30
    .line 31
    return-void

    .line 32
    :cond_0
    iget-object v11, v3, Lan/c;->b:Ljava/lang/String;

    .line 33
    .line 34
    iget-object v12, v3, Lan/c;->a:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v7}, Landroid/graphics/Canvas;->save()I

    .line 37
    .line 38
    .line 39
    invoke-virtual/range {p1 .. p2}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 40
    .line 41
    .line 42
    const/4 v13, 0x0

    .line 43
    invoke-virtual {v0, v9, v8, v13}, Ldn/k;->n(Lan/b;II)V

    .line 44
    .line 45
    .line 46
    iget-object v14, v0, Ldn/k;->N:Lum/j;

    .line 47
    .line 48
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    iget-object v1, v14, Lum/j;->d:Lum/a;

    .line 52
    .line 53
    iget-object v1, v1, Lum/a;->h:Landroidx/collection/b1;

    .line 54
    .line 55
    invoke-virtual {v1}, Landroidx/collection/b1;->f()I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    const-string v2, "\n"

    .line 60
    .line 61
    const-string v4, "\u0003"

    .line 62
    .line 63
    const-string v5, "\r"

    .line 64
    .line 65
    const-string v6, "\r\n"

    .line 66
    .line 67
    iget-object v15, v0, Ldn/k;->G:Ldn/i;

    .line 68
    .line 69
    move/from16 v16, v13

    .line 70
    .line 71
    iget-object v13, v0, Ldn/k;->H:Ldn/i;

    .line 72
    .line 73
    move/from16 v17, v1

    .line 74
    .line 75
    iget-object v1, v0, Ldn/k;->T:Lxm/f;

    .line 76
    .line 77
    const/high16 v18, 0x41200000    # 10.0f

    .line 78
    .line 79
    const/16 v19, 0x3

    .line 80
    .line 81
    const/16 v20, 0x1

    .line 82
    .line 83
    move-object/from16 v21, v13

    .line 84
    .line 85
    const/high16 v22, 0x42c80000    # 100.0f

    .line 86
    .line 87
    if-lez v17, :cond_b

    .line 88
    .line 89
    const/16 v17, 0x2

    .line 90
    .line 91
    iget v0, v9, Lan/b;->c:F

    .line 92
    .line 93
    div-float v0, v0, v22

    .line 94
    .line 95
    sget-object v22, Lgn/h;->e:Ley0/b;

    .line 96
    .line 97
    invoke-virtual/range {v22 .. v22}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v22

    .line 101
    const/16 v23, 0x0

    .line 102
    .line 103
    move-object/from16 v13, v22

    .line 104
    .line 105
    check-cast v13, [F

    .line 106
    .line 107
    aput v23, v13, v16

    .line 108
    .line 109
    aput v23, v13, v20

    .line 110
    .line 111
    sget v22, Lgn/h;->f:F

    .line 112
    .line 113
    aput v22, v13, v17

    .line 114
    .line 115
    aput v22, v13, v19

    .line 116
    .line 117
    move/from16 v22, v0

    .line 118
    .line 119
    move-object/from16 v0, p2

    .line 120
    .line 121
    invoke-virtual {v0, v13}, Landroid/graphics/Matrix;->mapPoints([F)V

    .line 122
    .line 123
    .line 124
    aget v0, v13, v17

    .line 125
    .line 126
    aget v17, v13, v16

    .line 127
    .line 128
    sub-float v0, v0, v17

    .line 129
    .line 130
    aget v17, v13, v19

    .line 131
    .line 132
    aget v13, v13, v20

    .line 133
    .line 134
    sub-float v13, v17, v13

    .line 135
    .line 136
    move-object/from16 v24, v1

    .line 137
    .line 138
    float-to-double v0, v0

    .line 139
    move-object/from16 v25, v14

    .line 140
    .line 141
    float-to-double v13, v13

    .line 142
    invoke-static {v0, v1, v13, v14}, Ljava/lang/Math;->hypot(DD)D

    .line 143
    .line 144
    .line 145
    iget-object v0, v9, Lan/b;->a:Ljava/lang/String;

    .line 146
    .line 147
    invoke-virtual {v0, v6, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    invoke-virtual {v0, v4, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-virtual {v0, v2, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-virtual {v0, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 164
    .line 165
    .line 166
    move-result-object v13

    .line 167
    invoke-interface {v13}, Ljava/util/List;->size()I

    .line 168
    .line 169
    .line 170
    move-result v14

    .line 171
    iget v0, v9, Lan/b;->e:I

    .line 172
    .line 173
    int-to-float v0, v0

    .line 174
    div-float v0, v0, v18

    .line 175
    .line 176
    if-eqz v24, :cond_1

    .line 177
    .line 178
    invoke-virtual/range {v24 .. v24}, Lxm/e;->d()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    check-cast v1, Ljava/lang/Float;

    .line 183
    .line 184
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    add-float/2addr v0, v1

    .line 189
    :cond_1
    move v5, v0

    .line 190
    move/from16 v0, v16

    .line 191
    .line 192
    const/16 v17, -0x1

    .line 193
    .line 194
    :goto_0
    if-ge v0, v14, :cond_a

    .line 195
    .line 196
    invoke-interface {v13, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    check-cast v1, Ljava/lang/String;

    .line 201
    .line 202
    iget-object v2, v9, Lan/b;->m:Landroid/graphics/PointF;

    .line 203
    .line 204
    if-nez v2, :cond_2

    .line 205
    .line 206
    move/from16 v2, v23

    .line 207
    .line 208
    goto :goto_1

    .line 209
    :cond_2
    iget v2, v2, Landroid/graphics/PointF;->x:F

    .line 210
    .line 211
    :goto_1
    const/4 v6, 0x1

    .line 212
    move/from16 v18, v0

    .line 213
    .line 214
    move/from16 v4, v22

    .line 215
    .line 216
    move-object/from16 v0, p0

    .line 217
    .line 218
    invoke-virtual/range {v0 .. v6}, Ldn/k;->t(Ljava/lang/String;FLan/c;FFZ)Ljava/util/List;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    move/from16 v2, v16

    .line 223
    .line 224
    :goto_2
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 225
    .line 226
    .line 227
    move-result v6

    .line 228
    if-ge v2, v6, :cond_9

    .line 229
    .line 230
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v6

    .line 234
    check-cast v6, Ldn/j;

    .line 235
    .line 236
    move-object/from16 p2, v1

    .line 237
    .line 238
    add-int/lit8 v1, v17, 0x1

    .line 239
    .line 240
    invoke-virtual {v7}, Landroid/graphics/Canvas;->save()I

    .line 241
    .line 242
    .line 243
    move/from16 v19, v2

    .line 244
    .line 245
    iget v2, v6, Ldn/j;->b:F

    .line 246
    .line 247
    invoke-virtual {v0, v7, v9, v1, v2}, Ldn/k;->s(Landroid/graphics/Canvas;Lan/b;IF)Z

    .line 248
    .line 249
    .line 250
    iget-object v2, v6, Ldn/j;->a:Ljava/lang/String;

    .line 251
    .line 252
    move/from16 p4, v1

    .line 253
    .line 254
    move/from16 v6, v16

    .line 255
    .line 256
    :goto_3
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 257
    .line 258
    .line 259
    move-result v1

    .line 260
    if-ge v6, v1, :cond_8

    .line 261
    .line 262
    invoke-virtual {v2, v6}, Ljava/lang/String;->charAt(I)C

    .line 263
    .line 264
    .line 265
    move-result v1

    .line 266
    invoke-static {v1, v12, v11}, Lan/d;->a(CLjava/lang/String;Ljava/lang/String;)I

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    move-object/from16 v17, v2

    .line 271
    .line 272
    iget-object v2, v10, Lum/a;->h:Landroidx/collection/b1;

    .line 273
    .line 274
    invoke-virtual {v2, v1}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    check-cast v1, Lan/d;

    .line 279
    .line 280
    if-nez v1, :cond_3

    .line 281
    .line 282
    move/from16 v20, v5

    .line 283
    .line 284
    move/from16 v22, v6

    .line 285
    .line 286
    move-object/from16 v26, v13

    .line 287
    .line 288
    move/from16 v27, v14

    .line 289
    .line 290
    move-object/from16 v13, v21

    .line 291
    .line 292
    move-object/from16 v14, v25

    .line 293
    .line 294
    goto/16 :goto_8

    .line 295
    .line 296
    :cond_3
    invoke-virtual {v0, v9, v8, v6}, Ldn/k;->n(Lan/b;II)V

    .line 297
    .line 298
    .line 299
    iget-object v2, v0, Ldn/k;->I:Ljava/util/HashMap;

    .line 300
    .line 301
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 302
    .line 303
    .line 304
    move-result v20

    .line 305
    if-eqz v20, :cond_4

    .line 306
    .line 307
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v2

    .line 311
    check-cast v2, Ljava/util/List;

    .line 312
    .line 313
    move/from16 v20, v5

    .line 314
    .line 315
    move/from16 v22, v6

    .line 316
    .line 317
    move-object/from16 v26, v13

    .line 318
    .line 319
    move/from16 v27, v14

    .line 320
    .line 321
    move-object/from16 v14, v25

    .line 322
    .line 323
    goto :goto_5

    .line 324
    :cond_4
    move/from16 v20, v5

    .line 325
    .line 326
    iget-object v5, v1, Lan/d;->a:Ljava/util/ArrayList;

    .line 327
    .line 328
    move/from16 v22, v6

    .line 329
    .line 330
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 331
    .line 332
    .line 333
    move-result v6

    .line 334
    move-object/from16 v26, v13

    .line 335
    .line 336
    new-instance v13, Ljava/util/ArrayList;

    .line 337
    .line 338
    invoke-direct {v13, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 339
    .line 340
    .line 341
    move/from16 v27, v14

    .line 342
    .line 343
    move/from16 v14, v16

    .line 344
    .line 345
    :goto_4
    if-ge v14, v6, :cond_5

    .line 346
    .line 347
    invoke-virtual {v5, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v24

    .line 351
    move-object/from16 v28, v5

    .line 352
    .line 353
    move-object/from16 v5, v24

    .line 354
    .line 355
    check-cast v5, Lcn/m;

    .line 356
    .line 357
    move/from16 v24, v6

    .line 358
    .line 359
    new-instance v6, Lwm/d;

    .line 360
    .line 361
    move/from16 v29, v14

    .line 362
    .line 363
    move-object/from16 v14, v25

    .line 364
    .line 365
    invoke-direct {v6, v14, v0, v5, v10}, Lwm/d;-><init>(Lum/j;Ldn/b;Lcn/m;Lum/a;)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v13, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    add-int/lit8 v5, v29, 0x1

    .line 372
    .line 373
    move/from16 v6, v24

    .line 374
    .line 375
    move v14, v5

    .line 376
    move-object/from16 v5, v28

    .line 377
    .line 378
    goto :goto_4

    .line 379
    :cond_5
    move-object/from16 v14, v25

    .line 380
    .line 381
    invoke-virtual {v2, v1, v13}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-object v2, v13

    .line 385
    :goto_5
    move/from16 v5, v16

    .line 386
    .line 387
    :goto_6
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 388
    .line 389
    .line 390
    move-result v6

    .line 391
    if-ge v5, v6, :cond_7

    .line 392
    .line 393
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    move-result-object v6

    .line 397
    check-cast v6, Lwm/d;

    .line 398
    .line 399
    invoke-virtual {v6}, Lwm/d;->d()Landroid/graphics/Path;

    .line 400
    .line 401
    .line 402
    move-result-object v6

    .line 403
    iget-object v13, v0, Ldn/k;->E:Landroid/graphics/RectF;

    .line 404
    .line 405
    move-object/from16 v24, v2

    .line 406
    .line 407
    move/from16 v2, v16

    .line 408
    .line 409
    invoke-virtual {v6, v13, v2}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 410
    .line 411
    .line 412
    iget-object v2, v0, Ldn/k;->F:Landroid/graphics/Matrix;

    .line 413
    .line 414
    invoke-virtual {v2}, Landroid/graphics/Matrix;->reset()V

    .line 415
    .line 416
    .line 417
    iget v13, v9, Lan/b;->g:F

    .line 418
    .line 419
    neg-float v13, v13

    .line 420
    invoke-static {}, Lgn/h;->c()F

    .line 421
    .line 422
    .line 423
    move-result v25

    .line 424
    mul-float v13, v13, v25

    .line 425
    .line 426
    move/from16 v0, v23

    .line 427
    .line 428
    invoke-virtual {v2, v0, v13}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 429
    .line 430
    .line 431
    invoke-virtual {v2, v4, v4}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 432
    .line 433
    .line 434
    invoke-virtual {v6, v2}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 435
    .line 436
    .line 437
    iget-boolean v0, v9, Lan/b;->k:Z

    .line 438
    .line 439
    if-eqz v0, :cond_6

    .line 440
    .line 441
    invoke-static {v6, v15, v7}, Ldn/k;->p(Landroid/graphics/Path;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 442
    .line 443
    .line 444
    move-object/from16 v13, v21

    .line 445
    .line 446
    invoke-static {v6, v13, v7}, Ldn/k;->p(Landroid/graphics/Path;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 447
    .line 448
    .line 449
    goto :goto_7

    .line 450
    :cond_6
    move-object/from16 v13, v21

    .line 451
    .line 452
    invoke-static {v6, v13, v7}, Ldn/k;->p(Landroid/graphics/Path;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 453
    .line 454
    .line 455
    invoke-static {v6, v15, v7}, Ldn/k;->p(Landroid/graphics/Path;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 456
    .line 457
    .line 458
    :goto_7
    add-int/lit8 v5, v5, 0x1

    .line 459
    .line 460
    move-object/from16 v0, p0

    .line 461
    .line 462
    move-object/from16 v21, v13

    .line 463
    .line 464
    move-object/from16 v2, v24

    .line 465
    .line 466
    const/16 v16, 0x0

    .line 467
    .line 468
    const/16 v23, 0x0

    .line 469
    .line 470
    goto :goto_6

    .line 471
    :cond_7
    move-object/from16 v13, v21

    .line 472
    .line 473
    iget-wide v0, v1, Lan/d;->c:D

    .line 474
    .line 475
    double-to-float v0, v0

    .line 476
    mul-float/2addr v0, v4

    .line 477
    invoke-static {}, Lgn/h;->c()F

    .line 478
    .line 479
    .line 480
    move-result v1

    .line 481
    mul-float/2addr v1, v0

    .line 482
    add-float v1, v1, v20

    .line 483
    .line 484
    const/4 v0, 0x0

    .line 485
    invoke-virtual {v7, v1, v0}, Landroid/graphics/Canvas;->translate(FF)V

    .line 486
    .line 487
    .line 488
    :goto_8
    add-int/lit8 v6, v22, 0x1

    .line 489
    .line 490
    move-object/from16 v0, p0

    .line 491
    .line 492
    move-object/from16 v21, v13

    .line 493
    .line 494
    move-object/from16 v25, v14

    .line 495
    .line 496
    move-object/from16 v2, v17

    .line 497
    .line 498
    move/from16 v5, v20

    .line 499
    .line 500
    move-object/from16 v13, v26

    .line 501
    .line 502
    move/from16 v14, v27

    .line 503
    .line 504
    const/16 v16, 0x0

    .line 505
    .line 506
    const/16 v23, 0x0

    .line 507
    .line 508
    goto/16 :goto_3

    .line 509
    .line 510
    :cond_8
    move/from16 v20, v5

    .line 511
    .line 512
    move-object/from16 v26, v13

    .line 513
    .line 514
    move/from16 v27, v14

    .line 515
    .line 516
    move-object/from16 v13, v21

    .line 517
    .line 518
    move-object/from16 v14, v25

    .line 519
    .line 520
    invoke-virtual {v7}, Landroid/graphics/Canvas;->restore()V

    .line 521
    .line 522
    .line 523
    add-int/lit8 v2, v19, 0x1

    .line 524
    .line 525
    move-object/from16 v0, p0

    .line 526
    .line 527
    move-object/from16 v1, p2

    .line 528
    .line 529
    move/from16 v17, p4

    .line 530
    .line 531
    move-object/from16 v13, v26

    .line 532
    .line 533
    move/from16 v14, v27

    .line 534
    .line 535
    const/16 v16, 0x0

    .line 536
    .line 537
    const/16 v23, 0x0

    .line 538
    .line 539
    goto/16 :goto_2

    .line 540
    .line 541
    :cond_9
    move/from16 v20, v5

    .line 542
    .line 543
    move-object/from16 v26, v13

    .line 544
    .line 545
    move/from16 v27, v14

    .line 546
    .line 547
    move-object/from16 v13, v21

    .line 548
    .line 549
    move-object/from16 v14, v25

    .line 550
    .line 551
    add-int/lit8 v0, v18, 0x1

    .line 552
    .line 553
    move/from16 v22, v4

    .line 554
    .line 555
    move-object/from16 v13, v26

    .line 556
    .line 557
    move/from16 v14, v27

    .line 558
    .line 559
    const/16 v16, 0x0

    .line 560
    .line 561
    const/16 v23, 0x0

    .line 562
    .line 563
    goto/16 :goto_0

    .line 564
    .line 565
    :cond_a
    move-object v8, v7

    .line 566
    goto/16 :goto_1c

    .line 567
    .line 568
    :cond_b
    move-object/from16 v24, v1

    .line 569
    .line 570
    move-object/from16 v13, v21

    .line 571
    .line 572
    const/16 v17, 0x2

    .line 573
    .line 574
    invoke-virtual {v14}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 575
    .line 576
    .line 577
    move-result-object v0

    .line 578
    const/4 v1, 0x0

    .line 579
    if-nez v0, :cond_c

    .line 580
    .line 581
    move-object v0, v1

    .line 582
    goto :goto_9

    .line 583
    :cond_c
    iget-object v0, v14, Lum/j;->i:Landroidx/lifecycle/c1;

    .line 584
    .line 585
    if-nez v0, :cond_d

    .line 586
    .line 587
    new-instance v0, Landroidx/lifecycle/c1;

    .line 588
    .line 589
    invoke-virtual {v14}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 590
    .line 591
    .line 592
    move-result-object v10

    .line 593
    invoke-direct {v0, v10}, Landroidx/lifecycle/c1;-><init>(Landroid/graphics/drawable/Drawable$Callback;)V

    .line 594
    .line 595
    .line 596
    iput-object v0, v14, Lum/j;->i:Landroidx/lifecycle/c1;

    .line 597
    .line 598
    :cond_d
    iget-object v0, v14, Lum/j;->i:Landroidx/lifecycle/c1;

    .line 599
    .line 600
    :goto_9
    if-eqz v0, :cond_15

    .line 601
    .line 602
    iget-object v1, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 603
    .line 604
    check-cast v1, Lvp/y1;

    .line 605
    .line 606
    iput-object v12, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 607
    .line 608
    iput-object v11, v1, Lvp/y1;->f:Ljava/lang/Object;

    .line 609
    .line 610
    iget-object v10, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 611
    .line 612
    check-cast v10, Ljava/util/HashMap;

    .line 613
    .line 614
    invoke-virtual {v10, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 615
    .line 616
    .line 617
    move-result-object v14

    .line 618
    check-cast v14, Landroid/graphics/Typeface;

    .line 619
    .line 620
    if-eqz v14, :cond_e

    .line 621
    .line 622
    move-object v1, v14

    .line 623
    goto/16 :goto_d

    .line 624
    .line 625
    :cond_e
    iget-object v14, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 626
    .line 627
    check-cast v14, Ljava/util/HashMap;

    .line 628
    .line 629
    invoke-virtual {v14, v12}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 630
    .line 631
    .line 632
    move-result-object v21

    .line 633
    check-cast v21, Landroid/graphics/Typeface;

    .line 634
    .line 635
    if-eqz v21, :cond_f

    .line 636
    .line 637
    move-object/from16 v0, v21

    .line 638
    .line 639
    goto :goto_a

    .line 640
    :cond_f
    iget-object v8, v3, Lan/c;->c:Landroid/graphics/Typeface;

    .line 641
    .line 642
    if-eqz v8, :cond_10

    .line 643
    .line 644
    move-object v0, v8

    .line 645
    goto :goto_a

    .line 646
    :cond_10
    new-instance v8, Ljava/lang/StringBuilder;

    .line 647
    .line 648
    const-string v7, "fonts/"

    .line 649
    .line 650
    invoke-direct {v8, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 651
    .line 652
    .line 653
    invoke-virtual {v8, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 654
    .line 655
    .line 656
    iget-object v7, v0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 657
    .line 658
    check-cast v7, Ljava/lang/String;

    .line 659
    .line 660
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 661
    .line 662
    .line 663
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 664
    .line 665
    .line 666
    move-result-object v7

    .line 667
    iget-object v0, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 668
    .line 669
    check-cast v0, Landroid/content/res/AssetManager;

    .line 670
    .line 671
    invoke-static {v0, v7}, Landroid/graphics/Typeface;->createFromAsset(Landroid/content/res/AssetManager;Ljava/lang/String;)Landroid/graphics/Typeface;

    .line 672
    .line 673
    .line 674
    move-result-object v0

    .line 675
    invoke-virtual {v14, v12, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 676
    .line 677
    .line 678
    :goto_a
    const-string v7, "Italic"

    .line 679
    .line 680
    invoke-virtual {v11, v7}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 681
    .line 682
    .line 683
    move-result v7

    .line 684
    const-string v8, "Bold"

    .line 685
    .line 686
    invoke-virtual {v11, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 687
    .line 688
    .line 689
    move-result v8

    .line 690
    if-eqz v7, :cond_11

    .line 691
    .line 692
    if-eqz v8, :cond_11

    .line 693
    .line 694
    move/from16 v7, v19

    .line 695
    .line 696
    goto :goto_b

    .line 697
    :cond_11
    if-eqz v7, :cond_12

    .line 698
    .line 699
    move/from16 v7, v17

    .line 700
    .line 701
    goto :goto_b

    .line 702
    :cond_12
    if-eqz v8, :cond_13

    .line 703
    .line 704
    move/from16 v7, v20

    .line 705
    .line 706
    goto :goto_b

    .line 707
    :cond_13
    const/4 v7, 0x0

    .line 708
    :goto_b
    invoke-virtual {v0}, Landroid/graphics/Typeface;->getStyle()I

    .line 709
    .line 710
    .line 711
    move-result v8

    .line 712
    if-ne v8, v7, :cond_14

    .line 713
    .line 714
    goto :goto_c

    .line 715
    :cond_14
    invoke-static {v0, v7}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    .line 716
    .line 717
    .line 718
    move-result-object v0

    .line 719
    :goto_c
    invoke-virtual {v10, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 720
    .line 721
    .line 722
    move-object v1, v0

    .line 723
    :cond_15
    :goto_d
    if-eqz v1, :cond_16

    .line 724
    .line 725
    goto :goto_e

    .line 726
    :cond_16
    iget-object v1, v3, Lan/c;->c:Landroid/graphics/Typeface;

    .line 727
    .line 728
    :goto_e
    if-nez v1, :cond_18

    .line 729
    .line 730
    :cond_17
    move-object/from16 v8, p1

    .line 731
    .line 732
    goto/16 :goto_1c

    .line 733
    .line 734
    :cond_18
    iget-object v0, v9, Lan/b;->a:Ljava/lang/String;

    .line 735
    .line 736
    invoke-virtual {v15, v1}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 737
    .line 738
    .line 739
    iget v1, v9, Lan/b;->c:F

    .line 740
    .line 741
    invoke-static {}, Lgn/h;->c()F

    .line 742
    .line 743
    .line 744
    move-result v7

    .line 745
    mul-float/2addr v7, v1

    .line 746
    invoke-virtual {v15, v7}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 747
    .line 748
    .line 749
    invoke-virtual {v15}, Landroid/graphics/Paint;->getTypeface()Landroid/graphics/Typeface;

    .line 750
    .line 751
    .line 752
    move-result-object v7

    .line 753
    invoke-virtual {v13, v7}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 754
    .line 755
    .line 756
    invoke-virtual {v15}, Landroid/graphics/Paint;->getTextSize()F

    .line 757
    .line 758
    .line 759
    move-result v7

    .line 760
    invoke-virtual {v13, v7}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 761
    .line 762
    .line 763
    iget v7, v9, Lan/b;->e:I

    .line 764
    .line 765
    int-to-float v7, v7

    .line 766
    div-float v7, v7, v18

    .line 767
    .line 768
    if-eqz v24, :cond_19

    .line 769
    .line 770
    invoke-virtual/range {v24 .. v24}, Lxm/e;->d()Ljava/lang/Object;

    .line 771
    .line 772
    .line 773
    move-result-object v8

    .line 774
    check-cast v8, Ljava/lang/Float;

    .line 775
    .line 776
    invoke-virtual {v8}, Ljava/lang/Float;->floatValue()F

    .line 777
    .line 778
    .line 779
    move-result v8

    .line 780
    add-float/2addr v7, v8

    .line 781
    :cond_19
    invoke-static {}, Lgn/h;->c()F

    .line 782
    .line 783
    .line 784
    move-result v8

    .line 785
    mul-float/2addr v8, v7

    .line 786
    mul-float/2addr v8, v1

    .line 787
    div-float v8, v8, v22

    .line 788
    .line 789
    invoke-virtual {v0, v6, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 790
    .line 791
    .line 792
    move-result-object v0

    .line 793
    invoke-virtual {v0, v4, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 794
    .line 795
    .line 796
    move-result-object v0

    .line 797
    invoke-virtual {v0, v2, v5}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 798
    .line 799
    .line 800
    move-result-object v0

    .line 801
    invoke-virtual {v0, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 802
    .line 803
    .line 804
    move-result-object v0

    .line 805
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 806
    .line 807
    .line 808
    move-result-object v7

    .line 809
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 810
    .line 811
    .line 812
    move-result v10

    .line 813
    const/4 v11, 0x0

    .line 814
    const/4 v12, -0x1

    .line 815
    const/4 v14, 0x0

    .line 816
    :goto_f
    if-ge v11, v10, :cond_17

    .line 817
    .line 818
    invoke-interface {v7, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 819
    .line 820
    .line 821
    move-result-object v0

    .line 822
    move-object v1, v0

    .line 823
    check-cast v1, Ljava/lang/String;

    .line 824
    .line 825
    iget-object v0, v9, Lan/b;->m:Landroid/graphics/PointF;

    .line 826
    .line 827
    if-nez v0, :cond_1a

    .line 828
    .line 829
    const/4 v2, 0x0

    .line 830
    goto :goto_10

    .line 831
    :cond_1a
    iget v0, v0, Landroid/graphics/PointF;->x:F

    .line 832
    .line 833
    move v2, v0

    .line 834
    :goto_10
    const/4 v4, 0x0

    .line 835
    const/4 v6, 0x0

    .line 836
    move-object/from16 v0, p0

    .line 837
    .line 838
    move v5, v8

    .line 839
    move/from16 v8, v17

    .line 840
    .line 841
    invoke-virtual/range {v0 .. v6}, Ldn/k;->t(Ljava/lang/String;FLan/c;FFZ)Ljava/util/List;

    .line 842
    .line 843
    .line 844
    move-result-object v1

    .line 845
    const/4 v2, 0x0

    .line 846
    :goto_11
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 847
    .line 848
    .line 849
    move-result v4

    .line 850
    if-ge v2, v4, :cond_25

    .line 851
    .line 852
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v4

    .line 856
    check-cast v4, Ldn/j;

    .line 857
    .line 858
    add-int/lit8 v12, v12, 0x1

    .line 859
    .line 860
    invoke-virtual/range {p1 .. p1}, Landroid/graphics/Canvas;->save()I

    .line 861
    .line 862
    .line 863
    iget-object v6, v4, Ldn/j;->a:Ljava/lang/String;

    .line 864
    .line 865
    invoke-virtual {v15, v6}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 866
    .line 867
    .line 868
    move-result v6

    .line 869
    move-object/from16 v8, p1

    .line 870
    .line 871
    invoke-virtual {v0, v8, v9, v12, v6}, Ldn/k;->s(Landroid/graphics/Canvas;Lan/b;IF)Z

    .line 872
    .line 873
    .line 874
    iget-object v6, v4, Ldn/j;->a:Ljava/lang/String;

    .line 875
    .line 876
    move-object/from16 p2, v1

    .line 877
    .line 878
    invoke-virtual {v6}, Ljava/lang/String;->toCharArray()[C

    .line 879
    .line 880
    .line 881
    move-result-object v1

    .line 882
    move/from16 v18, v2

    .line 883
    .line 884
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 885
    .line 886
    .line 887
    move-result v2

    .line 888
    move-object/from16 p4, v3

    .line 889
    .line 890
    const/4 v3, 0x0

    .line 891
    invoke-static {v1, v3, v2}, Ljava/text/Bidi;->requiresBidi([CII)Z

    .line 892
    .line 893
    .line 894
    move-result v1

    .line 895
    if-eqz v1, :cond_1f

    .line 896
    .line 897
    new-instance v1, Ljava/text/Bidi;

    .line 898
    .line 899
    const/4 v2, -0x2

    .line 900
    invoke-direct {v1, v6, v2}, Ljava/text/Bidi;-><init>(Ljava/lang/String;I)V

    .line 901
    .line 902
    .line 903
    invoke-virtual {v1}, Ljava/text/Bidi;->getRunCount()I

    .line 904
    .line 905
    .line 906
    move-result v2

    .line 907
    new-array v3, v2, [B

    .line 908
    .line 909
    move/from16 v19, v5

    .line 910
    .line 911
    new-array v5, v2, [Ljava/lang/Integer;

    .line 912
    .line 913
    move-object/from16 v21, v7

    .line 914
    .line 915
    const/4 v7, 0x0

    .line 916
    :goto_12
    if-ge v7, v2, :cond_1b

    .line 917
    .line 918
    move/from16 v22, v10

    .line 919
    .line 920
    invoke-virtual {v1, v7}, Ljava/text/Bidi;->getRunLevel(I)I

    .line 921
    .line 922
    .line 923
    move-result v10

    .line 924
    int-to-byte v10, v10

    .line 925
    aput-byte v10, v3, v7

    .line 926
    .line 927
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 928
    .line 929
    .line 930
    move-result-object v10

    .line 931
    aput-object v10, v5, v7

    .line 932
    .line 933
    add-int/lit8 v7, v7, 0x1

    .line 934
    .line 935
    move/from16 v10, v22

    .line 936
    .line 937
    goto :goto_12

    .line 938
    :cond_1b
    move/from16 v22, v10

    .line 939
    .line 940
    const/4 v7, 0x0

    .line 941
    invoke-static {v3, v7, v5, v7, v2}, Ljava/text/Bidi;->reorderVisually([BI[Ljava/lang/Object;II)V

    .line 942
    .line 943
    .line 944
    iget-object v3, v0, Ldn/k;->C:Ljava/lang/StringBuilder;

    .line 945
    .line 946
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 947
    .line 948
    .line 949
    const/4 v7, 0x0

    .line 950
    :goto_13
    if-ge v7, v2, :cond_1e

    .line 951
    .line 952
    aget-object v10, v5, v7

    .line 953
    .line 954
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 955
    .line 956
    .line 957
    move-result v10

    .line 958
    move/from16 v24, v2

    .line 959
    .line 960
    invoke-virtual {v1, v10}, Ljava/text/Bidi;->getRunStart(I)I

    .line 961
    .line 962
    .line 963
    move-result v2

    .line 964
    move-object/from16 v25, v5

    .line 965
    .line 966
    invoke-virtual {v1, v10}, Ljava/text/Bidi;->getRunLimit(I)I

    .line 967
    .line 968
    .line 969
    move-result v5

    .line 970
    invoke-virtual {v1, v10}, Ljava/text/Bidi;->getRunLevel(I)I

    .line 971
    .line 972
    .line 973
    move-result v10

    .line 974
    invoke-virtual {v6, v2, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 975
    .line 976
    .line 977
    move-result-object v2

    .line 978
    and-int/lit8 v5, v10, 0x1

    .line 979
    .line 980
    if-nez v5, :cond_1c

    .line 981
    .line 982
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 983
    .line 984
    .line 985
    move-object/from16 v26, v1

    .line 986
    .line 987
    goto :goto_15

    .line 988
    :cond_1c
    iget-object v5, v0, Ldn/k;->D:Ljava/lang/StringBuilder;

    .line 989
    .line 990
    const/4 v10, 0x0

    .line 991
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 992
    .line 993
    .line 994
    move-object/from16 v26, v1

    .line 995
    .line 996
    :goto_14
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 997
    .line 998
    .line 999
    move-result v1

    .line 1000
    if-ge v10, v1, :cond_1d

    .line 1001
    .line 1002
    invoke-virtual {v0, v10, v2}, Ldn/k;->m(ILjava/lang/String;)Ljava/lang/String;

    .line 1003
    .line 1004
    .line 1005
    move-result-object v1

    .line 1006
    move-object/from16 v27, v2

    .line 1007
    .line 1008
    const/4 v2, 0x0

    .line 1009
    invoke-virtual {v5, v2, v1}, Ljava/lang/StringBuilder;->insert(ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 1010
    .line 1011
    .line 1012
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 1013
    .line 1014
    .line 1015
    move-result v1

    .line 1016
    add-int/2addr v10, v1

    .line 1017
    move-object/from16 v2, v27

    .line 1018
    .line 1019
    goto :goto_14

    .line 1020
    :cond_1d
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 1021
    .line 1022
    .line 1023
    :goto_15
    add-int/lit8 v7, v7, 0x1

    .line 1024
    .line 1025
    move/from16 v2, v24

    .line 1026
    .line 1027
    move-object/from16 v5, v25

    .line 1028
    .line 1029
    move-object/from16 v1, v26

    .line 1030
    .line 1031
    goto :goto_13

    .line 1032
    :cond_1e
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v6

    .line 1036
    goto :goto_16

    .line 1037
    :cond_1f
    move/from16 v19, v5

    .line 1038
    .line 1039
    move-object/from16 v21, v7

    .line 1040
    .line 1041
    move/from16 v22, v10

    .line 1042
    .line 1043
    :goto_16
    iget-object v1, v0, Ldn/k;->K:Ljava/util/ArrayList;

    .line 1044
    .line 1045
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 1046
    .line 1047
    .line 1048
    const/4 v2, 0x0

    .line 1049
    :goto_17
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 1050
    .line 1051
    .line 1052
    move-result v3

    .line 1053
    if-ge v2, v3, :cond_20

    .line 1054
    .line 1055
    invoke-virtual {v0, v2, v6}, Ldn/k;->m(ILjava/lang/String;)Ljava/lang/String;

    .line 1056
    .line 1057
    .line 1058
    move-result-object v3

    .line 1059
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1060
    .line 1061
    .line 1062
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 1063
    .line 1064
    .line 1065
    move-result v3

    .line 1066
    add-int/2addr v2, v3

    .line 1067
    goto :goto_17

    .line 1068
    :cond_20
    const/4 v2, 0x0

    .line 1069
    :goto_18
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1070
    .line 1071
    .line 1072
    move-result v3

    .line 1073
    if-ge v2, v3, :cond_24

    .line 1074
    .line 1075
    iget-object v3, v0, Ldn/k;->B:Ljava/lang/StringBuilder;

    .line 1076
    .line 1077
    const/4 v7, 0x0

    .line 1078
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 1079
    .line 1080
    .line 1081
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v5

    .line 1085
    check-cast v5, Ljava/lang/String;

    .line 1086
    .line 1087
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1088
    .line 1089
    .line 1090
    add-int/lit8 v5, v2, 0x1

    .line 1091
    .line 1092
    :goto_19
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1093
    .line 1094
    .line 1095
    move-result v6

    .line 1096
    if-ge v5, v6, :cond_22

    .line 1097
    .line 1098
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v6

    .line 1102
    check-cast v6, Ljava/lang/String;

    .line 1103
    .line 1104
    const/4 v7, 0x0

    .line 1105
    :goto_1a
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 1106
    .line 1107
    .line 1108
    move-result v10

    .line 1109
    if-ge v7, v10, :cond_22

    .line 1110
    .line 1111
    invoke-virtual {v6, v7}, Ljava/lang/String;->codePointAt(I)I

    .line 1112
    .line 1113
    .line 1114
    move-result v10

    .line 1115
    invoke-static {v10}, Ljava/lang/Character;->getDirectionality(I)B

    .line 1116
    .line 1117
    .line 1118
    move-result v10

    .line 1119
    move-object/from16 v24, v1

    .line 1120
    .line 1121
    const/4 v1, 0x2

    .line 1122
    if-ne v10, v1, :cond_21

    .line 1123
    .line 1124
    const/4 v10, 0x0

    .line 1125
    invoke-virtual {v3, v10, v6}, Ljava/lang/StringBuilder;->insert(ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 1126
    .line 1127
    .line 1128
    add-int/lit8 v5, v5, 0x1

    .line 1129
    .line 1130
    move-object/from16 v1, v24

    .line 1131
    .line 1132
    goto :goto_19

    .line 1133
    :cond_21
    const/4 v10, 0x0

    .line 1134
    add-int/lit8 v7, v7, 0x1

    .line 1135
    .line 1136
    move-object/from16 v1, v24

    .line 1137
    .line 1138
    goto :goto_1a

    .line 1139
    :cond_22
    move-object/from16 v24, v1

    .line 1140
    .line 1141
    const/4 v1, 0x2

    .line 1142
    const/4 v10, 0x0

    .line 1143
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1144
    .line 1145
    .line 1146
    move-result-object v3

    .line 1147
    add-int/2addr v2, v14

    .line 1148
    move/from16 v6, p3

    .line 1149
    .line 1150
    invoke-virtual {v0, v9, v6, v2}, Ldn/k;->n(Lan/b;II)V

    .line 1151
    .line 1152
    .line 1153
    iget-boolean v2, v9, Lan/b;->k:Z

    .line 1154
    .line 1155
    if-eqz v2, :cond_23

    .line 1156
    .line 1157
    invoke-static {v3, v15, v8}, Ldn/k;->o(Ljava/lang/String;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 1158
    .line 1159
    .line 1160
    invoke-static {v3, v13, v8}, Ldn/k;->o(Ljava/lang/String;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 1161
    .line 1162
    .line 1163
    goto :goto_1b

    .line 1164
    :cond_23
    invoke-static {v3, v13, v8}, Ldn/k;->o(Ljava/lang/String;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 1165
    .line 1166
    .line 1167
    invoke-static {v3, v15, v8}, Ldn/k;->o(Ljava/lang/String;Landroid/graphics/Paint;Landroid/graphics/Canvas;)V

    .line 1168
    .line 1169
    .line 1170
    :goto_1b
    invoke-virtual {v15, v3}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 1171
    .line 1172
    .line 1173
    move-result v2

    .line 1174
    add-float v2, v2, v19

    .line 1175
    .line 1176
    const/4 v3, 0x0

    .line 1177
    invoke-virtual {v8, v2, v3}, Landroid/graphics/Canvas;->translate(FF)V

    .line 1178
    .line 1179
    .line 1180
    move v2, v5

    .line 1181
    move-object/from16 v1, v24

    .line 1182
    .line 1183
    goto :goto_18

    .line 1184
    :cond_24
    move/from16 v6, p3

    .line 1185
    .line 1186
    const/4 v1, 0x2

    .line 1187
    const/4 v3, 0x0

    .line 1188
    const/4 v10, 0x0

    .line 1189
    iget-object v2, v4, Ldn/j;->a:Ljava/lang/String;

    .line 1190
    .line 1191
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 1192
    .line 1193
    .line 1194
    move-result v2

    .line 1195
    add-int/2addr v14, v2

    .line 1196
    invoke-virtual {v8}, Landroid/graphics/Canvas;->restore()V

    .line 1197
    .line 1198
    .line 1199
    add-int/lit8 v2, v18, 0x1

    .line 1200
    .line 1201
    move-object/from16 v3, p4

    .line 1202
    .line 1203
    move v8, v1

    .line 1204
    move/from16 v5, v19

    .line 1205
    .line 1206
    move-object/from16 v7, v21

    .line 1207
    .line 1208
    move/from16 v10, v22

    .line 1209
    .line 1210
    move-object/from16 v1, p2

    .line 1211
    .line 1212
    goto/16 :goto_11

    .line 1213
    .line 1214
    :cond_25
    move/from16 v6, p3

    .line 1215
    .line 1216
    move-object/from16 p4, v3

    .line 1217
    .line 1218
    move/from16 v19, v5

    .line 1219
    .line 1220
    move-object/from16 v21, v7

    .line 1221
    .line 1222
    move v1, v8

    .line 1223
    move/from16 v22, v10

    .line 1224
    .line 1225
    const/4 v3, 0x0

    .line 1226
    const/4 v10, 0x0

    .line 1227
    move-object/from16 v8, p1

    .line 1228
    .line 1229
    add-int/lit8 v11, v11, 0x1

    .line 1230
    .line 1231
    move-object/from16 v3, p4

    .line 1232
    .line 1233
    move/from16 v17, v1

    .line 1234
    .line 1235
    move/from16 v8, v19

    .line 1236
    .line 1237
    move/from16 v10, v22

    .line 1238
    .line 1239
    goto/16 :goto_f

    .line 1240
    .line 1241
    :goto_1c
    invoke-virtual {v8}, Landroid/graphics/Canvas;->restore()V

    .line 1242
    .line 1243
    .line 1244
    return-void
.end method

.method public final m(ILjava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    invoke-virtual {p2, p1}, Ljava/lang/String;->codePointAt(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {v0}, Ljava/lang/Character;->charCount(I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/2addr v1, p1

    .line 10
    :goto_0
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-ge v1, v2, :cond_1

    .line 15
    .line 16
    invoke-virtual {p2, v1}, Ljava/lang/String;->codePointAt(I)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    invoke-static {v2}, Ljava/lang/Character;->getType(I)I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const/16 v4, 0x10

    .line 25
    .line 26
    if-eq v3, v4, :cond_0

    .line 27
    .line 28
    invoke-static {v2}, Ljava/lang/Character;->getType(I)I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    const/16 v4, 0x1b

    .line 33
    .line 34
    if-eq v3, v4, :cond_0

    .line 35
    .line 36
    invoke-static {v2}, Ljava/lang/Character;->getType(I)I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    const/4 v4, 0x6

    .line 41
    if-eq v3, v4, :cond_0

    .line 42
    .line 43
    invoke-static {v2}, Ljava/lang/Character;->getType(I)I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    const/16 v4, 0x1c

    .line 48
    .line 49
    if-eq v3, v4, :cond_0

    .line 50
    .line 51
    invoke-static {v2}, Ljava/lang/Character;->getType(I)I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    const/16 v4, 0x8

    .line 56
    .line 57
    if-eq v3, v4, :cond_0

    .line 58
    .line 59
    invoke-static {v2}, Ljava/lang/Character;->getType(I)I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    const/16 v4, 0x13

    .line 64
    .line 65
    if-ne v3, v4, :cond_1

    .line 66
    .line 67
    :cond_0
    invoke-static {v2}, Ljava/lang/Character;->charCount(I)I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    add-int/2addr v1, v3

    .line 72
    mul-int/lit8 v0, v0, 0x1f

    .line 73
    .line 74
    add-int/2addr v0, v2

    .line 75
    goto :goto_0

    .line 76
    :cond_1
    int-to-long v2, v0

    .line 77
    iget-object v0, p0, Ldn/k;->J:Landroidx/collection/u;

    .line 78
    .line 79
    invoke-virtual {v0, v2, v3}, Landroidx/collection/u;->c(J)I

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-ltz v4, :cond_2

    .line 84
    .line 85
    invoke-virtual {v0, v2, v3}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    check-cast p0, Ljava/lang/String;

    .line 90
    .line 91
    return-object p0

    .line 92
    :cond_2
    const/4 v4, 0x0

    .line 93
    iget-object p0, p0, Ldn/k;->A:Ljava/lang/StringBuilder;

    .line 94
    .line 95
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 96
    .line 97
    .line 98
    :goto_1
    if-ge p1, v1, :cond_3

    .line 99
    .line 100
    invoke-virtual {p2, p1}, Ljava/lang/String;->codePointAt(I)I

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    invoke-virtual {p0, v4}, Ljava/lang/StringBuilder;->appendCodePoint(I)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-static {v4}, Ljava/lang/Character;->charCount(I)I

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    add-int/2addr p1, v4

    .line 112
    goto :goto_1

    .line 113
    :cond_3
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-virtual {v0, v2, v3, p0}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    return-object p0
.end method

.method public final n(Lan/b;II)V
    .locals 6

    .line 1
    iget-object v0, p0, Ldn/k;->G:Ldn/i;

    .line 2
    .line 3
    iget-object v1, p0, Ldn/k;->Q:Lxm/f;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p3}, Ldn/k;->r(I)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget v1, p1, Lan/b;->h:I

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 30
    .line 31
    .line 32
    :goto_0
    iget-object v1, p0, Ldn/k;->R:Lxm/f;

    .line 33
    .line 34
    iget-object v2, p0, Ldn/k;->H:Ldn/i;

    .line 35
    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    invoke-virtual {p0, p3}, Ldn/k;->r(I)Z

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-eqz v3, :cond_1

    .line 43
    .line 44
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/lang/Integer;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    invoke-virtual {v2, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    iget v1, p1, Lan/b;->i:I

    .line 59
    .line 60
    invoke-virtual {v2, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 61
    .line 62
    .line 63
    :goto_1
    iget-object v1, p0, Ldn/b;->w:Lxm/n;

    .line 64
    .line 65
    iget-object v1, v1, Lxm/n;->j:Lxm/f;

    .line 66
    .line 67
    const/16 v3, 0x64

    .line 68
    .line 69
    if-nez v1, :cond_2

    .line 70
    .line 71
    move v1, v3

    .line 72
    goto :goto_2

    .line 73
    :cond_2
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Ljava/lang/Integer;

    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    :goto_2
    iget-object v4, p0, Ldn/k;->U:Lxm/f;

    .line 84
    .line 85
    if-eqz v4, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0, p3}, Ldn/k;->r(I)Z

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    if-eqz v5, :cond_3

    .line 92
    .line 93
    invoke-virtual {v4}, Lxm/e;->d()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    check-cast v3, Ljava/lang/Integer;

    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    :cond_3
    int-to-float v1, v1

    .line 104
    const/high16 v4, 0x437f0000    # 255.0f

    .line 105
    .line 106
    mul-float/2addr v1, v4

    .line 107
    const/high16 v5, 0x42c80000    # 100.0f

    .line 108
    .line 109
    div-float/2addr v1, v5

    .line 110
    int-to-float v3, v3

    .line 111
    div-float/2addr v3, v5

    .line 112
    mul-float/2addr v3, v1

    .line 113
    int-to-float p2, p2

    .line 114
    mul-float/2addr v3, p2

    .line 115
    div-float/2addr v3, v4

    .line 116
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    invoke-virtual {v0, p2}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v2, p2}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 124
    .line 125
    .line 126
    iget-object p2, p0, Ldn/k;->S:Lxm/f;

    .line 127
    .line 128
    if-eqz p2, :cond_4

    .line 129
    .line 130
    invoke-virtual {p0, p3}, Ldn/k;->r(I)Z

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-eqz p0, :cond_4

    .line 135
    .line 136
    invoke-virtual {p2}, Lxm/e;->d()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    check-cast p0, Ljava/lang/Float;

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    invoke-virtual {v2, p0}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 147
    .line 148
    .line 149
    return-void

    .line 150
    :cond_4
    iget p0, p1, Lan/b;->j:F

    .line 151
    .line 152
    invoke-static {}, Lgn/h;->c()F

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    mul-float/2addr p1, p0

    .line 157
    invoke-virtual {v2, p1}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 158
    .line 159
    .line 160
    return-void
.end method

.method public final q(I)Ldn/j;
    .locals 3

    .line 1
    iget-object p0, p0, Ldn/k;->L:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    :goto_0
    if-ge v0, p1, :cond_0

    .line 8
    .line 9
    new-instance v1, Ldn/j;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    const-string v2, ""

    .line 15
    .line 16
    iput-object v2, v1, Ldn/j;->a:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    iput v2, v1, Ldn/j;->b:F

    .line 20
    .line 21
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    add-int/lit8 p1, p1, -0x1

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Ldn/j;

    .line 34
    .line 35
    return-object p0
.end method

.method public final r(I)Z
    .locals 5

    .line 1
    iget-object v0, p0, Ldn/k;->M:Lxm/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Lxm/e;->d()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lan/b;

    .line 8
    .line 9
    iget-object v0, v0, Lan/b;->a:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iget-object v1, p0, Ldn/k;->V:Lxm/f;

    .line 16
    .line 17
    if-eqz v1, :cond_3

    .line 18
    .line 19
    iget-object v2, p0, Ldn/k;->W:Lxm/f;

    .line 20
    .line 21
    if-eqz v2, :cond_3

    .line 22
    .line 23
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ljava/lang/Integer;

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    check-cast v4, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    invoke-virtual {v1}, Lxm/e;->d()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/lang/Integer;

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    check-cast v2, Ljava/lang/Integer;

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    iget-object v2, p0, Ldn/k;->X:Lxm/f;

    .line 72
    .line 73
    if-eqz v2, :cond_0

    .line 74
    .line 75
    invoke-virtual {v2}, Lxm/e;->d()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    add-int/2addr v3, v2

    .line 86
    add-int/2addr v1, v2

    .line 87
    :cond_0
    iget p0, p0, Ldn/k;->P:I

    .line 88
    .line 89
    const/4 v2, 0x2

    .line 90
    if-ne p0, v2, :cond_1

    .line 91
    .line 92
    if-lt p1, v3, :cond_2

    .line 93
    .line 94
    if-ge p1, v1, :cond_2

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_1
    int-to-float p0, p1

    .line 98
    int-to-float p1, v0

    .line 99
    div-float/2addr p0, p1

    .line 100
    const/high16 p1, 0x42c80000    # 100.0f

    .line 101
    .line 102
    mul-float/2addr p0, p1

    .line 103
    int-to-float p1, v3

    .line 104
    cmpl-float p1, p0, p1

    .line 105
    .line 106
    if-ltz p1, :cond_2

    .line 107
    .line 108
    int-to-float p1, v1

    .line 109
    cmpg-float p0, p0, p1

    .line 110
    .line 111
    if-gez p0, :cond_2

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_2
    const/4 p0, 0x0

    .line 115
    return p0

    .line 116
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 117
    return p0
.end method

.method public final s(Landroid/graphics/Canvas;Lan/b;IF)Z
    .locals 6

    .line 1
    iget-object v0, p2, Lan/b;->l:Landroid/graphics/PointF;

    .line 2
    .line 3
    iget-object v1, p2, Lan/b;->m:Landroid/graphics/PointF;

    .line 4
    .line 5
    invoke-static {}, Lgn/h;->c()F

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const/4 v3, 0x0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    move v4, v3

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget v4, p2, Lan/b;->f:F

    .line 15
    .line 16
    mul-float/2addr v4, v2

    .line 17
    iget v5, v0, Landroid/graphics/PointF;->y:F

    .line 18
    .line 19
    add-float/2addr v4, v5

    .line 20
    :goto_0
    int-to-float p3, p3

    .line 21
    iget v5, p2, Lan/b;->f:F

    .line 22
    .line 23
    mul-float/2addr p3, v5

    .line 24
    mul-float/2addr p3, v2

    .line 25
    add-float/2addr p3, v4

    .line 26
    iget-object p0, p0, Ldn/k;->N:Lum/j;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    move p0, v3

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget p0, v0, Landroid/graphics/PointF;->x:F

    .line 36
    .line 37
    :goto_1
    if-nez v1, :cond_2

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    iget v3, v1, Landroid/graphics/PointF;->x:F

    .line 41
    .line 42
    :goto_2
    iget p2, p2, Lan/b;->d:I

    .line 43
    .line 44
    invoke-static {p2}, Lu/w;->o(I)I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    const/4 v0, 0x1

    .line 49
    if-eqz p2, :cond_5

    .line 50
    .line 51
    if-eq p2, v0, :cond_4

    .line 52
    .line 53
    const/4 v1, 0x2

    .line 54
    if-eq p2, v1, :cond_3

    .line 55
    .line 56
    return v0

    .line 57
    :cond_3
    const/high16 p2, 0x40000000    # 2.0f

    .line 58
    .line 59
    div-float/2addr v3, p2

    .line 60
    add-float/2addr v3, p0

    .line 61
    div-float/2addr p4, p2

    .line 62
    sub-float/2addr v3, p4

    .line 63
    invoke-virtual {p1, v3, p3}, Landroid/graphics/Canvas;->translate(FF)V

    .line 64
    .line 65
    .line 66
    return v0

    .line 67
    :cond_4
    add-float/2addr p0, v3

    .line 68
    sub-float/2addr p0, p4

    .line 69
    invoke-virtual {p1, p0, p3}, Landroid/graphics/Canvas;->translate(FF)V

    .line 70
    .line 71
    .line 72
    return v0

    .line 73
    :cond_5
    invoke-virtual {p1, p0, p3}, Landroid/graphics/Canvas;->translate(FF)V

    .line 74
    .line 75
    .line 76
    return v0
.end method

.method public final t(Ljava/lang/String;FLan/c;FFZ)Ljava/util/List;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move v5, v3

    .line 10
    move v7, v5

    .line 11
    move v8, v7

    .line 12
    move v9, v8

    .line 13
    move v11, v9

    .line 14
    move v6, v4

    .line 15
    move v10, v6

    .line 16
    move v12, v10

    .line 17
    :goto_0
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result v13

    .line 21
    if-ge v5, v13, :cond_7

    .line 22
    .line 23
    invoke-virtual {v1, v5}, Ljava/lang/String;->charAt(I)C

    .line 24
    .line 25
    .line 26
    move-result v13

    .line 27
    if-eqz p6, :cond_1

    .line 28
    .line 29
    iget-object v14, v2, Lan/c;->a:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v15, v2, Lan/c;->b:Ljava/lang/String;

    .line 32
    .line 33
    invoke-static {v13, v14, v15}, Lan/d;->a(CLjava/lang/String;Ljava/lang/String;)I

    .line 34
    .line 35
    .line 36
    move-result v14

    .line 37
    iget-object v15, v0, Ldn/k;->O:Lum/a;

    .line 38
    .line 39
    iget-object v15, v15, Lum/a;->h:Landroidx/collection/b1;

    .line 40
    .line 41
    invoke-virtual {v15, v14}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v14

    .line 45
    check-cast v14, Lan/d;

    .line 46
    .line 47
    if-nez v14, :cond_0

    .line 48
    .line 49
    goto/16 :goto_3

    .line 50
    .line 51
    :cond_0
    iget-wide v14, v14, Lan/d;->c:D

    .line 52
    .line 53
    double-to-float v14, v14

    .line 54
    mul-float v14, v14, p4

    .line 55
    .line 56
    invoke-static {}, Lgn/h;->c()F

    .line 57
    .line 58
    .line 59
    move-result v15

    .line 60
    mul-float/2addr v15, v14

    .line 61
    add-float v15, v15, p5

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    add-int/lit8 v14, v5, 0x1

    .line 65
    .line 66
    invoke-virtual {v1, v5, v14}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v14

    .line 70
    iget-object v15, v0, Ldn/k;->G:Ldn/i;

    .line 71
    .line 72
    invoke-virtual {v15, v14}, Landroid/graphics/Paint;->measureText(Ljava/lang/String;)F

    .line 73
    .line 74
    .line 75
    move-result v14

    .line 76
    add-float v15, v14, p5

    .line 77
    .line 78
    :goto_1
    const/16 v14, 0x20

    .line 79
    .line 80
    if-ne v13, v14, :cond_2

    .line 81
    .line 82
    const/4 v9, 0x1

    .line 83
    move v12, v15

    .line 84
    goto :goto_2

    .line 85
    :cond_2
    if-eqz v9, :cond_3

    .line 86
    .line 87
    move v9, v3

    .line 88
    move v11, v5

    .line 89
    move v10, v15

    .line 90
    goto :goto_2

    .line 91
    :cond_3
    add-float/2addr v10, v15

    .line 92
    :goto_2
    add-float/2addr v6, v15

    .line 93
    cmpl-float v16, p2, v4

    .line 94
    .line 95
    if-lez v16, :cond_6

    .line 96
    .line 97
    cmpl-float v16, v6, p2

    .line 98
    .line 99
    if-ltz v16, :cond_6

    .line 100
    .line 101
    if-ne v13, v14, :cond_4

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_4
    add-int/lit8 v7, v7, 0x1

    .line 105
    .line 106
    invoke-virtual {v0, v7}, Ldn/k;->q(I)Ldn/j;

    .line 107
    .line 108
    .line 109
    move-result-object v13

    .line 110
    if-ne v11, v8, :cond_5

    .line 111
    .line 112
    invoke-virtual {v1, v8, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v8

    .line 116
    invoke-virtual {v8}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v10

    .line 120
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 121
    .line 122
    .line 123
    move-result v11

    .line 124
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 125
    .line 126
    .line 127
    move-result v8

    .line 128
    sub-int/2addr v11, v8

    .line 129
    int-to-float v8, v11

    .line 130
    mul-float/2addr v8, v12

    .line 131
    sub-float/2addr v6, v15

    .line 132
    sub-float/2addr v6, v8

    .line 133
    iput-object v10, v13, Ldn/j;->a:Ljava/lang/String;

    .line 134
    .line 135
    iput v6, v13, Ldn/j;->b:F

    .line 136
    .line 137
    move v8, v5

    .line 138
    move v11, v8

    .line 139
    move v6, v15

    .line 140
    move v10, v6

    .line 141
    goto :goto_3

    .line 142
    :cond_5
    add-int/lit8 v14, v11, -0x1

    .line 143
    .line 144
    invoke-virtual {v1, v8, v14}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    invoke-virtual {v8}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v14

    .line 152
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 153
    .line 154
    .line 155
    move-result v8

    .line 156
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 157
    .line 158
    .line 159
    move-result v15

    .line 160
    sub-int/2addr v8, v15

    .line 161
    int-to-float v8, v8

    .line 162
    mul-float/2addr v8, v12

    .line 163
    sub-float/2addr v6, v10

    .line 164
    sub-float/2addr v6, v8

    .line 165
    sub-float/2addr v6, v12

    .line 166
    iput-object v14, v13, Ldn/j;->a:Ljava/lang/String;

    .line 167
    .line 168
    iput v6, v13, Ldn/j;->b:F

    .line 169
    .line 170
    move v6, v10

    .line 171
    move v8, v11

    .line 172
    :cond_6
    :goto_3
    add-int/lit8 v5, v5, 0x1

    .line 173
    .line 174
    goto/16 :goto_0

    .line 175
    .line 176
    :cond_7
    cmpl-float v2, v6, v4

    .line 177
    .line 178
    if-lez v2, :cond_8

    .line 179
    .line 180
    add-int/lit8 v7, v7, 0x1

    .line 181
    .line 182
    invoke-virtual {v0, v7}, Ldn/k;->q(I)Ldn/j;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    invoke-virtual {v1, v8}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    iput-object v1, v2, Ldn/j;->a:Ljava/lang/String;

    .line 191
    .line 192
    iput v6, v2, Ldn/j;->b:F

    .line 193
    .line 194
    :cond_8
    iget-object v0, v0, Ldn/k;->L:Ljava/util/ArrayList;

    .line 195
    .line 196
    invoke-virtual {v0, v3, v7}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    return-object v0
.end method
