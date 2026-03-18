.class public final Lh/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/s;
.implements Ll/w;


# instance fields
.field public final synthetic d:Lh/z;


# direct methods
.method public synthetic constructor <init>(Lh/z;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh/p;->d:Lh/z;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public d(Ll/l;Z)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Ll/l;->k()Ll/l;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eq v0, p1, :cond_0

    .line 8
    .line 9
    move v3, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v3, v1

    .line 12
    :goto_0
    if-eqz v3, :cond_1

    .line 13
    .line 14
    move-object p1, v0

    .line 15
    :cond_1
    iget-object p0, p0, Lh/p;->d:Lh/z;

    .line 16
    .line 17
    iget-object v4, p0, Lh/z;->O:[Lh/y;

    .line 18
    .line 19
    if-eqz v4, :cond_2

    .line 20
    .line 21
    array-length v5, v4

    .line 22
    goto :goto_1

    .line 23
    :cond_2
    move v5, v1

    .line 24
    :goto_1
    if-ge v1, v5, :cond_4

    .line 25
    .line 26
    aget-object v6, v4, v1

    .line 27
    .line 28
    if-eqz v6, :cond_3

    .line 29
    .line 30
    iget-object v7, v6, Lh/y;->h:Ll/l;

    .line 31
    .line 32
    if-ne v7, p1, :cond_3

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_4
    const/4 v6, 0x0

    .line 39
    :goto_2
    if-eqz v6, :cond_6

    .line 40
    .line 41
    if-eqz v3, :cond_5

    .line 42
    .line 43
    iget p1, v6, Lh/y;->a:I

    .line 44
    .line 45
    invoke-virtual {p0, p1, v6, v0}, Lh/z;->u(ILh/y;Ll/l;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, v6, v2}, Lh/z;->w(Lh/y;Z)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_5
    invoke-virtual {p0, v6, p2}, Lh/z;->w(Lh/y;Z)V

    .line 53
    .line 54
    .line 55
    :cond_6
    return-void
.end method

.method public f(Ll/l;)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Ll/l;->k()Ll/l;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lh/p;->d:Lh/z;

    .line 8
    .line 9
    iget-boolean v0, p0, Lh/z;->I:Z

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lh/z;->o:Landroid/view/Window;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroid/view/Window;->getCallback()Landroid/view/Window$Callback;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-boolean p0, p0, Lh/z;->T:Z

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    const/16 p0, 0x6c

    .line 26
    .line 27
    invoke-interface {v0, p0, p1}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    .line 28
    .line 29
    .line 30
    :cond_0
    const/4 p0, 0x1

    .line 31
    return p0
.end method

.method public onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    invoke-virtual {v1}, Ld6/w1;->d()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    move-object/from16 v3, p0

    .line 10
    .line 11
    iget-object v3, v3, Lh/p;->d:Lh/z;

    .line 12
    .line 13
    iget-object v4, v3, Lh/z;->n:Landroid/content/Context;

    .line 14
    .line 15
    invoke-virtual {v1}, Ld6/w1;->d()I

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    iget-object v6, v3, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 20
    .line 21
    const/16 v7, 0x8

    .line 22
    .line 23
    const/4 v8, 0x0

    .line 24
    if-eqz v6, :cond_e

    .line 25
    .line 26
    invoke-virtual {v6}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    instance-of v6, v6, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 31
    .line 32
    if-eqz v6, :cond_e

    .line 33
    .line 34
    iget-object v6, v3, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 35
    .line 36
    invoke-virtual {v6}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    check-cast v6, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 41
    .line 42
    iget-object v9, v3, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 43
    .line 44
    invoke-virtual {v9}, Landroid/view/View;->isShown()Z

    .line 45
    .line 46
    .line 47
    move-result v9

    .line 48
    const/4 v10, 0x1

    .line 49
    if-eqz v9, :cond_c

    .line 50
    .line 51
    iget-object v9, v3, Lh/z;->f0:Landroid/graphics/Rect;

    .line 52
    .line 53
    if-nez v9, :cond_0

    .line 54
    .line 55
    new-instance v9, Landroid/graphics/Rect;

    .line 56
    .line 57
    invoke-direct {v9}, Landroid/graphics/Rect;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object v9, v3, Lh/z;->f0:Landroid/graphics/Rect;

    .line 61
    .line 62
    new-instance v9, Landroid/graphics/Rect;

    .line 63
    .line 64
    invoke-direct {v9}, Landroid/graphics/Rect;-><init>()V

    .line 65
    .line 66
    .line 67
    iput-object v9, v3, Lh/z;->g0:Landroid/graphics/Rect;

    .line 68
    .line 69
    :cond_0
    iget-object v9, v3, Lh/z;->f0:Landroid/graphics/Rect;

    .line 70
    .line 71
    iget-object v11, v3, Lh/z;->g0:Landroid/graphics/Rect;

    .line 72
    .line 73
    invoke-virtual {v1}, Ld6/w1;->b()I

    .line 74
    .line 75
    .line 76
    move-result v12

    .line 77
    invoke-virtual {v1}, Ld6/w1;->d()I

    .line 78
    .line 79
    .line 80
    move-result v13

    .line 81
    invoke-virtual {v1}, Ld6/w1;->c()I

    .line 82
    .line 83
    .line 84
    move-result v14

    .line 85
    invoke-virtual {v1}, Ld6/w1;->a()I

    .line 86
    .line 87
    .line 88
    move-result v15

    .line 89
    invoke-virtual {v9, v12, v13, v14, v15}, Landroid/graphics/Rect;->set(IIII)V

    .line 90
    .line 91
    .line 92
    iget-object v12, v3, Lh/z;->D:Landroid/view/ViewGroup;

    .line 93
    .line 94
    invoke-static {v12, v9, v11}, Lm/a3;->a(Landroid/view/View;Landroid/graphics/Rect;Landroid/graphics/Rect;)V

    .line 95
    .line 96
    .line 97
    iget v11, v9, Landroid/graphics/Rect;->top:I

    .line 98
    .line 99
    iget v12, v9, Landroid/graphics/Rect;->left:I

    .line 100
    .line 101
    iget v9, v9, Landroid/graphics/Rect;->right:I

    .line 102
    .line 103
    iget-object v13, v3, Lh/z;->D:Landroid/view/ViewGroup;

    .line 104
    .line 105
    sget-object v14, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 106
    .line 107
    invoke-static {v13}, Ld6/l0;->a(Landroid/view/View;)Ld6/w1;

    .line 108
    .line 109
    .line 110
    move-result-object v13

    .line 111
    if-nez v13, :cond_1

    .line 112
    .line 113
    move v14, v8

    .line 114
    goto :goto_0

    .line 115
    :cond_1
    invoke-virtual {v13}, Ld6/w1;->b()I

    .line 116
    .line 117
    .line 118
    move-result v14

    .line 119
    :goto_0
    if-nez v13, :cond_2

    .line 120
    .line 121
    move v13, v8

    .line 122
    goto :goto_1

    .line 123
    :cond_2
    invoke-virtual {v13}, Ld6/w1;->c()I

    .line 124
    .line 125
    .line 126
    move-result v13

    .line 127
    :goto_1
    iget v15, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 128
    .line 129
    if-ne v15, v11, :cond_4

    .line 130
    .line 131
    iget v15, v6, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 132
    .line 133
    if-ne v15, v12, :cond_4

    .line 134
    .line 135
    iget v15, v6, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 136
    .line 137
    if-eq v15, v9, :cond_3

    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_3
    move v9, v8

    .line 141
    goto :goto_3

    .line 142
    :cond_4
    :goto_2
    iput v11, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 143
    .line 144
    iput v12, v6, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 145
    .line 146
    iput v9, v6, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 147
    .line 148
    move v9, v10

    .line 149
    :goto_3
    if-lez v11, :cond_5

    .line 150
    .line 151
    iget-object v11, v3, Lh/z;->F:Landroid/view/View;

    .line 152
    .line 153
    if-nez v11, :cond_5

    .line 154
    .line 155
    new-instance v11, Landroid/view/View;

    .line 156
    .line 157
    invoke-direct {v11, v4}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    .line 158
    .line 159
    .line 160
    iput-object v11, v3, Lh/z;->F:Landroid/view/View;

    .line 161
    .line 162
    invoke-virtual {v11, v7}, Landroid/view/View;->setVisibility(I)V

    .line 163
    .line 164
    .line 165
    new-instance v11, Landroid/widget/FrameLayout$LayoutParams;

    .line 166
    .line 167
    iget v12, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 168
    .line 169
    const/16 v15, 0x33

    .line 170
    .line 171
    const/4 v7, -0x1

    .line 172
    invoke-direct {v11, v7, v12, v15}, Landroid/widget/FrameLayout$LayoutParams;-><init>(III)V

    .line 173
    .line 174
    .line 175
    iput v14, v11, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I

    .line 176
    .line 177
    iput v13, v11, Landroid/widget/FrameLayout$LayoutParams;->rightMargin:I

    .line 178
    .line 179
    iget-object v12, v3, Lh/z;->D:Landroid/view/ViewGroup;

    .line 180
    .line 181
    iget-object v13, v3, Lh/z;->F:Landroid/view/View;

    .line 182
    .line 183
    invoke-virtual {v12, v13, v7, v11}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    .line 184
    .line 185
    .line 186
    goto :goto_4

    .line 187
    :cond_5
    iget-object v7, v3, Lh/z;->F:Landroid/view/View;

    .line 188
    .line 189
    if-eqz v7, :cond_7

    .line 190
    .line 191
    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 192
    .line 193
    .line 194
    move-result-object v7

    .line 195
    check-cast v7, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 196
    .line 197
    iget v11, v7, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 198
    .line 199
    iget v12, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 200
    .line 201
    if-ne v11, v12, :cond_6

    .line 202
    .line 203
    iget v11, v7, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 204
    .line 205
    if-ne v11, v14, :cond_6

    .line 206
    .line 207
    iget v11, v7, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 208
    .line 209
    if-eq v11, v13, :cond_7

    .line 210
    .line 211
    :cond_6
    iput v12, v7, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 212
    .line 213
    iput v14, v7, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 214
    .line 215
    iput v13, v7, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 216
    .line 217
    iget-object v11, v3, Lh/z;->F:Landroid/view/View;

    .line 218
    .line 219
    invoke-virtual {v11, v7}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 220
    .line 221
    .line 222
    :cond_7
    :goto_4
    iget-object v7, v3, Lh/z;->F:Landroid/view/View;

    .line 223
    .line 224
    if-eqz v7, :cond_8

    .line 225
    .line 226
    goto :goto_5

    .line 227
    :cond_8
    move v10, v8

    .line 228
    :goto_5
    if-eqz v10, :cond_a

    .line 229
    .line 230
    invoke-virtual {v7}, Landroid/view/View;->getVisibility()I

    .line 231
    .line 232
    .line 233
    move-result v7

    .line 234
    if-eqz v7, :cond_a

    .line 235
    .line 236
    iget-object v7, v3, Lh/z;->F:Landroid/view/View;

    .line 237
    .line 238
    invoke-virtual {v7}, Landroid/view/View;->getWindowSystemUiVisibility()I

    .line 239
    .line 240
    .line 241
    move-result v11

    .line 242
    and-int/lit16 v11, v11, 0x2000

    .line 243
    .line 244
    if-eqz v11, :cond_9

    .line 245
    .line 246
    const v11, 0x7f060006

    .line 247
    .line 248
    .line 249
    invoke-virtual {v4, v11}, Landroid/content/Context;->getColor(I)I

    .line 250
    .line 251
    .line 252
    move-result v4

    .line 253
    goto :goto_6

    .line 254
    :cond_9
    const v11, 0x7f060005

    .line 255
    .line 256
    .line 257
    invoke-virtual {v4, v11}, Landroid/content/Context;->getColor(I)I

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    :goto_6
    invoke-virtual {v7, v4}, Landroid/view/View;->setBackgroundColor(I)V

    .line 262
    .line 263
    .line 264
    :cond_a
    iget-boolean v4, v3, Lh/z;->K:Z

    .line 265
    .line 266
    if-nez v4, :cond_b

    .line 267
    .line 268
    if-eqz v10, :cond_b

    .line 269
    .line 270
    move v5, v8

    .line 271
    :cond_b
    move v4, v10

    .line 272
    move v10, v9

    .line 273
    goto :goto_7

    .line 274
    :cond_c
    iget v4, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 275
    .line 276
    if-eqz v4, :cond_d

    .line 277
    .line 278
    iput v8, v6, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 279
    .line 280
    move v4, v8

    .line 281
    goto :goto_7

    .line 282
    :cond_d
    move v4, v8

    .line 283
    move v10, v4

    .line 284
    :goto_7
    if-eqz v10, :cond_f

    .line 285
    .line 286
    iget-object v7, v3, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 287
    .line 288
    invoke-virtual {v7, v6}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 289
    .line 290
    .line 291
    goto :goto_8

    .line 292
    :cond_e
    move v4, v8

    .line 293
    :cond_f
    :goto_8
    iget-object v3, v3, Lh/z;->F:Landroid/view/View;

    .line 294
    .line 295
    if-eqz v3, :cond_11

    .line 296
    .line 297
    if-eqz v4, :cond_10

    .line 298
    .line 299
    move v7, v8

    .line 300
    goto :goto_9

    .line 301
    :cond_10
    const/16 v7, 0x8

    .line 302
    .line 303
    :goto_9
    invoke-virtual {v3, v7}, Landroid/view/View;->setVisibility(I)V

    .line 304
    .line 305
    .line 306
    :cond_11
    if-eq v2, v5, :cond_15

    .line 307
    .line 308
    invoke-virtual {v1}, Ld6/w1;->b()I

    .line 309
    .line 310
    .line 311
    move-result v2

    .line 312
    invoke-virtual {v1}, Ld6/w1;->c()I

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    invoke-virtual {v1}, Ld6/w1;->a()I

    .line 317
    .line 318
    .line 319
    move-result v4

    .line 320
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 321
    .line 322
    const/16 v7, 0x22

    .line 323
    .line 324
    if-lt v6, v7, :cond_12

    .line 325
    .line 326
    new-instance v6, Ld6/j1;

    .line 327
    .line 328
    invoke-direct {v6, v1}, Ld6/j1;-><init>(Ld6/w1;)V

    .line 329
    .line 330
    .line 331
    goto :goto_a

    .line 332
    :cond_12
    const/16 v7, 0x1f

    .line 333
    .line 334
    if-lt v6, v7, :cond_13

    .line 335
    .line 336
    new-instance v6, Ld6/i1;

    .line 337
    .line 338
    invoke-direct {v6, v1}, Ld6/i1;-><init>(Ld6/w1;)V

    .line 339
    .line 340
    .line 341
    goto :goto_a

    .line 342
    :cond_13
    const/16 v7, 0x1e

    .line 343
    .line 344
    if-lt v6, v7, :cond_14

    .line 345
    .line 346
    new-instance v6, Ld6/h1;

    .line 347
    .line 348
    invoke-direct {v6, v1}, Ld6/h1;-><init>(Ld6/w1;)V

    .line 349
    .line 350
    .line 351
    goto :goto_a

    .line 352
    :cond_14
    new-instance v6, Ld6/g1;

    .line 353
    .line 354
    invoke-direct {v6, v1}, Ld6/g1;-><init>(Ld6/w1;)V

    .line 355
    .line 356
    .line 357
    :goto_a
    invoke-static {v2, v5, v3, v4}, Ls5/b;->b(IIII)Ls5/b;

    .line 358
    .line 359
    .line 360
    move-result-object v1

    .line 361
    invoke-virtual {v6, v1}, Ld6/g1;->g(Ls5/b;)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {v6}, Ld6/g1;->b()Ld6/w1;

    .line 365
    .line 366
    .line 367
    move-result-object v1

    .line 368
    :cond_15
    sget-object v2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 369
    .line 370
    invoke-virtual {v1}, Ld6/w1;->g()Landroid/view/WindowInsets;

    .line 371
    .line 372
    .line 373
    move-result-object v2

    .line 374
    if-eqz v2, :cond_16

    .line 375
    .line 376
    invoke-static {v0, v2}, Ld6/i0;->b(Landroid/view/View;Landroid/view/WindowInsets;)Landroid/view/WindowInsets;

    .line 377
    .line 378
    .line 379
    move-result-object v3

    .line 380
    invoke-virtual {v3, v2}, Landroid/view/WindowInsets;->equals(Ljava/lang/Object;)Z

    .line 381
    .line 382
    .line 383
    move-result v2

    .line 384
    if-nez v2, :cond_16

    .line 385
    .line 386
    invoke-static {v0, v3}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 387
    .line 388
    .line 389
    move-result-object v0

    .line 390
    return-object v0

    .line 391
    :cond_16
    return-object v1
.end method
