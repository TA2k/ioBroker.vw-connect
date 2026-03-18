.class final Lcom/google/android/material/datepicker/MaterialCalendarGridView;
.super Landroid/widget/GridView;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/util/Calendar;

.field public final e:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0}, Landroid/widget/GridView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 3
    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-static {p1}, Lcom/google/android/material/datepicker/n0;->g(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->d:Ljava/util/Calendar;

    .line 11
    .line 12
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const p2, 0x101020d

    .line 17
    .line 18
    .line 19
    invoke-static {p1, p2}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    const p1, 0x7f0a0073

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Landroid/view/View;->setNextFocusLeftId(I)V

    .line 29
    .line 30
    .line 31
    const p1, 0x7f0a00eb

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1}, Landroid/view/View;->setNextFocusRightId(I)V

    .line 35
    .line 36
    .line 37
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    const p2, 0x7f040419

    .line 42
    .line 43
    .line 44
    invoke-static {p1, p2}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    iput-boolean p1, p0, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->e:Z

    .line 49
    .line 50
    new-instance p1, Lcom/google/android/material/datepicker/o;

    .line 51
    .line 52
    const/4 p2, 0x2

    .line 53
    invoke-direct {p1, p2}, Lcom/google/android/material/datepicker/o;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-static {p0, p1}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 57
    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a()Lcom/google/android/material/datepicker/c0;
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lcom/google/android/material/datepicker/c0;

    .line 6
    .line 7
    return-object p0
.end method

.method public final b(I)Landroid/view/View;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/widget/AdapterView;->getFirstVisiblePosition()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sub-int/2addr p1, v0

    .line 6
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final getAdapter()Landroid/widget/Adapter;
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    move-result-object p0

    check-cast p0, Lcom/google/android/material/datepicker/c0;

    return-object p0
.end method

.method public final getAdapter()Landroid/widget/ListAdapter;
    .locals 0

    .line 2
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    move-result-object p0

    check-cast p0, Lcom/google/android/material/datepicker/c0;

    return-object p0
.end method

.method public final onAttachedToWindow()V
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/view/View;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    check-cast p0, Lcom/google/android/material/datepicker/c0;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/widget/BaseAdapter;->notifyDataSetChanged()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final onDraw(Landroid/graphics/Canvas;)V
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-super/range {p0 .. p1}, Landroid/view/View;->onDraw(Landroid/graphics/Canvas;)V

    .line 4
    .line 5
    .line 6
    invoke-super {v0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Lcom/google/android/material/datepicker/c0;

    .line 11
    .line 12
    iget-object v2, v1, Lcom/google/android/material/datepicker/c0;->b:Lcom/google/android/material/datepicker/i;

    .line 13
    .line 14
    iget-object v3, v1, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 15
    .line 16
    iget-object v4, v1, Lcom/google/android/material/datepicker/c0;->d:Lcom/google/android/material/datepicker/d;

    .line 17
    .line 18
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    invoke-virtual {v0}, Landroid/widget/AdapterView;->getFirstVisiblePosition()I

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    invoke-static {v5, v6}, Ljava/lang/Math;->max(II)I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->c()I

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    invoke-virtual {v0}, Landroid/widget/AdapterView;->getLastVisiblePosition()I

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    invoke-static {v6, v7}, Ljava/lang/Math;->min(II)I

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    invoke-virtual {v1, v5}, Lcom/google/android/material/datepicker/c0;->b(I)Ljava/lang/Long;

    .line 43
    .line 44
    .line 45
    move-result-object v7

    .line 46
    invoke-virtual {v1, v6}, Lcom/google/android/material/datepicker/c0;->b(I)Ljava/lang/Long;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    invoke-interface {v2}, Lcom/google/android/material/datepicker/i;->V()Ljava/util/ArrayList;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 59
    .line 60
    .line 61
    move-result v9

    .line 62
    if-eqz v9, :cond_11

    .line 63
    .line 64
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    check-cast v9, Lc6/b;

    .line 69
    .line 70
    iget-object v10, v9, Lc6/b;->a:Ljava/lang/Object;

    .line 71
    .line 72
    iget-object v9, v9, Lc6/b;->b:Ljava/lang/Object;

    .line 73
    .line 74
    if-eqz v10, :cond_10

    .line 75
    .line 76
    if-nez v9, :cond_0

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_0
    check-cast v10, Ljava/lang/Long;

    .line 80
    .line 81
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 82
    .line 83
    .line 84
    move-result-wide v11

    .line 85
    check-cast v9, Ljava/lang/Long;

    .line 86
    .line 87
    invoke-virtual {v9}, Ljava/lang/Long;->longValue()J

    .line 88
    .line 89
    .line 90
    move-result-wide v13

    .line 91
    if-eqz v7, :cond_1

    .line 92
    .line 93
    if-eqz v8, :cond_1

    .line 94
    .line 95
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 96
    .line 97
    .line 98
    move-result-wide v15

    .line 99
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 100
    .line 101
    .line 102
    move-result-wide v17

    .line 103
    cmp-long v10, v15, v17

    .line 104
    .line 105
    if-gtz v10, :cond_1

    .line 106
    .line 107
    invoke-virtual {v9}, Ljava/lang/Long;->longValue()J

    .line 108
    .line 109
    .line 110
    move-result-wide v9

    .line 111
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 112
    .line 113
    .line 114
    move-result-wide v15

    .line 115
    cmp-long v9, v9, v15

    .line 116
    .line 117
    if-gez v9, :cond_2

    .line 118
    .line 119
    :cond_1
    move-object/from16 v20, v1

    .line 120
    .line 121
    move-object/from16 v16, v2

    .line 122
    .line 123
    move-object v15, v3

    .line 124
    goto/16 :goto_b

    .line 125
    .line 126
    :cond_2
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 127
    .line 128
    .line 129
    move-result v9

    .line 130
    const/4 v15, 0x1

    .line 131
    if-ne v9, v15, :cond_3

    .line 132
    .line 133
    move v9, v15

    .line 134
    goto :goto_1

    .line 135
    :cond_3
    const/4 v9, 0x0

    .line 136
    :goto_1
    invoke-virtual {v7}, Ljava/lang/Long;->longValue()J

    .line 137
    .line 138
    .line 139
    move-result-wide v16

    .line 140
    cmp-long v16, v11, v16

    .line 141
    .line 142
    const/4 v10, 0x5

    .line 143
    move/from16 v18, v15

    .line 144
    .line 145
    iget-object v15, v0, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->d:Ljava/util/Calendar;

    .line 146
    .line 147
    if-gez v16, :cond_6

    .line 148
    .line 149
    iget v11, v3, Lcom/google/android/material/datepicker/b0;->g:I

    .line 150
    .line 151
    rem-int v11, v5, v11

    .line 152
    .line 153
    if-nez v11, :cond_4

    .line 154
    .line 155
    const/4 v11, 0x0

    .line 156
    goto :goto_2

    .line 157
    :cond_4
    if-nez v9, :cond_5

    .line 158
    .line 159
    add-int/lit8 v11, v5, -0x1

    .line 160
    .line 161
    invoke-virtual {v0, v11}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 162
    .line 163
    .line 164
    move-result-object v11

    .line 165
    invoke-virtual {v11}, Landroid/view/View;->getRight()I

    .line 166
    .line 167
    .line 168
    move-result v11

    .line 169
    goto :goto_2

    .line 170
    :cond_5
    add-int/lit8 v11, v5, -0x1

    .line 171
    .line 172
    invoke-virtual {v0, v11}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 173
    .line 174
    .line 175
    move-result-object v11

    .line 176
    invoke-virtual {v11}, Landroid/view/View;->getLeft()I

    .line 177
    .line 178
    .line 179
    move-result v11

    .line 180
    :goto_2
    move v12, v5

    .line 181
    goto :goto_3

    .line 182
    :cond_6
    invoke-virtual {v15, v11, v12}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v15, v10}, Ljava/util/Calendar;->get(I)I

    .line 186
    .line 187
    .line 188
    move-result v11

    .line 189
    add-int/lit8 v11, v11, -0x1

    .line 190
    .line 191
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 192
    .line 193
    .line 194
    move-result v12

    .line 195
    add-int/2addr v12, v11

    .line 196
    invoke-virtual {v0, v12}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 197
    .line 198
    .line 199
    move-result-object v11

    .line 200
    invoke-virtual {v11}, Landroid/view/View;->getLeft()I

    .line 201
    .line 202
    .line 203
    move-result v16

    .line 204
    invoke-virtual {v11}, Landroid/view/View;->getWidth()I

    .line 205
    .line 206
    .line 207
    move-result v11

    .line 208
    div-int/lit8 v11, v11, 0x2

    .line 209
    .line 210
    add-int v11, v11, v16

    .line 211
    .line 212
    :goto_3
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 213
    .line 214
    .line 215
    move-result-wide v19

    .line 216
    cmp-long v16, v13, v19

    .line 217
    .line 218
    if-lez v16, :cond_9

    .line 219
    .line 220
    add-int/lit8 v10, v6, 0x1

    .line 221
    .line 222
    iget v13, v3, Lcom/google/android/material/datepicker/b0;->g:I

    .line 223
    .line 224
    rem-int/2addr v10, v13

    .line 225
    if-nez v10, :cond_7

    .line 226
    .line 227
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 228
    .line 229
    .line 230
    move-result v10

    .line 231
    goto :goto_4

    .line 232
    :cond_7
    if-nez v9, :cond_8

    .line 233
    .line 234
    invoke-virtual {v0, v6}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 235
    .line 236
    .line 237
    move-result-object v10

    .line 238
    invoke-virtual {v10}, Landroid/view/View;->getRight()I

    .line 239
    .line 240
    .line 241
    move-result v10

    .line 242
    goto :goto_4

    .line 243
    :cond_8
    invoke-virtual {v0, v6}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 244
    .line 245
    .line 246
    move-result-object v10

    .line 247
    invoke-virtual {v10}, Landroid/view/View;->getLeft()I

    .line 248
    .line 249
    .line 250
    move-result v10

    .line 251
    :goto_4
    move v13, v6

    .line 252
    goto :goto_5

    .line 253
    :cond_9
    invoke-virtual {v15, v13, v14}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v15, v10}, Ljava/util/Calendar;->get(I)I

    .line 257
    .line 258
    .line 259
    move-result v10

    .line 260
    add-int/lit8 v10, v10, -0x1

    .line 261
    .line 262
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 263
    .line 264
    .line 265
    move-result v13

    .line 266
    add-int/2addr v13, v10

    .line 267
    invoke-virtual {v0, v13}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 268
    .line 269
    .line 270
    move-result-object v10

    .line 271
    invoke-virtual {v10}, Landroid/view/View;->getLeft()I

    .line 272
    .line 273
    .line 274
    move-result v14

    .line 275
    invoke-virtual {v10}, Landroid/view/View;->getWidth()I

    .line 276
    .line 277
    .line 278
    move-result v10

    .line 279
    div-int/lit8 v10, v10, 0x2

    .line 280
    .line 281
    add-int/2addr v10, v14

    .line 282
    :goto_5
    invoke-virtual {v1, v12}, Lcom/google/android/material/datepicker/c0;->getItemId(I)J

    .line 283
    .line 284
    .line 285
    move-result-wide v14

    .line 286
    long-to-int v14, v14

    .line 287
    move-object/from16 v16, v2

    .line 288
    .line 289
    move-object v15, v3

    .line 290
    invoke-virtual {v1, v13}, Lcom/google/android/material/datepicker/c0;->getItemId(I)J

    .line 291
    .line 292
    .line 293
    move-result-wide v2

    .line 294
    long-to-int v2, v2

    .line 295
    :goto_6
    if-gt v14, v2, :cond_f

    .line 296
    .line 297
    invoke-virtual {v0}, Landroid/widget/GridView;->getNumColumns()I

    .line 298
    .line 299
    .line 300
    move-result v3

    .line 301
    mul-int/2addr v3, v14

    .line 302
    invoke-virtual {v0}, Landroid/widget/GridView;->getNumColumns()I

    .line 303
    .line 304
    .line 305
    move-result v19

    .line 306
    add-int v19, v19, v3

    .line 307
    .line 308
    move-object/from16 v20, v1

    .line 309
    .line 310
    add-int/lit8 v1, v19, -0x1

    .line 311
    .line 312
    invoke-virtual {v0, v3}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->b(I)Landroid/view/View;

    .line 313
    .line 314
    .line 315
    move-result-object v19

    .line 316
    invoke-virtual/range {v19 .. v19}, Landroid/view/View;->getTop()I

    .line 317
    .line 318
    .line 319
    move-result v21

    .line 320
    iget-object v0, v4, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 321
    .line 322
    check-cast v0, Lca/j;

    .line 323
    .line 324
    iget-object v0, v0, Lca/j;->b:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast v0, Landroid/graphics/Rect;

    .line 327
    .line 328
    iget v0, v0, Landroid/graphics/Rect;->top:I

    .line 329
    .line 330
    add-int v0, v21, v0

    .line 331
    .line 332
    invoke-virtual/range {v19 .. v19}, Landroid/view/View;->getBottom()I

    .line 333
    .line 334
    .line 335
    move-result v19

    .line 336
    move/from16 v21, v2

    .line 337
    .line 338
    iget-object v2, v4, Lcom/google/android/material/datepicker/d;->a:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v2, Lca/j;

    .line 341
    .line 342
    iget-object v2, v2, Lca/j;->b:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast v2, Landroid/graphics/Rect;

    .line 345
    .line 346
    iget v2, v2, Landroid/graphics/Rect;->bottom:I

    .line 347
    .line 348
    sub-int v2, v19, v2

    .line 349
    .line 350
    if-nez v9, :cond_c

    .line 351
    .line 352
    if-le v3, v12, :cond_a

    .line 353
    .line 354
    const/4 v3, 0x0

    .line 355
    goto :goto_7

    .line 356
    :cond_a
    move v3, v11

    .line 357
    :goto_7
    if-le v13, v1, :cond_b

    .line 358
    .line 359
    invoke-virtual/range {p0 .. p0}, Landroid/view/View;->getWidth()I

    .line 360
    .line 361
    .line 362
    move-result v1

    .line 363
    goto :goto_a

    .line 364
    :cond_b
    move v1, v10

    .line 365
    goto :goto_a

    .line 366
    :cond_c
    if-le v13, v1, :cond_d

    .line 367
    .line 368
    const/4 v1, 0x0

    .line 369
    goto :goto_8

    .line 370
    :cond_d
    move v1, v10

    .line 371
    :goto_8
    if-le v3, v12, :cond_e

    .line 372
    .line 373
    invoke-virtual/range {p0 .. p0}, Landroid/view/View;->getWidth()I

    .line 374
    .line 375
    .line 376
    move-result v3

    .line 377
    goto :goto_9

    .line 378
    :cond_e
    move v3, v11

    .line 379
    :goto_9
    move/from16 v28, v3

    .line 380
    .line 381
    move v3, v1

    .line 382
    move/from16 v1, v28

    .line 383
    .line 384
    :goto_a
    int-to-float v3, v3

    .line 385
    int-to-float v0, v0

    .line 386
    int-to-float v1, v1

    .line 387
    int-to-float v2, v2

    .line 388
    move/from16 v24, v0

    .line 389
    .line 390
    iget-object v0, v4, Lcom/google/android/material/datepicker/d;->h:Ljava/lang/Object;

    .line 391
    .line 392
    move-object/from16 v27, v0

    .line 393
    .line 394
    check-cast v27, Landroid/graphics/Paint;

    .line 395
    .line 396
    move-object/from16 v22, p1

    .line 397
    .line 398
    move/from16 v25, v1

    .line 399
    .line 400
    move/from16 v26, v2

    .line 401
    .line 402
    move/from16 v23, v3

    .line 403
    .line 404
    invoke-virtual/range {v22 .. v27}, Landroid/graphics/Canvas;->drawRect(FFFFLandroid/graphics/Paint;)V

    .line 405
    .line 406
    .line 407
    add-int/lit8 v14, v14, 0x1

    .line 408
    .line 409
    move-object/from16 v0, p0

    .line 410
    .line 411
    move-object/from16 v1, v20

    .line 412
    .line 413
    move/from16 v2, v21

    .line 414
    .line 415
    goto :goto_6

    .line 416
    :cond_f
    move-object/from16 v0, p0

    .line 417
    .line 418
    move-object v3, v15

    .line 419
    move-object/from16 v2, v16

    .line 420
    .line 421
    goto/16 :goto_0

    .line 422
    .line 423
    :goto_b
    move-object/from16 v0, p0

    .line 424
    .line 425
    move-object v3, v15

    .line 426
    move-object/from16 v2, v16

    .line 427
    .line 428
    move-object/from16 v1, v20

    .line 429
    .line 430
    goto/16 :goto_0

    .line 431
    .line 432
    :cond_10
    move-object/from16 v0, p0

    .line 433
    .line 434
    goto/16 :goto_0

    .line 435
    .line 436
    :cond_11
    return-void
.end method

.method public final onFocusChanged(ZILandroid/graphics/Rect;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    const/16 p1, 0x21

    .line 4
    .line 5
    if-ne p2, p1, :cond_0

    .line 6
    .line 7
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    check-cast p1, Lcom/google/android/material/datepicker/c0;

    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/c0;->c()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->setSelection(I)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    const/16 p1, 0x82

    .line 22
    .line 23
    if-ne p2, p1, :cond_1

    .line 24
    .line 25
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p1, Lcom/google/android/material/datepicker/c0;

    .line 30
    .line 31
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->setSelection(I)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    const/4 p1, 0x1

    .line 40
    invoke-super {p0, p1, p2, p3}, Landroid/widget/GridView;->onFocusChanged(ZILandroid/graphics/Rect;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    const/4 p1, 0x0

    .line 45
    invoke-super {p0, p1, p2, p3}, Landroid/widget/GridView;->onFocusChanged(ZILandroid/graphics/Rect;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public final onKeyDown(ILandroid/view/KeyEvent;)Z
    .locals 3

    .line 1
    invoke-super {p0, p1, p2}, Landroid/widget/GridView;->onKeyDown(ILandroid/view/KeyEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p2, :cond_0

    .line 7
    .line 8
    return v0

    .line 9
    :cond_0
    invoke-virtual {p0}, Landroid/widget/AdapterView;->getSelectedItemPosition()I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    const/4 v1, -0x1

    .line 14
    const/4 v2, 0x1

    .line 15
    if-eq p2, v1, :cond_3

    .line 16
    .line 17
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lcom/google/android/material/datepicker/c0;

    .line 22
    .line 23
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-lt p2, v1, :cond_1

    .line 28
    .line 29
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lcom/google/android/material/datepicker/c0;

    .line 34
    .line 35
    invoke-virtual {v1}, Lcom/google/android/material/datepicker/c0;->c()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-gt p2, v1, :cond_1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    const/16 p2, 0x13

    .line 43
    .line 44
    if-ne p2, p1, :cond_2

    .line 45
    .line 46
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    check-cast p1, Lcom/google/android/material/datepicker/c0;

    .line 51
    .line 52
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->setSelection(I)V

    .line 57
    .line 58
    .line 59
    return v2

    .line 60
    :cond_2
    return v0

    .line 61
    :cond_3
    :goto_0
    return v2
.end method

.method public final onMeasure(II)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const p2, 0xffffff

    .line 6
    .line 7
    .line 8
    const/high16 v0, -0x80000000

    .line 9
    .line 10
    invoke-static {p2, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    invoke-super {p0, p1, p2}, Landroid/widget/GridView;->onMeasure(II)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredHeight()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    iput p0, p1, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    invoke-super {p0, p1, p2}, Landroid/widget/GridView;->onMeasure(II)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public final bridge synthetic setAdapter(Landroid/widget/Adapter;)V
    .locals 0

    .line 1
    check-cast p1, Landroid/widget/ListAdapter;

    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->setAdapter(Landroid/widget/ListAdapter;)V

    return-void
.end method

.method public final setAdapter(Landroid/widget/ListAdapter;)V
    .locals 1

    .line 2
    instance-of v0, p1, Lcom/google/android/material/datepicker/c0;

    if-eqz v0, :cond_0

    .line 3
    invoke-super {p0, p1}, Landroid/widget/GridView;->setAdapter(Landroid/widget/ListAdapter;)V

    return-void

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-class p1, Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 5
    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object p1

    const-class v0, Lcom/google/android/material/datepicker/c0;

    .line 6
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v0

    filled-new-array {p1, v0}, [Ljava/lang/Object;

    move-result-object p1

    .line 7
    const-string v0, "%1$s must have its Adapter set to a %2$s"

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final setSelection(I)V
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lcom/google/android/material/datepicker/c0;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-ge p1, v0, :cond_0

    .line 12
    .line 13
    invoke-super {p0}, Landroid/widget/GridView;->getAdapter()Landroid/widget/ListAdapter;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Lcom/google/android/material/datepicker/c0;

    .line 18
    .line 19
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-super {p0, p1}, Landroid/widget/GridView;->setSelection(I)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    invoke-super {p0, p1}, Landroid/widget/GridView;->setSelection(I)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
