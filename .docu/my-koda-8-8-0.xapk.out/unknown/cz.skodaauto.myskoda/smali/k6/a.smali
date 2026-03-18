.class public final Lk6/a;
.super Lbu/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I

.field public final synthetic h:Ld6/b;


# direct methods
.method public synthetic constructor <init>(Ld6/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lk6/a;->g:I

    .line 2
    .line 3
    iput-object p1, p0, Lk6/a;->h:Ld6/b;

    .line 4
    .line 5
    const/16 p1, 0x11

    .line 6
    .line 7
    invoke-direct {p0, p1}, Lbu/c;-><init>(I)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private final C(I)Le6/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lk6/a;->h:Ld6/b;

    .line 2
    .line 3
    check-cast p0, Lk6/b;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lk6/b;->n(I)Le6/d;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    iget-object p0, p0, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 10
    .line 11
    invoke-static {p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain(Landroid/view/accessibility/AccessibilityNodeInfo;)Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    new-instance p1, Le6/d;

    .line 16
    .line 17
    invoke-direct {p1, p0}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 18
    .line 19
    .line 20
    return-object p1
.end method


# virtual methods
.method public i(ILe6/d;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    iget v0, p0, Lk6/a;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lk6/a;->h:Ld6/b;

    .line 8
    .line 9
    check-cast p0, Lw3/z;

    .line 10
    .line 11
    invoke-virtual {p0, p1, p2, p3, p4}, Lw3/z;->j(ILe6/d;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final j(I)Le6/d;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lk6/a;->g:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v0, v0, Lk6/a;->h:Ld6/b;

    .line 11
    .line 12
    check-cast v0, Lw3/z;

    .line 13
    .line 14
    iget-object v2, v0, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 15
    .line 16
    iget-object v3, v0, Lw3/z;->d:Lw3/t;

    .line 17
    .line 18
    invoke-virtual {v3}, Lw3/t;->getViewTreeOwners()Lw3/l;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    if-eqz v4, :cond_0

    .line 23
    .line 24
    iget-object v4, v4, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 25
    .line 26
    invoke-interface {v4}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    if-eqz v4, :cond_0

    .line 31
    .line 32
    invoke-virtual {v4}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v4, 0x0

    .line 38
    :goto_0
    sget-object v6, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 39
    .line 40
    if-ne v4, v6, :cond_1

    .line 41
    .line 42
    invoke-virtual {v2}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-nez v2, :cond_5

    .line 47
    .line 48
    invoke-static {}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain()Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    new-instance v5, Le6/d;

    .line 53
    .line 54
    invoke-direct {v5, v2}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_56

    .line 58
    .line 59
    :cond_1
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    invoke-virtual {v4, v1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    check-cast v4, Ld4/r;

    .line 68
    .line 69
    if-nez v4, :cond_2

    .line 70
    .line 71
    invoke-virtual {v2}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-nez v2, :cond_5

    .line 76
    .line 77
    invoke-static {}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain()Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    new-instance v5, Le6/d;

    .line 82
    .line 83
    invoke-direct {v5, v2}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 84
    .line 85
    .line 86
    goto/16 :goto_56

    .line 87
    .line 88
    :cond_2
    iget-object v6, v4, Ld4/r;->a:Ld4/q;

    .line 89
    .line 90
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    iget-object v8, v6, Ld4/q;->c:Lv3/h0;

    .line 95
    .line 96
    iget-object v9, v6, Ld4/q;->d:Ld4/l;

    .line 97
    .line 98
    sget-object v10, Ld4/v;->n:Ld4/z;

    .line 99
    .line 100
    iget-object v7, v7, Ld4/l;->d:Landroidx/collection/q0;

    .line 101
    .line 102
    invoke-virtual {v7, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    if-nez v7, :cond_3

    .line 107
    .line 108
    const/4 v7, 0x0

    .line 109
    :cond_3
    sget-object v10, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 110
    .line 111
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    const/16 v10, 0x22

    .line 116
    .line 117
    if-eqz v7, :cond_6

    .line 118
    .line 119
    sget v12, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 120
    .line 121
    if-lt v12, v10, :cond_4

    .line 122
    .line 123
    invoke-static {v2}, Lb/a;->k(Landroid/view/accessibility/AccessibilityManager;)Z

    .line 124
    .line 125
    .line 126
    move-result v12

    .line 127
    goto :goto_1

    .line 128
    :cond_4
    const/4 v12, 0x1

    .line 129
    :goto_1
    if-nez v12, :cond_6

    .line 130
    .line 131
    :cond_5
    const/4 v5, 0x0

    .line 132
    goto/16 :goto_56

    .line 133
    .line 134
    :cond_6
    invoke-static {}, Landroid/view/accessibility/AccessibilityNodeInfo;->obtain()Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 135
    .line 136
    .line 137
    move-result-object v12

    .line 138
    new-instance v13, Le6/d;

    .line 139
    .line 140
    invoke-direct {v13, v12}, Le6/d;-><init>(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 141
    .line 142
    .line 143
    sget v14, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 144
    .line 145
    const/4 v15, 0x0

    .line 146
    if-lt v14, v10, :cond_7

    .line 147
    .line 148
    invoke-static {v12, v7}, Lb/a;->n(Landroid/view/accessibility/AccessibilityNodeInfo;Z)V

    .line 149
    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_7
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 153
    .line 154
    .line 155
    move-result-object v5

    .line 156
    if-eqz v5, :cond_9

    .line 157
    .line 158
    const-string v11, "androidx.view.accessibility.AccessibilityNodeInfoCompat.BOOLEAN_PROPERTY_KEY"

    .line 159
    .line 160
    invoke-virtual {v5, v11, v15}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 161
    .line 162
    .line 163
    move-result v16

    .line 164
    and-int/lit8 v16, v16, -0x41

    .line 165
    .line 166
    if-eqz v7, :cond_8

    .line 167
    .line 168
    const/16 v7, 0x40

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_8
    move v7, v15

    .line 172
    :goto_2
    or-int v7, v16, v7

    .line 173
    .line 174
    invoke-virtual {v5, v11, v7}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 175
    .line 176
    .line 177
    :cond_9
    :goto_3
    const/4 v5, -0x1

    .line 178
    if-ne v1, v5, :cond_b

    .line 179
    .line 180
    invoke-virtual {v3}, Landroid/view/View;->getParentForAccessibility()Landroid/view/ViewParent;

    .line 181
    .line 182
    .line 183
    move-result-object v7

    .line 184
    instance-of v11, v7, Landroid/view/View;

    .line 185
    .line 186
    if-eqz v11, :cond_a

    .line 187
    .line 188
    check-cast v7, Landroid/view/View;

    .line 189
    .line 190
    goto :goto_4

    .line 191
    :cond_a
    const/4 v7, 0x0

    .line 192
    :goto_4
    iput v5, v13, Le6/d;->b:I

    .line 193
    .line 194
    invoke-virtual {v12, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setParent(Landroid/view/View;)V

    .line 195
    .line 196
    .line 197
    goto :goto_6

    .line 198
    :cond_b
    invoke-virtual {v6}, Ld4/q;->l()Ld4/q;

    .line 199
    .line 200
    .line 201
    move-result-object v7

    .line 202
    if-eqz v7, :cond_c

    .line 203
    .line 204
    iget v7, v7, Ld4/q;->g:I

    .line 205
    .line 206
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 207
    .line 208
    .line 209
    move-result-object v7

    .line 210
    goto :goto_5

    .line 211
    :cond_c
    const/4 v7, 0x0

    .line 212
    :goto_5
    if-eqz v7, :cond_c5

    .line 213
    .line 214
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 215
    .line 216
    .line 217
    move-result v7

    .line 218
    invoke-virtual {v3}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 219
    .line 220
    .line 221
    move-result-object v11

    .line 222
    invoke-virtual {v11}, Ld4/s;->a()Ld4/q;

    .line 223
    .line 224
    .line 225
    move-result-object v11

    .line 226
    iget v11, v11, Ld4/q;->g:I

    .line 227
    .line 228
    if-ne v7, v11, :cond_d

    .line 229
    .line 230
    move v7, v5

    .line 231
    :cond_d
    iput v7, v13, Le6/d;->b:I

    .line 232
    .line 233
    invoke-virtual {v12, v3, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setParent(Landroid/view/View;I)V

    .line 234
    .line 235
    .line 236
    :goto_6
    iput v1, v13, Le6/d;->c:I

    .line 237
    .line 238
    invoke-virtual {v12, v3, v1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setSource(Landroid/view/View;I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v0, v4}, Lw3/z;->k(Ld4/r;)Landroid/graphics/Rect;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    invoke-virtual {v12, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setBoundsInScreen(Landroid/graphics/Rect;)V

    .line 246
    .line 247
    .line 248
    sget-object v4, Lw3/z;->Q:Landroidx/collection/a0;

    .line 249
    .line 250
    iget-object v7, v0, Lw3/z;->M:Landroidx/collection/z;

    .line 251
    .line 252
    iget-object v11, v0, Lw3/z;->v:Landroidx/collection/b1;

    .line 253
    .line 254
    invoke-virtual {v3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 255
    .line 256
    .line 257
    move-result-object v16

    .line 258
    invoke-virtual/range {v16 .. v16}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 259
    .line 260
    .line 261
    move-result-object v15

    .line 262
    const-string v5, "android.view.View"

    .line 263
    .line 264
    invoke-virtual {v13, v5}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 265
    .line 266
    .line 267
    iget-object v5, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 268
    .line 269
    sget-object v10, Ld4/v;->E:Ld4/z;

    .line 270
    .line 271
    invoke-virtual {v5, v10}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v10

    .line 275
    if-eqz v10, :cond_e

    .line 276
    .line 277
    const-string v10, "android.widget.EditText"

    .line 278
    .line 279
    invoke-virtual {v13, v10}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 280
    .line 281
    .line 282
    :cond_e
    sget-object v10, Ld4/v;->A:Ld4/z;

    .line 283
    .line 284
    invoke-virtual {v5, v10}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    move-result v10

    .line 288
    if-eqz v10, :cond_f

    .line 289
    .line 290
    const-string v10, "android.widget.TextView"

    .line 291
    .line 292
    invoke-virtual {v13, v10}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 293
    .line 294
    .line 295
    :cond_f
    sget-object v10, Ld4/v;->x:Ld4/z;

    .line 296
    .line 297
    invoke-virtual {v5, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v10

    .line 301
    if-nez v10, :cond_10

    .line 302
    .line 303
    const/4 v10, 0x0

    .line 304
    :cond_10
    check-cast v10, Ld4/i;

    .line 305
    .line 306
    move-object/from16 v18, v2

    .line 307
    .line 308
    if-eqz v10, :cond_15

    .line 309
    .line 310
    iget v2, v10, Ld4/i;->a:I

    .line 311
    .line 312
    move-object/from16 v21, v11

    .line 313
    .line 314
    iget-boolean v11, v6, Ld4/q;->e:Z

    .line 315
    .line 316
    if-nez v11, :cond_11

    .line 317
    .line 318
    const/4 v11, 0x4

    .line 319
    invoke-static {v11, v6}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 320
    .line 321
    .line 322
    move-result-object v19

    .line 323
    invoke-interface/range {v19 .. v19}, Ljava/util/List;->isEmpty()Z

    .line 324
    .line 325
    .line 326
    move-result v19

    .line 327
    move-object/from16 v22, v4

    .line 328
    .line 329
    if-eqz v19, :cond_16

    .line 330
    .line 331
    goto :goto_7

    .line 332
    :cond_11
    const/4 v11, 0x4

    .line 333
    move-object/from16 v22, v4

    .line 334
    .line 335
    :goto_7
    const-string v4, "AccessibilityNodeInfo.roleDescription"

    .line 336
    .line 337
    if-ne v2, v11, :cond_12

    .line 338
    .line 339
    const v2, 0x7f12128a

    .line 340
    .line 341
    .line 342
    invoke-virtual {v15, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 347
    .line 348
    .line 349
    move-result-object v11

    .line 350
    invoke-virtual {v11, v4, v2}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 351
    .line 352
    .line 353
    goto :goto_8

    .line 354
    :cond_12
    const/4 v11, 0x2

    .line 355
    if-ne v2, v11, :cond_13

    .line 356
    .line 357
    const v2, 0x7f121289

    .line 358
    .line 359
    .line 360
    invoke-virtual {v15, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v2

    .line 364
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 365
    .line 366
    .line 367
    move-result-object v11

    .line 368
    invoke-virtual {v11, v4, v2}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 369
    .line 370
    .line 371
    goto :goto_8

    .line 372
    :cond_13
    invoke-static {v2}, Lw3/h0;->B(I)Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v4

    .line 376
    const/4 v11, 0x5

    .line 377
    if-ne v2, v11, :cond_14

    .line 378
    .line 379
    invoke-virtual {v6}, Ld4/q;->o()Z

    .line 380
    .line 381
    .line 382
    move-result v2

    .line 383
    if-nez v2, :cond_14

    .line 384
    .line 385
    iget-boolean v2, v9, Ld4/l;->f:Z

    .line 386
    .line 387
    if-eqz v2, :cond_16

    .line 388
    .line 389
    :cond_14
    invoke-virtual {v13, v4}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 390
    .line 391
    .line 392
    goto :goto_8

    .line 393
    :cond_15
    move-object/from16 v22, v4

    .line 394
    .line 395
    move-object/from16 v21, v11

    .line 396
    .line 397
    :cond_16
    :goto_8
    invoke-virtual {v3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 398
    .line 399
    .line 400
    move-result-object v2

    .line 401
    invoke-virtual {v2}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v2

    .line 405
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setPackageName(Ljava/lang/CharSequence;)V

    .line 406
    .line 407
    .line 408
    invoke-static {v6}, Ld4/t;->f(Ld4/q;)Z

    .line 409
    .line 410
    .line 411
    move-result v2

    .line 412
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setImportantForAccessibility(Z)V

    .line 413
    .line 414
    .line 415
    const/16 v2, 0x22

    .line 416
    .line 417
    if-lt v14, v2, :cond_17

    .line 418
    .line 419
    invoke-static/range {v18 .. v18}, Lb/a;->k(Landroid/view/accessibility/AccessibilityManager;)Z

    .line 420
    .line 421
    .line 422
    move-result v2

    .line 423
    :goto_9
    const/4 v11, 0x4

    .line 424
    goto :goto_a

    .line 425
    :cond_17
    const/4 v2, 0x1

    .line 426
    goto :goto_9

    .line 427
    :goto_a
    invoke-static {v11, v6}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 428
    .line 429
    .line 430
    move-result-object v4

    .line 431
    move-object v11, v4

    .line 432
    check-cast v11, Ljava/util/Collection;

    .line 433
    .line 434
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 435
    .line 436
    .line 437
    move-result v11

    .line 438
    move/from16 v17, v2

    .line 439
    .line 440
    move-object/from16 v18, v8

    .line 441
    .line 442
    const/4 v2, 0x0

    .line 443
    const/4 v14, 0x0

    .line 444
    :goto_b
    iget-object v8, v13, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 445
    .line 446
    if-ge v14, v11, :cond_1f

    .line 447
    .line 448
    invoke-interface {v4, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v23

    .line 452
    move-object/from16 v24, v4

    .line 453
    .line 454
    move-object/from16 v4, v23

    .line 455
    .line 456
    check-cast v4, Ld4/q;

    .line 457
    .line 458
    move/from16 v23, v11

    .line 459
    .line 460
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 461
    .line 462
    .line 463
    move-result-object v11

    .line 464
    move/from16 v25, v14

    .line 465
    .line 466
    iget v14, v4, Ld4/q;->g:I

    .line 467
    .line 468
    invoke-virtual {v11, v14}, Landroidx/collection/p;->a(I)Z

    .line 469
    .line 470
    .line 471
    move-result v11

    .line 472
    if-eqz v11, :cond_1e

    .line 473
    .line 474
    invoke-virtual {v3}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 475
    .line 476
    .line 477
    move-result-object v11

    .line 478
    invoke-virtual {v11}, Lw3/t0;->getLayoutNodeToHolder()Ljava/util/HashMap;

    .line 479
    .line 480
    .line 481
    move-result-object v11

    .line 482
    iget-object v4, v4, Ld4/q;->c:Lv3/h0;

    .line 483
    .line 484
    invoke-virtual {v11, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object v4

    .line 488
    check-cast v4, Lw4/g;

    .line 489
    .line 490
    const/4 v11, -0x1

    .line 491
    if-ne v14, v11, :cond_18

    .line 492
    .line 493
    goto :goto_e

    .line 494
    :cond_18
    if-eqz v4, :cond_19

    .line 495
    .line 496
    invoke-virtual {v12, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->addChild(Landroid/view/View;)V

    .line 497
    .line 498
    .line 499
    goto :goto_d

    .line 500
    :cond_19
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 501
    .line 502
    .line 503
    move-result-object v4

    .line 504
    invoke-virtual {v4, v14}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v4

    .line 508
    check-cast v4, Ld4/r;

    .line 509
    .line 510
    if-eqz v4, :cond_1b

    .line 511
    .line 512
    iget-object v4, v4, Ld4/r;->a:Ld4/q;

    .line 513
    .line 514
    if-eqz v4, :cond_1b

    .line 515
    .line 516
    invoke-virtual {v4}, Ld4/q;->k()Ld4/l;

    .line 517
    .line 518
    .line 519
    move-result-object v4

    .line 520
    sget-object v11, Ld4/v;->n:Ld4/z;

    .line 521
    .line 522
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 523
    .line 524
    invoke-virtual {v4, v11}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 525
    .line 526
    .line 527
    move-result-object v4

    .line 528
    if-nez v4, :cond_1a

    .line 529
    .line 530
    const/4 v4, 0x0

    .line 531
    :cond_1a
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 532
    .line 533
    invoke-static {v4, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    move-result v4

    .line 537
    goto :goto_c

    .line 538
    :cond_1b
    const/4 v4, 0x0

    .line 539
    :goto_c
    if-nez v17, :cond_1c

    .line 540
    .line 541
    if-nez v4, :cond_1d

    .line 542
    .line 543
    :cond_1c
    invoke-virtual {v8, v3, v14}, Landroid/view/accessibility/AccessibilityNodeInfo;->addChild(Landroid/view/View;I)V

    .line 544
    .line 545
    .line 546
    :cond_1d
    :goto_d
    invoke-virtual {v7, v14, v2}, Landroidx/collection/z;->f(II)V

    .line 547
    .line 548
    .line 549
    add-int/lit8 v2, v2, 0x1

    .line 550
    .line 551
    :cond_1e
    :goto_e
    add-int/lit8 v14, v25, 0x1

    .line 552
    .line 553
    move/from16 v11, v23

    .line 554
    .line 555
    move-object/from16 v4, v24

    .line 556
    .line 557
    goto :goto_b

    .line 558
    :cond_1f
    iget v2, v0, Lw3/z;->n:I

    .line 559
    .line 560
    if-ne v1, v2, :cond_20

    .line 561
    .line 562
    const/4 v2, 0x1

    .line 563
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setAccessibilityFocused(Z)V

    .line 564
    .line 565
    .line 566
    sget-object v2, Le6/c;->g:Le6/c;

    .line 567
    .line 568
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 569
    .line 570
    .line 571
    goto :goto_f

    .line 572
    :cond_20
    const/4 v2, 0x0

    .line 573
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setAccessibilityFocused(Z)V

    .line 574
    .line 575
    .line 576
    sget-object v2, Le6/c;->f:Le6/c;

    .line 577
    .line 578
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 579
    .line 580
    .line 581
    :goto_f
    invoke-virtual {v0, v6, v13}, Lw3/z;->L(Ld4/q;Le6/d;)V

    .line 582
    .line 583
    .line 584
    sget-object v2, Ld4/v;->K:Ld4/z;

    .line 585
    .line 586
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 587
    .line 588
    .line 589
    move-result v4

    .line 590
    if-eqz v4, :cond_22

    .line 591
    .line 592
    const/4 v4, 0x1

    .line 593
    invoke-virtual {v12, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setContentInvalid(Z)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 597
    .line 598
    .line 599
    move-result-object v2

    .line 600
    if-nez v2, :cond_21

    .line 601
    .line 602
    const/4 v2, 0x0

    .line 603
    :cond_21
    check-cast v2, Ljava/lang/CharSequence;

    .line 604
    .line 605
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setError(Ljava/lang/CharSequence;)V

    .line 606
    .line 607
    .line 608
    :cond_22
    invoke-static {v6, v15}, Lw3/h0;->s(Ld4/q;Landroid/content/res/Resources;)Ljava/lang/String;

    .line 609
    .line 610
    .line 611
    move-result-object v2

    .line 612
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 613
    .line 614
    const/16 v11, 0x1e

    .line 615
    .line 616
    if-lt v4, v11, :cond_23

    .line 617
    .line 618
    invoke-static {v8, v2}, Ld6/h;->j(Landroid/view/accessibility/AccessibilityNodeInfo;Ljava/lang/CharSequence;)V

    .line 619
    .line 620
    .line 621
    goto :goto_10

    .line 622
    :cond_23
    invoke-virtual {v8}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 623
    .line 624
    .line 625
    move-result-object v4

    .line 626
    const-string v11, "androidx.view.accessibility.AccessibilityNodeInfoCompat.STATE_DESCRIPTION_KEY"

    .line 627
    .line 628
    invoke-virtual {v4, v11, v2}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 629
    .line 630
    .line 631
    :goto_10
    invoke-static {v6}, Lw3/h0;->r(Ld4/q;)Z

    .line 632
    .line 633
    .line 634
    move-result v2

    .line 635
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCheckable(Z)V

    .line 636
    .line 637
    .line 638
    sget-object v2, Ld4/v;->I:Ld4/z;

    .line 639
    .line 640
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 641
    .line 642
    .line 643
    move-result-object v2

    .line 644
    if-nez v2, :cond_24

    .line 645
    .line 646
    const/4 v2, 0x0

    .line 647
    :cond_24
    check-cast v2, Lf4/a;

    .line 648
    .line 649
    if-eqz v2, :cond_26

    .line 650
    .line 651
    sget-object v4, Lf4/a;->d:Lf4/a;

    .line 652
    .line 653
    if-ne v2, v4, :cond_25

    .line 654
    .line 655
    const/4 v4, 0x1

    .line 656
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setChecked(Z)V

    .line 657
    .line 658
    .line 659
    goto :goto_11

    .line 660
    :cond_25
    sget-object v4, Lf4/a;->e:Lf4/a;

    .line 661
    .line 662
    if-ne v2, v4, :cond_26

    .line 663
    .line 664
    const/4 v2, 0x0

    .line 665
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setChecked(Z)V

    .line 666
    .line 667
    .line 668
    :cond_26
    :goto_11
    sget-object v2, Ld4/v;->H:Ld4/z;

    .line 669
    .line 670
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 671
    .line 672
    .line 673
    move-result-object v2

    .line 674
    if-nez v2, :cond_27

    .line 675
    .line 676
    const/4 v2, 0x0

    .line 677
    :cond_27
    check-cast v2, Ljava/lang/Boolean;

    .line 678
    .line 679
    if-eqz v2, :cond_2a

    .line 680
    .line 681
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 682
    .line 683
    .line 684
    move-result v2

    .line 685
    if-nez v10, :cond_28

    .line 686
    .line 687
    const/4 v11, 0x4

    .line 688
    goto :goto_12

    .line 689
    :cond_28
    iget v4, v10, Ld4/i;->a:I

    .line 690
    .line 691
    const/4 v11, 0x4

    .line 692
    if-ne v4, v11, :cond_29

    .line 693
    .line 694
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setSelected(Z)V

    .line 695
    .line 696
    .line 697
    goto :goto_13

    .line 698
    :cond_29
    :goto_12
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setChecked(Z)V

    .line 699
    .line 700
    .line 701
    goto :goto_13

    .line 702
    :cond_2a
    const/4 v11, 0x4

    .line 703
    :goto_13
    iget-boolean v2, v9, Ld4/l;->f:Z

    .line 704
    .line 705
    if-eqz v2, :cond_2b

    .line 706
    .line 707
    invoke-static {v11, v6}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 708
    .line 709
    .line 710
    move-result-object v2

    .line 711
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 712
    .line 713
    .line 714
    move-result v2

    .line 715
    if-eqz v2, :cond_2e

    .line 716
    .line 717
    :cond_2b
    sget-object v2, Ld4/v;->a:Ld4/z;

    .line 718
    .line 719
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 720
    .line 721
    .line 722
    move-result-object v2

    .line 723
    if-nez v2, :cond_2c

    .line 724
    .line 725
    const/4 v2, 0x0

    .line 726
    :cond_2c
    check-cast v2, Ljava/util/List;

    .line 727
    .line 728
    if-eqz v2, :cond_2d

    .line 729
    .line 730
    invoke-static {v2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v2

    .line 734
    check-cast v2, Ljava/lang/String;

    .line 735
    .line 736
    goto :goto_14

    .line 737
    :cond_2d
    const/4 v2, 0x0

    .line 738
    :goto_14
    invoke-virtual {v13, v2}, Le6/d;->j(Ljava/lang/CharSequence;)V

    .line 739
    .line 740
    .line 741
    :cond_2e
    sget-object v2, Ld4/v;->y:Ld4/z;

    .line 742
    .line 743
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 744
    .line 745
    .line 746
    move-result-object v2

    .line 747
    if-nez v2, :cond_2f

    .line 748
    .line 749
    const/4 v2, 0x0

    .line 750
    :cond_2f
    check-cast v2, Ljava/lang/String;

    .line 751
    .line 752
    if-eqz v2, :cond_32

    .line 753
    .line 754
    move-object v4, v6

    .line 755
    :goto_15
    if-eqz v4, :cond_31

    .line 756
    .line 757
    iget-object v11, v4, Ld4/q;->d:Ld4/l;

    .line 758
    .line 759
    sget-object v14, Ld4/w;->a:Ld4/z;

    .line 760
    .line 761
    move-object/from16 v17, v4

    .line 762
    .line 763
    iget-object v4, v11, Ld4/l;->d:Landroidx/collection/q0;

    .line 764
    .line 765
    invoke-virtual {v4, v14}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 766
    .line 767
    .line 768
    move-result v4

    .line 769
    if-eqz v4, :cond_30

    .line 770
    .line 771
    invoke-virtual {v11, v14}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 772
    .line 773
    .line 774
    move-result-object v4

    .line 775
    check-cast v4, Ljava/lang/Boolean;

    .line 776
    .line 777
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 778
    .line 779
    .line 780
    move-result v4

    .line 781
    goto :goto_16

    .line 782
    :cond_30
    invoke-virtual/range {v17 .. v17}, Ld4/q;->l()Ld4/q;

    .line 783
    .line 784
    .line 785
    move-result-object v4

    .line 786
    goto :goto_15

    .line 787
    :cond_31
    const/4 v4, 0x0

    .line 788
    :goto_16
    if-eqz v4, :cond_32

    .line 789
    .line 790
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setViewIdResourceName(Ljava/lang/String;)V

    .line 791
    .line 792
    .line 793
    :cond_32
    sget-object v2, Ld4/v;->h:Ld4/z;

    .line 794
    .line 795
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 796
    .line 797
    .line 798
    move-result-object v2

    .line 799
    if-nez v2, :cond_33

    .line 800
    .line 801
    const/4 v2, 0x0

    .line 802
    :cond_33
    check-cast v2, Llx0/b0;

    .line 803
    .line 804
    if-eqz v2, :cond_34

    .line 805
    .line 806
    const/4 v4, 0x1

    .line 807
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setHeading(Z)V

    .line 808
    .line 809
    .line 810
    :cond_34
    const/4 v11, -0x1

    .line 811
    if-eq v1, v11, :cond_36

    .line 812
    .line 813
    iget v2, v6, Ld4/q;->g:I

    .line 814
    .line 815
    invoke-virtual {v7, v2}, Landroidx/collection/z;->d(I)I

    .line 816
    .line 817
    .line 818
    move-result v2

    .line 819
    if-eq v2, v11, :cond_35

    .line 820
    .line 821
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setDrawingOrder(I)V

    .line 822
    .line 823
    .line 824
    goto :goto_17

    .line 825
    :cond_35
    const-string v2, "AccessibilityDelegate"

    .line 826
    .line 827
    const-string v4, "Drawing order is not available, was AccessibilityNodeInfo requested for a child node before its parent?"

    .line 828
    .line 829
    invoke-static {v2, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 830
    .line 831
    .line 832
    :cond_36
    :goto_17
    sget-object v2, Ld4/v;->J:Ld4/z;

    .line 833
    .line 834
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 835
    .line 836
    .line 837
    move-result v2

    .line 838
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setPassword(Z)V

    .line 839
    .line 840
    .line 841
    sget-object v2, Ld4/v;->M:Ld4/z;

    .line 842
    .line 843
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 844
    .line 845
    .line 846
    move-result v2

    .line 847
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setEditable(Z)V

    .line 848
    .line 849
    .line 850
    sget-object v2, Ld4/v;->N:Ld4/z;

    .line 851
    .line 852
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v2

    .line 856
    if-nez v2, :cond_37

    .line 857
    .line 858
    const/4 v2, 0x0

    .line 859
    :cond_37
    check-cast v2, Ljava/lang/Integer;

    .line 860
    .line 861
    if-eqz v2, :cond_38

    .line 862
    .line 863
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 864
    .line 865
    .line 866
    move-result v2

    .line 867
    goto :goto_18

    .line 868
    :cond_38
    const/4 v2, -0x1

    .line 869
    :goto_18
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setMaxTextLength(I)V

    .line 870
    .line 871
    .line 872
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 873
    .line 874
    .line 875
    move-result v2

    .line 876
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setEnabled(Z)V

    .line 877
    .line 878
    .line 879
    sget-object v2, Ld4/v;->k:Ld4/z;

    .line 880
    .line 881
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 882
    .line 883
    .line 884
    move-result v4

    .line 885
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setFocusable(Z)V

    .line 886
    .line 887
    .line 888
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->isFocusable()Z

    .line 889
    .line 890
    .line 891
    move-result v4

    .line 892
    if-eqz v4, :cond_3a

    .line 893
    .line 894
    invoke-virtual {v9, v2}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 895
    .line 896
    .line 897
    move-result-object v4

    .line 898
    check-cast v4, Ljava/lang/Boolean;

    .line 899
    .line 900
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 901
    .line 902
    .line 903
    move-result v4

    .line 904
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setFocused(Z)V

    .line 905
    .line 906
    .line 907
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->isFocused()Z

    .line 908
    .line 909
    .line 910
    move-result v4

    .line 911
    if-eqz v4, :cond_39

    .line 912
    .line 913
    const/4 v11, 0x2

    .line 914
    invoke-virtual {v13, v11}, Le6/d;->a(I)V

    .line 915
    .line 916
    .line 917
    iput v1, v0, Lw3/z;->o:I

    .line 918
    .line 919
    const/4 v4, 0x1

    .line 920
    goto :goto_19

    .line 921
    :cond_39
    const/4 v4, 0x1

    .line 922
    const/4 v11, 0x2

    .line 923
    invoke-virtual {v13, v4}, Le6/d;->a(I)V

    .line 924
    .line 925
    .line 926
    goto :goto_19

    .line 927
    :cond_3a
    const/4 v4, 0x1

    .line 928
    const/4 v11, 0x2

    .line 929
    :goto_19
    invoke-static {v6}, Ld4/t;->e(Ld4/q;)Z

    .line 930
    .line 931
    .line 932
    move-result v7

    .line 933
    xor-int/2addr v7, v4

    .line 934
    invoke-virtual {v8, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setVisibleToUser(Z)V

    .line 935
    .line 936
    .line 937
    sget-object v4, Ld4/v;->j:Ld4/z;

    .line 938
    .line 939
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 940
    .line 941
    .line 942
    move-result-object v4

    .line 943
    if-nez v4, :cond_3b

    .line 944
    .line 945
    const/4 v4, 0x0

    .line 946
    :cond_3b
    check-cast v4, Ld4/f;

    .line 947
    .line 948
    if-eqz v4, :cond_40

    .line 949
    .line 950
    iget v4, v4, Ld4/f;->a:I

    .line 951
    .line 952
    if-nez v4, :cond_3c

    .line 953
    .line 954
    const/4 v7, 0x1

    .line 955
    goto :goto_1a

    .line 956
    :cond_3c
    const/4 v7, 0x0

    .line 957
    :goto_1a
    if-eqz v7, :cond_3e

    .line 958
    .line 959
    :cond_3d
    const/4 v11, 0x1

    .line 960
    goto :goto_1c

    .line 961
    :cond_3e
    const/4 v7, 0x1

    .line 962
    if-ne v4, v7, :cond_3f

    .line 963
    .line 964
    const/4 v4, 0x1

    .line 965
    goto :goto_1b

    .line 966
    :cond_3f
    const/4 v4, 0x0

    .line 967
    :goto_1b
    if-eqz v4, :cond_3d

    .line 968
    .line 969
    :goto_1c
    invoke-virtual {v12, v11}, Landroid/view/accessibility/AccessibilityNodeInfo;->setLiveRegion(I)V

    .line 970
    .line 971
    .line 972
    :cond_40
    const/4 v4, 0x0

    .line 973
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setClickable(Z)V

    .line 974
    .line 975
    .line 976
    sget-object v4, Ld4/k;->b:Ld4/z;

    .line 977
    .line 978
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 979
    .line 980
    .line 981
    move-result-object v4

    .line 982
    if-nez v4, :cond_41

    .line 983
    .line 984
    const/4 v4, 0x0

    .line 985
    :cond_41
    check-cast v4, Ld4/a;

    .line 986
    .line 987
    if-eqz v4, :cond_4b

    .line 988
    .line 989
    sget-object v7, Ld4/v;->H:Ld4/z;

    .line 990
    .line 991
    invoke-virtual {v5, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 992
    .line 993
    .line 994
    move-result-object v7

    .line 995
    if-nez v7, :cond_42

    .line 996
    .line 997
    const/4 v7, 0x0

    .line 998
    :cond_42
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 999
    .line 1000
    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1001
    .line 1002
    .line 1003
    move-result v7

    .line 1004
    if-nez v10, :cond_44

    .line 1005
    .line 1006
    :cond_43
    const/4 v11, 0x0

    .line 1007
    goto :goto_1d

    .line 1008
    :cond_44
    iget v11, v10, Ld4/i;->a:I

    .line 1009
    .line 1010
    const/4 v14, 0x4

    .line 1011
    if-ne v11, v14, :cond_43

    .line 1012
    .line 1013
    const/4 v11, 0x1

    .line 1014
    :goto_1d
    if-nez v11, :cond_48

    .line 1015
    .line 1016
    if-nez v10, :cond_46

    .line 1017
    .line 1018
    :cond_45
    const/4 v10, 0x0

    .line 1019
    goto :goto_1e

    .line 1020
    :cond_46
    iget v10, v10, Ld4/i;->a:I

    .line 1021
    .line 1022
    const/4 v11, 0x3

    .line 1023
    if-ne v10, v11, :cond_45

    .line 1024
    .line 1025
    const/4 v10, 0x1

    .line 1026
    :goto_1e
    if-eqz v10, :cond_47

    .line 1027
    .line 1028
    goto :goto_1f

    .line 1029
    :cond_47
    const/4 v10, 0x0

    .line 1030
    goto :goto_20

    .line 1031
    :cond_48
    :goto_1f
    const/4 v10, 0x1

    .line 1032
    :goto_20
    if-eqz v10, :cond_4a

    .line 1033
    .line 1034
    if-eqz v10, :cond_49

    .line 1035
    .line 1036
    if-nez v7, :cond_49

    .line 1037
    .line 1038
    goto :goto_21

    .line 1039
    :cond_49
    const/4 v7, 0x0

    .line 1040
    goto :goto_22

    .line 1041
    :cond_4a
    :goto_21
    const/4 v7, 0x1

    .line 1042
    :goto_22
    invoke-virtual {v8, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setClickable(Z)V

    .line 1043
    .line 1044
    .line 1045
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 1046
    .line 1047
    .line 1048
    move-result v7

    .line 1049
    if-eqz v7, :cond_4b

    .line 1050
    .line 1051
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->isClickable()Z

    .line 1052
    .line 1053
    .line 1054
    move-result v7

    .line 1055
    if-eqz v7, :cond_4b

    .line 1056
    .line 1057
    new-instance v7, Le6/c;

    .line 1058
    .line 1059
    const/16 v10, 0x10

    .line 1060
    .line 1061
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1062
    .line 1063
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1064
    .line 1065
    .line 1066
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1067
    .line 1068
    .line 1069
    :cond_4b
    const/4 v4, 0x0

    .line 1070
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setLongClickable(Z)V

    .line 1071
    .line 1072
    .line 1073
    sget-object v4, Ld4/k;->c:Ld4/z;

    .line 1074
    .line 1075
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1076
    .line 1077
    .line 1078
    move-result-object v4

    .line 1079
    if-nez v4, :cond_4c

    .line 1080
    .line 1081
    const/4 v4, 0x0

    .line 1082
    :cond_4c
    check-cast v4, Ld4/a;

    .line 1083
    .line 1084
    if-eqz v4, :cond_4d

    .line 1085
    .line 1086
    const/4 v7, 0x1

    .line 1087
    invoke-virtual {v8, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setLongClickable(Z)V

    .line 1088
    .line 1089
    .line 1090
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 1091
    .line 1092
    .line 1093
    move-result v7

    .line 1094
    if-eqz v7, :cond_4d

    .line 1095
    .line 1096
    new-instance v7, Le6/c;

    .line 1097
    .line 1098
    const/16 v10, 0x20

    .line 1099
    .line 1100
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1101
    .line 1102
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1103
    .line 1104
    .line 1105
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1106
    .line 1107
    .line 1108
    :cond_4d
    sget-object v4, Ld4/k;->p:Ld4/z;

    .line 1109
    .line 1110
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1111
    .line 1112
    .line 1113
    move-result-object v4

    .line 1114
    if-nez v4, :cond_4e

    .line 1115
    .line 1116
    const/4 v4, 0x0

    .line 1117
    :cond_4e
    check-cast v4, Ld4/a;

    .line 1118
    .line 1119
    if-eqz v4, :cond_4f

    .line 1120
    .line 1121
    new-instance v7, Le6/c;

    .line 1122
    .line 1123
    const/16 v10, 0x4000

    .line 1124
    .line 1125
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1126
    .line 1127
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1128
    .line 1129
    .line 1130
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1131
    .line 1132
    .line 1133
    :cond_4f
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 1134
    .line 1135
    .line 1136
    move-result v4

    .line 1137
    if-eqz v4, :cond_58

    .line 1138
    .line 1139
    sget-object v4, Ld4/k;->j:Ld4/z;

    .line 1140
    .line 1141
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1142
    .line 1143
    .line 1144
    move-result-object v4

    .line 1145
    if-nez v4, :cond_50

    .line 1146
    .line 1147
    const/4 v4, 0x0

    .line 1148
    :cond_50
    check-cast v4, Ld4/a;

    .line 1149
    .line 1150
    if-eqz v4, :cond_51

    .line 1151
    .line 1152
    new-instance v7, Le6/c;

    .line 1153
    .line 1154
    const/high16 v10, 0x200000

    .line 1155
    .line 1156
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1157
    .line 1158
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1159
    .line 1160
    .line 1161
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1162
    .line 1163
    .line 1164
    :cond_51
    sget-object v4, Ld4/k;->o:Ld4/z;

    .line 1165
    .line 1166
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1167
    .line 1168
    .line 1169
    move-result-object v4

    .line 1170
    if-nez v4, :cond_52

    .line 1171
    .line 1172
    const/4 v4, 0x0

    .line 1173
    :cond_52
    check-cast v4, Ld4/a;

    .line 1174
    .line 1175
    if-eqz v4, :cond_53

    .line 1176
    .line 1177
    new-instance v7, Le6/c;

    .line 1178
    .line 1179
    const v10, 0x1020054

    .line 1180
    .line 1181
    .line 1182
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1183
    .line 1184
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1185
    .line 1186
    .line 1187
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1188
    .line 1189
    .line 1190
    :cond_53
    sget-object v4, Ld4/k;->q:Ld4/z;

    .line 1191
    .line 1192
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v4

    .line 1196
    if-nez v4, :cond_54

    .line 1197
    .line 1198
    const/4 v4, 0x0

    .line 1199
    :cond_54
    check-cast v4, Ld4/a;

    .line 1200
    .line 1201
    if-eqz v4, :cond_55

    .line 1202
    .line 1203
    new-instance v7, Le6/c;

    .line 1204
    .line 1205
    const/high16 v10, 0x10000

    .line 1206
    .line 1207
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1208
    .line 1209
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1210
    .line 1211
    .line 1212
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1213
    .line 1214
    .line 1215
    :cond_55
    sget-object v4, Ld4/k;->r:Ld4/z;

    .line 1216
    .line 1217
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1218
    .line 1219
    .line 1220
    move-result-object v4

    .line 1221
    if-nez v4, :cond_56

    .line 1222
    .line 1223
    const/4 v4, 0x0

    .line 1224
    :cond_56
    check-cast v4, Ld4/a;

    .line 1225
    .line 1226
    if-eqz v4, :cond_58

    .line 1227
    .line 1228
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->isFocused()Z

    .line 1229
    .line 1230
    .line 1231
    move-result v7

    .line 1232
    if-eqz v7, :cond_58

    .line 1233
    .line 1234
    invoke-virtual {v3}, Lw3/t;->getClipboardManager()Lw3/i;

    .line 1235
    .line 1236
    .line 1237
    move-result-object v7

    .line 1238
    iget-object v7, v7, Lw3/i;->a:Landroid/content/ClipboardManager;

    .line 1239
    .line 1240
    invoke-virtual {v7}, Landroid/content/ClipboardManager;->getPrimaryClipDescription()Landroid/content/ClipDescription;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v7

    .line 1244
    if-eqz v7, :cond_57

    .line 1245
    .line 1246
    const-string v10, "text/*"

    .line 1247
    .line 1248
    invoke-virtual {v7, v10}, Landroid/content/ClipDescription;->hasMimeType(Ljava/lang/String;)Z

    .line 1249
    .line 1250
    .line 1251
    move-result v7

    .line 1252
    goto :goto_23

    .line 1253
    :cond_57
    const/4 v7, 0x0

    .line 1254
    :goto_23
    if-eqz v7, :cond_58

    .line 1255
    .line 1256
    new-instance v7, Le6/c;

    .line 1257
    .line 1258
    const v10, 0x8000

    .line 1259
    .line 1260
    .line 1261
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1262
    .line 1263
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1264
    .line 1265
    .line 1266
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1267
    .line 1268
    .line 1269
    :cond_58
    invoke-static {v6}, Lw3/z;->u(Ld4/q;)Ljava/lang/String;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v4

    .line 1273
    if-eqz v4, :cond_5a

    .line 1274
    .line 1275
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 1276
    .line 1277
    .line 1278
    move-result v4

    .line 1279
    if-nez v4, :cond_59

    .line 1280
    .line 1281
    goto :goto_24

    .line 1282
    :cond_59
    const/4 v4, 0x0

    .line 1283
    goto :goto_25

    .line 1284
    :cond_5a
    :goto_24
    const/4 v4, 0x1

    .line 1285
    :goto_25
    if-nez v4, :cond_68

    .line 1286
    .line 1287
    invoke-virtual {v0, v6}, Lw3/z;->s(Ld4/q;)I

    .line 1288
    .line 1289
    .line 1290
    move-result v4

    .line 1291
    invoke-virtual {v0, v6}, Lw3/z;->r(Ld4/q;)I

    .line 1292
    .line 1293
    .line 1294
    move-result v7

    .line 1295
    invoke-virtual {v12, v4, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setTextSelection(II)V

    .line 1296
    .line 1297
    .line 1298
    sget-object v4, Ld4/k;->i:Ld4/z;

    .line 1299
    .line 1300
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1301
    .line 1302
    .line 1303
    move-result-object v4

    .line 1304
    if-nez v4, :cond_5b

    .line 1305
    .line 1306
    const/4 v4, 0x0

    .line 1307
    :cond_5b
    check-cast v4, Ld4/a;

    .line 1308
    .line 1309
    new-instance v7, Le6/c;

    .line 1310
    .line 1311
    if-eqz v4, :cond_5c

    .line 1312
    .line 1313
    iget-object v4, v4, Ld4/a;->a:Ljava/lang/String;

    .line 1314
    .line 1315
    goto :goto_26

    .line 1316
    :cond_5c
    const/4 v4, 0x0

    .line 1317
    :goto_26
    const/high16 v10, 0x20000

    .line 1318
    .line 1319
    invoke-direct {v7, v10, v4}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1320
    .line 1321
    .line 1322
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 1323
    .line 1324
    .line 1325
    const/16 v4, 0x100

    .line 1326
    .line 1327
    invoke-virtual {v13, v4}, Le6/d;->a(I)V

    .line 1328
    .line 1329
    .line 1330
    const/16 v4, 0x200

    .line 1331
    .line 1332
    invoke-virtual {v13, v4}, Le6/d;->a(I)V

    .line 1333
    .line 1334
    .line 1335
    const/16 v4, 0xb

    .line 1336
    .line 1337
    invoke-virtual {v8, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setMovementGranularities(I)V

    .line 1338
    .line 1339
    .line 1340
    sget-object v4, Ld4/v;->a:Ld4/z;

    .line 1341
    .line 1342
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1343
    .line 1344
    .line 1345
    move-result-object v4

    .line 1346
    if-nez v4, :cond_5d

    .line 1347
    .line 1348
    const/4 v4, 0x0

    .line 1349
    :cond_5d
    check-cast v4, Ljava/util/List;

    .line 1350
    .line 1351
    check-cast v4, Ljava/util/Collection;

    .line 1352
    .line 1353
    if-eqz v4, :cond_5f

    .line 1354
    .line 1355
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 1356
    .line 1357
    .line 1358
    move-result v4

    .line 1359
    if-eqz v4, :cond_5e

    .line 1360
    .line 1361
    goto :goto_27

    .line 1362
    :cond_5e
    const/4 v4, 0x0

    .line 1363
    goto :goto_28

    .line 1364
    :cond_5f
    :goto_27
    const/4 v4, 0x1

    .line 1365
    :goto_28
    if-eqz v4, :cond_68

    .line 1366
    .line 1367
    sget-object v4, Ld4/k;->a:Ld4/z;

    .line 1368
    .line 1369
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1370
    .line 1371
    .line 1372
    move-result v4

    .line 1373
    if-eqz v4, :cond_68

    .line 1374
    .line 1375
    sget-object v4, Ld4/v;->E:Ld4/z;

    .line 1376
    .line 1377
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1378
    .line 1379
    .line 1380
    move-result v4

    .line 1381
    if-eqz v4, :cond_61

    .line 1382
    .line 1383
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1384
    .line 1385
    .line 1386
    move-result-object v4

    .line 1387
    if-nez v4, :cond_60

    .line 1388
    .line 1389
    const/4 v4, 0x0

    .line 1390
    :cond_60
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1391
    .line 1392
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1393
    .line 1394
    .line 1395
    move-result v4

    .line 1396
    if-nez v4, :cond_61

    .line 1397
    .line 1398
    goto :goto_2d

    .line 1399
    :cond_61
    invoke-virtual/range {v18 .. v18}, Lv3/h0;->v()Lv3/h0;

    .line 1400
    .line 1401
    .line 1402
    move-result-object v4

    .line 1403
    :goto_29
    if-eqz v4, :cond_64

    .line 1404
    .line 1405
    invoke-virtual {v4}, Lv3/h0;->x()Ld4/l;

    .line 1406
    .line 1407
    .line 1408
    move-result-object v7

    .line 1409
    if-eqz v7, :cond_62

    .line 1410
    .line 1411
    iget-boolean v10, v7, Ld4/l;->f:Z

    .line 1412
    .line 1413
    const/4 v11, 0x1

    .line 1414
    if-ne v10, v11, :cond_62

    .line 1415
    .line 1416
    sget-object v10, Ld4/v;->E:Ld4/z;

    .line 1417
    .line 1418
    iget-object v7, v7, Ld4/l;->d:Landroidx/collection/q0;

    .line 1419
    .line 1420
    invoke-virtual {v7, v10}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1421
    .line 1422
    .line 1423
    move-result v7

    .line 1424
    if-eqz v7, :cond_62

    .line 1425
    .line 1426
    const/4 v7, 0x1

    .line 1427
    goto :goto_2a

    .line 1428
    :cond_62
    const/4 v7, 0x0

    .line 1429
    :goto_2a
    if-eqz v7, :cond_63

    .line 1430
    .line 1431
    goto :goto_2b

    .line 1432
    :cond_63
    invoke-virtual {v4}, Lv3/h0;->v()Lv3/h0;

    .line 1433
    .line 1434
    .line 1435
    move-result-object v4

    .line 1436
    goto :goto_29

    .line 1437
    :cond_64
    const/4 v4, 0x0

    .line 1438
    :goto_2b
    if-eqz v4, :cond_67

    .line 1439
    .line 1440
    invoke-virtual {v4}, Lv3/h0;->x()Ld4/l;

    .line 1441
    .line 1442
    .line 1443
    move-result-object v4

    .line 1444
    if-eqz v4, :cond_66

    .line 1445
    .line 1446
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 1447
    .line 1448
    invoke-virtual {v4, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1449
    .line 1450
    .line 1451
    move-result-object v2

    .line 1452
    if-nez v2, :cond_65

    .line 1453
    .line 1454
    const/4 v2, 0x0

    .line 1455
    :cond_65
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 1456
    .line 1457
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1458
    .line 1459
    .line 1460
    move-result v2

    .line 1461
    goto :goto_2c

    .line 1462
    :cond_66
    const/4 v2, 0x0

    .line 1463
    :goto_2c
    if-nez v2, :cond_67

    .line 1464
    .line 1465
    :goto_2d
    const/4 v2, 0x1

    .line 1466
    goto :goto_2e

    .line 1467
    :cond_67
    const/4 v2, 0x0

    .line 1468
    :goto_2e
    if-nez v2, :cond_68

    .line 1469
    .line 1470
    invoke-virtual {v12}, Landroid/view/accessibility/AccessibilityNodeInfo;->getMovementGranularities()I

    .line 1471
    .line 1472
    .line 1473
    move-result v2

    .line 1474
    or-int/lit8 v2, v2, 0x14

    .line 1475
    .line 1476
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setMovementGranularities(I)V

    .line 1477
    .line 1478
    .line 1479
    :cond_68
    new-instance v2, Ljava/util/ArrayList;

    .line 1480
    .line 1481
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1482
    .line 1483
    .line 1484
    const-string v4, "androidx.compose.ui.semantics.id"

    .line 1485
    .line 1486
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1487
    .line 1488
    .line 1489
    invoke-virtual {v13}, Le6/d;->g()Ljava/lang/CharSequence;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v4

    .line 1493
    if-eqz v4, :cond_6a

    .line 1494
    .line 1495
    invoke-interface {v4}, Ljava/lang/CharSequence;->length()I

    .line 1496
    .line 1497
    .line 1498
    move-result v4

    .line 1499
    if-nez v4, :cond_69

    .line 1500
    .line 1501
    goto :goto_2f

    .line 1502
    :cond_69
    const/4 v4, 0x0

    .line 1503
    goto :goto_30

    .line 1504
    :cond_6a
    :goto_2f
    const/4 v4, 0x1

    .line 1505
    :goto_30
    if-nez v4, :cond_6b

    .line 1506
    .line 1507
    sget-object v4, Ld4/k;->a:Ld4/z;

    .line 1508
    .line 1509
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1510
    .line 1511
    .line 1512
    move-result v4

    .line 1513
    if-eqz v4, :cond_6b

    .line 1514
    .line 1515
    const-string v4, "android.view.accessibility.extra.DATA_TEXT_CHARACTER_LOCATION_KEY"

    .line 1516
    .line 1517
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1518
    .line 1519
    .line 1520
    :cond_6b
    sget-object v4, Ld4/v;->y:Ld4/z;

    .line 1521
    .line 1522
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1523
    .line 1524
    .line 1525
    move-result v4

    .line 1526
    if-eqz v4, :cond_6c

    .line 1527
    .line 1528
    const-string v4, "androidx.compose.ui.semantics.testTag"

    .line 1529
    .line 1530
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1531
    .line 1532
    .line 1533
    :cond_6c
    sget-object v4, Ld4/v;->O:Ld4/z;

    .line 1534
    .line 1535
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1536
    .line 1537
    .line 1538
    move-result v4

    .line 1539
    if-eqz v4, :cond_6d

    .line 1540
    .line 1541
    const-string v4, "androidx.compose.ui.semantics.shapeType"

    .line 1542
    .line 1543
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1544
    .line 1545
    .line 1546
    const-string v4, "androidx.compose.ui.semantics.shapeRect"

    .line 1547
    .line 1548
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1549
    .line 1550
    .line 1551
    const-string v4, "androidx.compose.ui.semantics.shapeCorners"

    .line 1552
    .line 1553
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1554
    .line 1555
    .line 1556
    const-string v4, "androidx.compose.ui.semantics.shapeRegion"

    .line 1557
    .line 1558
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1559
    .line 1560
    .line 1561
    :cond_6d
    invoke-virtual {v12, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setAvailableExtraData(Ljava/util/List;)V

    .line 1562
    .line 1563
    .line 1564
    sget-object v2, Ld4/v;->c:Ld4/z;

    .line 1565
    .line 1566
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1567
    .line 1568
    .line 1569
    move-result-object v2

    .line 1570
    if-nez v2, :cond_6e

    .line 1571
    .line 1572
    const/4 v2, 0x0

    .line 1573
    :cond_6e
    check-cast v2, Ld4/h;

    .line 1574
    .line 1575
    if-eqz v2, :cond_74

    .line 1576
    .line 1577
    iget v4, v2, Ld4/h;->a:F

    .line 1578
    .line 1579
    iget-object v7, v2, Ld4/h;->b:Lgy0/e;

    .line 1580
    .line 1581
    sget-object v10, Ld4/k;->h:Ld4/z;

    .line 1582
    .line 1583
    invoke-virtual {v5, v10}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1584
    .line 1585
    .line 1586
    move-result v11

    .line 1587
    if-eqz v11, :cond_6f

    .line 1588
    .line 1589
    const-string v11, "android.widget.SeekBar"

    .line 1590
    .line 1591
    invoke-virtual {v13, v11}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 1592
    .line 1593
    .line 1594
    goto :goto_31

    .line 1595
    :cond_6f
    const-string v11, "android.widget.ProgressBar"

    .line 1596
    .line 1597
    invoke-virtual {v13, v11}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 1598
    .line 1599
    .line 1600
    :goto_31
    sget-object v11, Ld4/h;->d:Ld4/h;

    .line 1601
    .line 1602
    if-eq v2, v11, :cond_70

    .line 1603
    .line 1604
    iget v2, v7, Lgy0/e;->d:F

    .line 1605
    .line 1606
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1607
    .line 1608
    .line 1609
    move-result-object v2

    .line 1610
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1611
    .line 1612
    .line 1613
    move-result v2

    .line 1614
    iget v11, v7, Lgy0/e;->e:F

    .line 1615
    .line 1616
    invoke-static {v11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1617
    .line 1618
    .line 1619
    move-result-object v11

    .line 1620
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 1621
    .line 1622
    .line 1623
    move-result v11

    .line 1624
    const/4 v12, 0x1

    .line 1625
    invoke-static {v12, v2, v11, v4}, Landroid/view/accessibility/AccessibilityNodeInfo$RangeInfo;->obtain(IFFF)Landroid/view/accessibility/AccessibilityNodeInfo$RangeInfo;

    .line 1626
    .line 1627
    .line 1628
    move-result-object v2

    .line 1629
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setRangeInfo(Landroid/view/accessibility/AccessibilityNodeInfo$RangeInfo;)V

    .line 1630
    .line 1631
    .line 1632
    :cond_70
    invoke-virtual {v5, v10}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1633
    .line 1634
    .line 1635
    move-result v2

    .line 1636
    if-eqz v2, :cond_74

    .line 1637
    .line 1638
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 1639
    .line 1640
    .line 1641
    move-result v2

    .line 1642
    if-eqz v2, :cond_74

    .line 1643
    .line 1644
    iget v2, v7, Lgy0/e;->e:F

    .line 1645
    .line 1646
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1647
    .line 1648
    .line 1649
    move-result-object v2

    .line 1650
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1651
    .line 1652
    .line 1653
    move-result v2

    .line 1654
    iget v5, v7, Lgy0/e;->d:F

    .line 1655
    .line 1656
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1657
    .line 1658
    .line 1659
    move-result-object v5

    .line 1660
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 1661
    .line 1662
    .line 1663
    move-result v5

    .line 1664
    cmpg-float v10, v2, v5

    .line 1665
    .line 1666
    if-gez v10, :cond_71

    .line 1667
    .line 1668
    move v2, v5

    .line 1669
    :cond_71
    cmpg-float v2, v4, v2

    .line 1670
    .line 1671
    if-gez v2, :cond_72

    .line 1672
    .line 1673
    sget-object v2, Le6/c;->h:Le6/c;

    .line 1674
    .line 1675
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 1676
    .line 1677
    .line 1678
    :cond_72
    iget v2, v7, Lgy0/e;->d:F

    .line 1679
    .line 1680
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1681
    .line 1682
    .line 1683
    move-result-object v2

    .line 1684
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1685
    .line 1686
    .line 1687
    move-result v2

    .line 1688
    iget v5, v7, Lgy0/e;->e:F

    .line 1689
    .line 1690
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1691
    .line 1692
    .line 1693
    move-result-object v5

    .line 1694
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 1695
    .line 1696
    .line 1697
    move-result v5

    .line 1698
    cmpl-float v7, v2, v5

    .line 1699
    .line 1700
    if-lez v7, :cond_73

    .line 1701
    .line 1702
    move v2, v5

    .line 1703
    :cond_73
    cmpl-float v2, v4, v2

    .line 1704
    .line 1705
    if-lez v2, :cond_74

    .line 1706
    .line 1707
    sget-object v2, Le6/c;->i:Le6/c;

    .line 1708
    .line 1709
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 1710
    .line 1711
    .line 1712
    :cond_74
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 1713
    .line 1714
    .line 1715
    move-result v2

    .line 1716
    if-eqz v2, :cond_76

    .line 1717
    .line 1718
    sget-object v2, Ld4/k;->h:Ld4/z;

    .line 1719
    .line 1720
    iget-object v4, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 1721
    .line 1722
    invoke-virtual {v4, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1723
    .line 1724
    .line 1725
    move-result-object v2

    .line 1726
    if-nez v2, :cond_75

    .line 1727
    .line 1728
    const/4 v2, 0x0

    .line 1729
    :cond_75
    check-cast v2, Ld4/a;

    .line 1730
    .line 1731
    if-eqz v2, :cond_76

    .line 1732
    .line 1733
    new-instance v4, Le6/c;

    .line 1734
    .line 1735
    const v5, 0x102003d

    .line 1736
    .line 1737
    .line 1738
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 1739
    .line 1740
    invoke-direct {v4, v5, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 1741
    .line 1742
    .line 1743
    invoke-virtual {v13, v4}, Le6/d;->b(Le6/c;)V

    .line 1744
    .line 1745
    .line 1746
    :cond_76
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 1747
    .line 1748
    .line 1749
    move-result-object v2

    .line 1750
    sget-object v4, Ld4/v;->f:Ld4/z;

    .line 1751
    .line 1752
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 1753
    .line 1754
    invoke-virtual {v2, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1755
    .line 1756
    .line 1757
    move-result-object v2

    .line 1758
    if-nez v2, :cond_77

    .line 1759
    .line 1760
    const/4 v2, 0x0

    .line 1761
    :cond_77
    check-cast v2, Ld4/b;

    .line 1762
    .line 1763
    if-eqz v2, :cond_78

    .line 1764
    .line 1765
    iget v4, v2, Ld4/b;->a:I

    .line 1766
    .line 1767
    iget v2, v2, Ld4/b;->b:I

    .line 1768
    .line 1769
    const/4 v5, 0x0

    .line 1770
    invoke-static {v4, v2, v5, v5}, Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;->obtain(IIZI)Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;

    .line 1771
    .line 1772
    .line 1773
    move-result-object v2

    .line 1774
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCollectionInfo(Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;)V

    .line 1775
    .line 1776
    .line 1777
    goto :goto_36

    .line 1778
    :cond_78
    new-instance v2, Ljava/util/ArrayList;

    .line 1779
    .line 1780
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1781
    .line 1782
    .line 1783
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 1784
    .line 1785
    .line 1786
    move-result-object v4

    .line 1787
    sget-object v5, Ld4/v;->e:Ld4/z;

    .line 1788
    .line 1789
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 1790
    .line 1791
    invoke-virtual {v4, v5}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1792
    .line 1793
    .line 1794
    move-result-object v4

    .line 1795
    if-nez v4, :cond_79

    .line 1796
    .line 1797
    const/4 v4, 0x0

    .line 1798
    :cond_79
    if-eqz v4, :cond_7b

    .line 1799
    .line 1800
    const/4 v11, 0x4

    .line 1801
    invoke-static {v11, v6}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 1802
    .line 1803
    .line 1804
    move-result-object v4

    .line 1805
    move-object v5, v4

    .line 1806
    check-cast v5, Ljava/util/Collection;

    .line 1807
    .line 1808
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 1809
    .line 1810
    .line 1811
    move-result v5

    .line 1812
    const/4 v7, 0x0

    .line 1813
    :goto_32
    if-ge v7, v5, :cond_7b

    .line 1814
    .line 1815
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1816
    .line 1817
    .line 1818
    move-result-object v10

    .line 1819
    check-cast v10, Ld4/q;

    .line 1820
    .line 1821
    invoke-virtual {v10}, Ld4/q;->k()Ld4/l;

    .line 1822
    .line 1823
    .line 1824
    move-result-object v11

    .line 1825
    sget-object v12, Ld4/v;->H:Ld4/z;

    .line 1826
    .line 1827
    iget-object v11, v11, Ld4/l;->d:Landroidx/collection/q0;

    .line 1828
    .line 1829
    invoke-virtual {v11, v12}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1830
    .line 1831
    .line 1832
    move-result v11

    .line 1833
    if-eqz v11, :cond_7a

    .line 1834
    .line 1835
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1836
    .line 1837
    .line 1838
    :cond_7a
    add-int/lit8 v7, v7, 0x1

    .line 1839
    .line 1840
    goto :goto_32

    .line 1841
    :cond_7b
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1842
    .line 1843
    .line 1844
    move-result v4

    .line 1845
    if-nez v4, :cond_7e

    .line 1846
    .line 1847
    invoke-static {v2}, Llp/fe;->a(Ljava/util/ArrayList;)Z

    .line 1848
    .line 1849
    .line 1850
    move-result v4

    .line 1851
    if-eqz v4, :cond_7c

    .line 1852
    .line 1853
    const/4 v5, 0x1

    .line 1854
    goto :goto_33

    .line 1855
    :cond_7c
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 1856
    .line 1857
    .line 1858
    move-result v5

    .line 1859
    :goto_33
    if-eqz v4, :cond_7d

    .line 1860
    .line 1861
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 1862
    .line 1863
    .line 1864
    move-result v2

    .line 1865
    :goto_34
    const/4 v4, 0x0

    .line 1866
    goto :goto_35

    .line 1867
    :cond_7d
    const/4 v2, 0x1

    .line 1868
    goto :goto_34

    .line 1869
    :goto_35
    invoke-static {v5, v2, v4, v4}, Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;->obtain(IIZI)Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;

    .line 1870
    .line 1871
    .line 1872
    move-result-object v2

    .line 1873
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCollectionInfo(Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;)V

    .line 1874
    .line 1875
    .line 1876
    :cond_7e
    :goto_36
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 1877
    .line 1878
    .line 1879
    move-result-object v2

    .line 1880
    sget-object v4, Ld4/v;->g:Ld4/z;

    .line 1881
    .line 1882
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 1883
    .line 1884
    invoke-virtual {v2, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1885
    .line 1886
    .line 1887
    move-result-object v2

    .line 1888
    const/4 v4, 0x0

    .line 1889
    if-nez v2, :cond_7f

    .line 1890
    .line 1891
    move-object v2, v4

    .line 1892
    :cond_7f
    if-nez v2, :cond_c4

    .line 1893
    .line 1894
    invoke-virtual {v6}, Ld4/q;->l()Ld4/q;

    .line 1895
    .line 1896
    .line 1897
    move-result-object v2

    .line 1898
    if-nez v2, :cond_80

    .line 1899
    .line 1900
    goto/16 :goto_3b

    .line 1901
    .line 1902
    :cond_80
    invoke-virtual {v2}, Ld4/q;->k()Ld4/l;

    .line 1903
    .line 1904
    .line 1905
    move-result-object v5

    .line 1906
    sget-object v7, Ld4/v;->e:Ld4/z;

    .line 1907
    .line 1908
    iget-object v5, v5, Ld4/l;->d:Landroidx/collection/q0;

    .line 1909
    .line 1910
    invoke-virtual {v5, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1911
    .line 1912
    .line 1913
    move-result-object v5

    .line 1914
    if-nez v5, :cond_81

    .line 1915
    .line 1916
    move-object v5, v4

    .line 1917
    :cond_81
    if-eqz v5, :cond_8a

    .line 1918
    .line 1919
    invoke-virtual {v2}, Ld4/q;->k()Ld4/l;

    .line 1920
    .line 1921
    .line 1922
    move-result-object v5

    .line 1923
    sget-object v7, Ld4/v;->f:Ld4/z;

    .line 1924
    .line 1925
    iget-object v5, v5, Ld4/l;->d:Landroidx/collection/q0;

    .line 1926
    .line 1927
    invoke-virtual {v5, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1928
    .line 1929
    .line 1930
    move-result-object v5

    .line 1931
    if-nez v5, :cond_82

    .line 1932
    .line 1933
    goto :goto_37

    .line 1934
    :cond_82
    move-object v4, v5

    .line 1935
    :goto_37
    check-cast v4, Ld4/b;

    .line 1936
    .line 1937
    if-eqz v4, :cond_83

    .line 1938
    .line 1939
    iget v5, v4, Ld4/b;->a:I

    .line 1940
    .line 1941
    if-ltz v5, :cond_8a

    .line 1942
    .line 1943
    iget v4, v4, Ld4/b;->b:I

    .line 1944
    .line 1945
    if-gez v4, :cond_83

    .line 1946
    .line 1947
    goto/16 :goto_3b

    .line 1948
    .line 1949
    :cond_83
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 1950
    .line 1951
    .line 1952
    move-result-object v4

    .line 1953
    sget-object v5, Ld4/v;->H:Ld4/z;

    .line 1954
    .line 1955
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 1956
    .line 1957
    invoke-virtual {v4, v5}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1958
    .line 1959
    .line 1960
    move-result v4

    .line 1961
    if-nez v4, :cond_84

    .line 1962
    .line 1963
    goto/16 :goto_3b

    .line 1964
    .line 1965
    :cond_84
    new-instance v4, Ljava/util/ArrayList;

    .line 1966
    .line 1967
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1968
    .line 1969
    .line 1970
    const/4 v5, 0x4

    .line 1971
    invoke-static {v5, v2}, Ld4/q;->j(ILd4/q;)Ljava/util/List;

    .line 1972
    .line 1973
    .line 1974
    move-result-object v2

    .line 1975
    move-object v5, v2

    .line 1976
    check-cast v5, Ljava/util/Collection;

    .line 1977
    .line 1978
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 1979
    .line 1980
    .line 1981
    move-result v5

    .line 1982
    const/4 v10, 0x0

    .line 1983
    const/4 v11, 0x0

    .line 1984
    :goto_38
    if-ge v10, v5, :cond_86

    .line 1985
    .line 1986
    invoke-interface {v2, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1987
    .line 1988
    .line 1989
    move-result-object v12

    .line 1990
    check-cast v12, Ld4/q;

    .line 1991
    .line 1992
    invoke-virtual {v12}, Ld4/q;->k()Ld4/l;

    .line 1993
    .line 1994
    .line 1995
    move-result-object v14

    .line 1996
    sget-object v7, Ld4/v;->H:Ld4/z;

    .line 1997
    .line 1998
    iget-object v14, v14, Ld4/l;->d:Landroidx/collection/q0;

    .line 1999
    .line 2000
    invoke-virtual {v14, v7}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 2001
    .line 2002
    .line 2003
    move-result v7

    .line 2004
    if-eqz v7, :cond_85

    .line 2005
    .line 2006
    invoke-virtual {v4, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2007
    .line 2008
    .line 2009
    iget-object v7, v12, Ld4/q;->c:Lv3/h0;

    .line 2010
    .line 2011
    invoke-virtual {v7}, Lv3/h0;->w()I

    .line 2012
    .line 2013
    .line 2014
    move-result v7

    .line 2015
    iget-object v12, v6, Ld4/q;->c:Lv3/h0;

    .line 2016
    .line 2017
    invoke-virtual {v12}, Lv3/h0;->w()I

    .line 2018
    .line 2019
    .line 2020
    move-result v12

    .line 2021
    if-ge v7, v12, :cond_85

    .line 2022
    .line 2023
    add-int/lit8 v11, v11, 0x1

    .line 2024
    .line 2025
    :cond_85
    add-int/lit8 v10, v10, 0x1

    .line 2026
    .line 2027
    goto :goto_38

    .line 2028
    :cond_86
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 2029
    .line 2030
    .line 2031
    move-result v2

    .line 2032
    if-nez v2, :cond_8a

    .line 2033
    .line 2034
    invoke-static {v4}, Llp/fe;->a(Ljava/util/ArrayList;)Z

    .line 2035
    .line 2036
    .line 2037
    move-result v2

    .line 2038
    if-eqz v2, :cond_87

    .line 2039
    .line 2040
    const/16 v23, 0x0

    .line 2041
    .line 2042
    goto :goto_39

    .line 2043
    :cond_87
    move/from16 v23, v11

    .line 2044
    .line 2045
    :goto_39
    if-eqz v2, :cond_88

    .line 2046
    .line 2047
    move/from16 v25, v11

    .line 2048
    .line 2049
    goto :goto_3a

    .line 2050
    :cond_88
    const/16 v25, 0x0

    .line 2051
    .line 2052
    :goto_3a
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 2053
    .line 2054
    .line 2055
    move-result-object v2

    .line 2056
    sget-object v4, Ld4/v;->H:Ld4/z;

    .line 2057
    .line 2058
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 2059
    .line 2060
    invoke-virtual {v2, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2061
    .line 2062
    .line 2063
    move-result-object v2

    .line 2064
    if-nez v2, :cond_89

    .line 2065
    .line 2066
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 2067
    .line 2068
    :cond_89
    check-cast v2, Ljava/lang/Boolean;

    .line 2069
    .line 2070
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 2071
    .line 2072
    .line 2073
    move-result v28

    .line 2074
    const/16 v27, 0x0

    .line 2075
    .line 2076
    const/16 v24, 0x1

    .line 2077
    .line 2078
    const/16 v26, 0x1

    .line 2079
    .line 2080
    invoke-static/range {v23 .. v28}, Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;->obtain(IIIIZZ)Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;

    .line 2081
    .line 2082
    .line 2083
    move-result-object v2

    .line 2084
    iget-object v4, v13, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 2085
    .line 2086
    invoke-virtual {v4, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCollectionItemInfo(Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;)V

    .line 2087
    .line 2088
    .line 2089
    :cond_8a
    :goto_3b
    sget-object v2, Ld4/v;->t:Ld4/z;

    .line 2090
    .line 2091
    iget-object v4, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 2092
    .line 2093
    invoke-virtual {v4, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2094
    .line 2095
    .line 2096
    move-result-object v2

    .line 2097
    if-nez v2, :cond_8b

    .line 2098
    .line 2099
    const/4 v2, 0x0

    .line 2100
    :cond_8b
    check-cast v2, Ld4/j;

    .line 2101
    .line 2102
    sget-object v4, Ld4/k;->d:Ld4/z;

    .line 2103
    .line 2104
    iget-object v5, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 2105
    .line 2106
    invoke-virtual {v5, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2107
    .line 2108
    .line 2109
    move-result-object v4

    .line 2110
    if-nez v4, :cond_8c

    .line 2111
    .line 2112
    const/4 v4, 0x0

    .line 2113
    :cond_8c
    check-cast v4, Ld4/a;

    .line 2114
    .line 2115
    const/4 v5, 0x0

    .line 2116
    if-eqz v2, :cond_98

    .line 2117
    .line 2118
    if-eqz v4, :cond_98

    .line 2119
    .line 2120
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 2121
    .line 2122
    .line 2123
    move-result-object v7

    .line 2124
    sget-object v10, Ld4/v;->f:Ld4/z;

    .line 2125
    .line 2126
    iget-object v7, v7, Ld4/l;->d:Landroidx/collection/q0;

    .line 2127
    .line 2128
    invoke-virtual {v7, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2129
    .line 2130
    .line 2131
    move-result-object v7

    .line 2132
    if-nez v7, :cond_8d

    .line 2133
    .line 2134
    const/4 v7, 0x0

    .line 2135
    :cond_8d
    if-nez v7, :cond_90

    .line 2136
    .line 2137
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 2138
    .line 2139
    .line 2140
    move-result-object v7

    .line 2141
    sget-object v10, Ld4/v;->e:Ld4/z;

    .line 2142
    .line 2143
    iget-object v7, v7, Ld4/l;->d:Landroidx/collection/q0;

    .line 2144
    .line 2145
    invoke-virtual {v7, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2146
    .line 2147
    .line 2148
    move-result-object v7

    .line 2149
    if-nez v7, :cond_8e

    .line 2150
    .line 2151
    const/4 v7, 0x0

    .line 2152
    :cond_8e
    if-eqz v7, :cond_8f

    .line 2153
    .line 2154
    goto :goto_3c

    .line 2155
    :cond_8f
    const/4 v7, 0x0

    .line 2156
    goto :goto_3d

    .line 2157
    :cond_90
    :goto_3c
    const/4 v7, 0x1

    .line 2158
    :goto_3d
    if-nez v7, :cond_91

    .line 2159
    .line 2160
    const-string v7, "android.widget.HorizontalScrollView"

    .line 2161
    .line 2162
    invoke-virtual {v13, v7}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 2163
    .line 2164
    .line 2165
    :cond_91
    iget-object v7, v2, Ld4/j;->b:Lay0/a;

    .line 2166
    .line 2167
    invoke-interface {v7}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2168
    .line 2169
    .line 2170
    move-result-object v7

    .line 2171
    check-cast v7, Ljava/lang/Number;

    .line 2172
    .line 2173
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 2174
    .line 2175
    .line 2176
    move-result v7

    .line 2177
    cmpl-float v7, v7, v5

    .line 2178
    .line 2179
    if-lez v7, :cond_92

    .line 2180
    .line 2181
    const/4 v7, 0x1

    .line 2182
    invoke-virtual {v13, v7}, Le6/d;->k(Z)V

    .line 2183
    .line 2184
    .line 2185
    :cond_92
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 2186
    .line 2187
    .line 2188
    move-result v7

    .line 2189
    if-eqz v7, :cond_98

    .line 2190
    .line 2191
    invoke-static {v2}, Lw3/z;->z(Ld4/j;)Z

    .line 2192
    .line 2193
    .line 2194
    move-result v7

    .line 2195
    if-eqz v7, :cond_95

    .line 2196
    .line 2197
    sget-object v7, Le6/c;->h:Le6/c;

    .line 2198
    .line 2199
    invoke-virtual {v13, v7}, Le6/d;->b(Le6/c;)V

    .line 2200
    .line 2201
    .line 2202
    move-object/from16 v7, v18

    .line 2203
    .line 2204
    iget-object v10, v7, Lv3/h0;->B:Lt4/m;

    .line 2205
    .line 2206
    sget-object v11, Lt4/m;->e:Lt4/m;

    .line 2207
    .line 2208
    if-ne v10, v11, :cond_93

    .line 2209
    .line 2210
    const/4 v10, 0x1

    .line 2211
    goto :goto_3e

    .line 2212
    :cond_93
    const/4 v10, 0x0

    .line 2213
    :goto_3e
    if-nez v10, :cond_94

    .line 2214
    .line 2215
    sget-object v10, Le6/c;->p:Le6/c;

    .line 2216
    .line 2217
    goto :goto_3f

    .line 2218
    :cond_94
    sget-object v10, Le6/c;->n:Le6/c;

    .line 2219
    .line 2220
    :goto_3f
    invoke-virtual {v13, v10}, Le6/d;->b(Le6/c;)V

    .line 2221
    .line 2222
    .line 2223
    goto :goto_40

    .line 2224
    :cond_95
    move-object/from16 v7, v18

    .line 2225
    .line 2226
    :goto_40
    invoke-static {v2}, Lw3/z;->y(Ld4/j;)Z

    .line 2227
    .line 2228
    .line 2229
    move-result v2

    .line 2230
    if-eqz v2, :cond_98

    .line 2231
    .line 2232
    sget-object v2, Le6/c;->i:Le6/c;

    .line 2233
    .line 2234
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 2235
    .line 2236
    .line 2237
    iget-object v2, v7, Lv3/h0;->B:Lt4/m;

    .line 2238
    .line 2239
    sget-object v7, Lt4/m;->e:Lt4/m;

    .line 2240
    .line 2241
    if-ne v2, v7, :cond_96

    .line 2242
    .line 2243
    const/4 v2, 0x1

    .line 2244
    goto :goto_41

    .line 2245
    :cond_96
    const/4 v2, 0x0

    .line 2246
    :goto_41
    if-nez v2, :cond_97

    .line 2247
    .line 2248
    sget-object v2, Le6/c;->n:Le6/c;

    .line 2249
    .line 2250
    goto :goto_42

    .line 2251
    :cond_97
    sget-object v2, Le6/c;->p:Le6/c;

    .line 2252
    .line 2253
    :goto_42
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 2254
    .line 2255
    .line 2256
    :cond_98
    sget-object v2, Ld4/v;->u:Ld4/z;

    .line 2257
    .line 2258
    iget-object v7, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 2259
    .line 2260
    invoke-virtual {v7, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2261
    .line 2262
    .line 2263
    move-result-object v2

    .line 2264
    if-nez v2, :cond_99

    .line 2265
    .line 2266
    const/4 v2, 0x0

    .line 2267
    :cond_99
    check-cast v2, Ld4/j;

    .line 2268
    .line 2269
    if-eqz v2, :cond_a1

    .line 2270
    .line 2271
    if-eqz v4, :cond_a1

    .line 2272
    .line 2273
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 2274
    .line 2275
    .line 2276
    move-result-object v4

    .line 2277
    sget-object v7, Ld4/v;->f:Ld4/z;

    .line 2278
    .line 2279
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 2280
    .line 2281
    invoke-virtual {v4, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2282
    .line 2283
    .line 2284
    move-result-object v4

    .line 2285
    if-nez v4, :cond_9a

    .line 2286
    .line 2287
    const/4 v4, 0x0

    .line 2288
    :cond_9a
    if-nez v4, :cond_9d

    .line 2289
    .line 2290
    invoke-virtual {v6}, Ld4/q;->k()Ld4/l;

    .line 2291
    .line 2292
    .line 2293
    move-result-object v4

    .line 2294
    sget-object v7, Ld4/v;->e:Ld4/z;

    .line 2295
    .line 2296
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 2297
    .line 2298
    invoke-virtual {v4, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2299
    .line 2300
    .line 2301
    move-result-object v4

    .line 2302
    if-nez v4, :cond_9b

    .line 2303
    .line 2304
    const/4 v4, 0x0

    .line 2305
    :cond_9b
    if-eqz v4, :cond_9c

    .line 2306
    .line 2307
    goto :goto_43

    .line 2308
    :cond_9c
    const/4 v4, 0x0

    .line 2309
    goto :goto_44

    .line 2310
    :cond_9d
    :goto_43
    const/4 v4, 0x1

    .line 2311
    :goto_44
    if-nez v4, :cond_9e

    .line 2312
    .line 2313
    const-string v4, "android.widget.ScrollView"

    .line 2314
    .line 2315
    invoke-virtual {v13, v4}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 2316
    .line 2317
    .line 2318
    :cond_9e
    iget-object v4, v2, Ld4/j;->b:Lay0/a;

    .line 2319
    .line 2320
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2321
    .line 2322
    .line 2323
    move-result-object v4

    .line 2324
    check-cast v4, Ljava/lang/Number;

    .line 2325
    .line 2326
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 2327
    .line 2328
    .line 2329
    move-result v4

    .line 2330
    cmpl-float v4, v4, v5

    .line 2331
    .line 2332
    if-lez v4, :cond_9f

    .line 2333
    .line 2334
    const/4 v4, 0x1

    .line 2335
    invoke-virtual {v13, v4}, Le6/d;->k(Z)V

    .line 2336
    .line 2337
    .line 2338
    goto :goto_45

    .line 2339
    :cond_9f
    const/4 v4, 0x1

    .line 2340
    :goto_45
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 2341
    .line 2342
    .line 2343
    move-result v5

    .line 2344
    if-eqz v5, :cond_a2

    .line 2345
    .line 2346
    invoke-static {v2}, Lw3/z;->z(Ld4/j;)Z

    .line 2347
    .line 2348
    .line 2349
    move-result v5

    .line 2350
    if-eqz v5, :cond_a0

    .line 2351
    .line 2352
    sget-object v5, Le6/c;->h:Le6/c;

    .line 2353
    .line 2354
    invoke-virtual {v13, v5}, Le6/d;->b(Le6/c;)V

    .line 2355
    .line 2356
    .line 2357
    sget-object v5, Le6/c;->o:Le6/c;

    .line 2358
    .line 2359
    invoke-virtual {v13, v5}, Le6/d;->b(Le6/c;)V

    .line 2360
    .line 2361
    .line 2362
    :cond_a0
    invoke-static {v2}, Lw3/z;->y(Ld4/j;)Z

    .line 2363
    .line 2364
    .line 2365
    move-result v2

    .line 2366
    if-eqz v2, :cond_a2

    .line 2367
    .line 2368
    sget-object v2, Le6/c;->i:Le6/c;

    .line 2369
    .line 2370
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 2371
    .line 2372
    .line 2373
    sget-object v2, Le6/c;->m:Le6/c;

    .line 2374
    .line 2375
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 2376
    .line 2377
    .line 2378
    goto :goto_46

    .line 2379
    :cond_a1
    const/4 v4, 0x1

    .line 2380
    :cond_a2
    :goto_46
    iget-object v2, v6, Ld4/q;->d:Ld4/l;

    .line 2381
    .line 2382
    iget-object v5, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 2383
    .line 2384
    sget-object v7, Ld4/v;->x:Ld4/z;

    .line 2385
    .line 2386
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 2387
    .line 2388
    invoke-virtual {v2, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2389
    .line 2390
    .line 2391
    move-result-object v2

    .line 2392
    const/4 v7, 0x0

    .line 2393
    if-nez v2, :cond_a3

    .line 2394
    .line 2395
    move-object v2, v7

    .line 2396
    :cond_a3
    check-cast v2, Ld4/i;

    .line 2397
    .line 2398
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 2399
    .line 2400
    .line 2401
    move-result v9

    .line 2402
    if-eqz v9, :cond_ad

    .line 2403
    .line 2404
    if-nez v2, :cond_a4

    .line 2405
    .line 2406
    goto :goto_47

    .line 2407
    :cond_a4
    iget v2, v2, Ld4/i;->a:I

    .line 2408
    .line 2409
    const/16 v9, 0x8

    .line 2410
    .line 2411
    if-ne v2, v9, :cond_a5

    .line 2412
    .line 2413
    goto :goto_49

    .line 2414
    :cond_a5
    :goto_47
    sget-object v2, Ld4/k;->x:Ld4/z;

    .line 2415
    .line 2416
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2417
    .line 2418
    .line 2419
    move-result-object v2

    .line 2420
    if-nez v2, :cond_a6

    .line 2421
    .line 2422
    move-object v2, v7

    .line 2423
    :cond_a6
    check-cast v2, Ld4/a;

    .line 2424
    .line 2425
    if-eqz v2, :cond_a7

    .line 2426
    .line 2427
    new-instance v9, Le6/c;

    .line 2428
    .line 2429
    const v10, 0x1020046

    .line 2430
    .line 2431
    .line 2432
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 2433
    .line 2434
    invoke-direct {v9, v10, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2435
    .line 2436
    .line 2437
    invoke-virtual {v13, v9}, Le6/d;->b(Le6/c;)V

    .line 2438
    .line 2439
    .line 2440
    :cond_a7
    sget-object v2, Ld4/k;->z:Ld4/z;

    .line 2441
    .line 2442
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2443
    .line 2444
    .line 2445
    move-result-object v2

    .line 2446
    if-nez v2, :cond_a8

    .line 2447
    .line 2448
    move-object v2, v7

    .line 2449
    :cond_a8
    check-cast v2, Ld4/a;

    .line 2450
    .line 2451
    if-eqz v2, :cond_a9

    .line 2452
    .line 2453
    new-instance v9, Le6/c;

    .line 2454
    .line 2455
    const v10, 0x1020047

    .line 2456
    .line 2457
    .line 2458
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 2459
    .line 2460
    invoke-direct {v9, v10, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2461
    .line 2462
    .line 2463
    invoke-virtual {v13, v9}, Le6/d;->b(Le6/c;)V

    .line 2464
    .line 2465
    .line 2466
    :cond_a9
    sget-object v2, Ld4/k;->y:Ld4/z;

    .line 2467
    .line 2468
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2469
    .line 2470
    .line 2471
    move-result-object v2

    .line 2472
    if-nez v2, :cond_aa

    .line 2473
    .line 2474
    move-object v2, v7

    .line 2475
    :cond_aa
    check-cast v2, Ld4/a;

    .line 2476
    .line 2477
    if-eqz v2, :cond_ab

    .line 2478
    .line 2479
    new-instance v9, Le6/c;

    .line 2480
    .line 2481
    const v10, 0x1020048

    .line 2482
    .line 2483
    .line 2484
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 2485
    .line 2486
    invoke-direct {v9, v10, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2487
    .line 2488
    .line 2489
    invoke-virtual {v13, v9}, Le6/d;->b(Le6/c;)V

    .line 2490
    .line 2491
    .line 2492
    :cond_ab
    sget-object v2, Ld4/k;->A:Ld4/z;

    .line 2493
    .line 2494
    invoke-virtual {v5, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2495
    .line 2496
    .line 2497
    move-result-object v2

    .line 2498
    if-nez v2, :cond_ac

    .line 2499
    .line 2500
    goto :goto_48

    .line 2501
    :cond_ac
    move-object v7, v2

    .line 2502
    :goto_48
    check-cast v7, Ld4/a;

    .line 2503
    .line 2504
    if-eqz v7, :cond_ad

    .line 2505
    .line 2506
    new-instance v2, Le6/c;

    .line 2507
    .line 2508
    const v5, 0x1020049

    .line 2509
    .line 2510
    .line 2511
    iget-object v7, v7, Ld4/a;->a:Ljava/lang/String;

    .line 2512
    .line 2513
    invoke-direct {v2, v5, v7}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2514
    .line 2515
    .line 2516
    invoke-virtual {v13, v2}, Le6/d;->b(Le6/c;)V

    .line 2517
    .line 2518
    .line 2519
    :cond_ad
    :goto_49
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 2520
    .line 2521
    .line 2522
    move-result-object v2

    .line 2523
    sget-object v5, Ld4/v;->d:Ld4/z;

    .line 2524
    .line 2525
    invoke-static {v2, v5}, Ld4/t;->d(Ld4/l;Ld4/z;)Ljava/lang/Object;

    .line 2526
    .line 2527
    .line 2528
    move-result-object v2

    .line 2529
    check-cast v2, Ljava/lang/CharSequence;

    .line 2530
    .line 2531
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setPaneTitle(Ljava/lang/CharSequence;)V

    .line 2532
    .line 2533
    .line 2534
    invoke-static {v6}, Lw3/h0;->h(Ld4/q;)Z

    .line 2535
    .line 2536
    .line 2537
    move-result v2

    .line 2538
    if-eqz v2, :cond_bd

    .line 2539
    .line 2540
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 2541
    .line 2542
    .line 2543
    move-result-object v2

    .line 2544
    sget-object v5, Ld4/k;->s:Ld4/z;

    .line 2545
    .line 2546
    invoke-static {v2, v5}, Ld4/t;->d(Ld4/l;Ld4/z;)Ljava/lang/Object;

    .line 2547
    .line 2548
    .line 2549
    move-result-object v2

    .line 2550
    check-cast v2, Ld4/a;

    .line 2551
    .line 2552
    if-eqz v2, :cond_ae

    .line 2553
    .line 2554
    new-instance v5, Le6/c;

    .line 2555
    .line 2556
    const/high16 v7, 0x40000

    .line 2557
    .line 2558
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 2559
    .line 2560
    invoke-direct {v5, v7, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2561
    .line 2562
    .line 2563
    invoke-virtual {v13, v5}, Le6/d;->b(Le6/c;)V

    .line 2564
    .line 2565
    .line 2566
    :cond_ae
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 2567
    .line 2568
    .line 2569
    move-result-object v2

    .line 2570
    sget-object v5, Ld4/k;->t:Ld4/z;

    .line 2571
    .line 2572
    invoke-static {v2, v5}, Ld4/t;->d(Ld4/l;Ld4/z;)Ljava/lang/Object;

    .line 2573
    .line 2574
    .line 2575
    move-result-object v2

    .line 2576
    check-cast v2, Ld4/a;

    .line 2577
    .line 2578
    if-eqz v2, :cond_af

    .line 2579
    .line 2580
    new-instance v5, Le6/c;

    .line 2581
    .line 2582
    const/high16 v7, 0x80000

    .line 2583
    .line 2584
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 2585
    .line 2586
    invoke-direct {v5, v7, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2587
    .line 2588
    .line 2589
    invoke-virtual {v13, v5}, Le6/d;->b(Le6/c;)V

    .line 2590
    .line 2591
    .line 2592
    :cond_af
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 2593
    .line 2594
    .line 2595
    move-result-object v2

    .line 2596
    sget-object v5, Ld4/k;->u:Ld4/z;

    .line 2597
    .line 2598
    invoke-static {v2, v5}, Ld4/t;->d(Ld4/l;Ld4/z;)Ljava/lang/Object;

    .line 2599
    .line 2600
    .line 2601
    move-result-object v2

    .line 2602
    check-cast v2, Ld4/a;

    .line 2603
    .line 2604
    if-eqz v2, :cond_b0

    .line 2605
    .line 2606
    new-instance v5, Le6/c;

    .line 2607
    .line 2608
    const/high16 v7, 0x100000

    .line 2609
    .line 2610
    iget-object v2, v2, Ld4/a;->a:Ljava/lang/String;

    .line 2611
    .line 2612
    invoke-direct {v5, v7, v2}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2613
    .line 2614
    .line 2615
    invoke-virtual {v13, v5}, Le6/d;->b(Le6/c;)V

    .line 2616
    .line 2617
    .line 2618
    :cond_b0
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 2619
    .line 2620
    .line 2621
    move-result-object v2

    .line 2622
    sget-object v5, Ld4/k;->w:Ld4/z;

    .line 2623
    .line 2624
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 2625
    .line 2626
    invoke-virtual {v2, v5}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 2627
    .line 2628
    .line 2629
    move-result v2

    .line 2630
    if-eqz v2, :cond_bd

    .line 2631
    .line 2632
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 2633
    .line 2634
    .line 2635
    move-result-object v2

    .line 2636
    invoke-virtual {v2, v5}, Ld4/l;->e(Ld4/z;)Ljava/lang/Object;

    .line 2637
    .line 2638
    .line 2639
    move-result-object v2

    .line 2640
    check-cast v2, Ljava/util/List;

    .line 2641
    .line 2642
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 2643
    .line 2644
    .line 2645
    move-result v5

    .line 2646
    move-object/from16 v7, v22

    .line 2647
    .line 2648
    iget v9, v7, Landroidx/collection/a0;->b:I

    .line 2649
    .line 2650
    if-ge v5, v9, :cond_bc

    .line 2651
    .line 2652
    new-instance v5, Landroidx/collection/b1;

    .line 2653
    .line 2654
    const/4 v9, 0x0

    .line 2655
    invoke-direct {v5, v9}, Landroidx/collection/b1;-><init>(I)V

    .line 2656
    .line 2657
    .line 2658
    invoke-static {}, Landroidx/collection/v0;->a()Landroidx/collection/h0;

    .line 2659
    .line 2660
    .line 2661
    move-result-object v10

    .line 2662
    move-object/from16 v11, v21

    .line 2663
    .line 2664
    iget-boolean v12, v11, Landroidx/collection/b1;->d:Z

    .line 2665
    .line 2666
    if-eqz v12, :cond_b1

    .line 2667
    .line 2668
    invoke-static {v11}, Landroidx/collection/v;->a(Landroidx/collection/b1;)V

    .line 2669
    .line 2670
    .line 2671
    :cond_b1
    iget-object v12, v11, Landroidx/collection/b1;->e:[I

    .line 2672
    .line 2673
    iget v14, v11, Landroidx/collection/b1;->g:I

    .line 2674
    .line 2675
    invoke-static {v14, v1, v12}, La1/a;->a(II[I)I

    .line 2676
    .line 2677
    .line 2678
    move-result v12

    .line 2679
    if-ltz v12, :cond_b2

    .line 2680
    .line 2681
    const/4 v12, 0x1

    .line 2682
    goto :goto_4a

    .line 2683
    :cond_b2
    const/4 v12, 0x0

    .line 2684
    :goto_4a
    if-eqz v12, :cond_ba

    .line 2685
    .line 2686
    invoke-virtual {v11, v1}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 2687
    .line 2688
    .line 2689
    move-result-object v12

    .line 2690
    check-cast v12, Landroidx/collection/h0;

    .line 2691
    .line 2692
    new-instance v14, Landroidx/collection/a0;

    .line 2693
    .line 2694
    invoke-direct {v14}, Landroidx/collection/a0;-><init>()V

    .line 2695
    .line 2696
    .line 2697
    iget-object v4, v7, Landroidx/collection/a0;->a:[I

    .line 2698
    .line 2699
    iget v7, v7, Landroidx/collection/a0;->b:I

    .line 2700
    .line 2701
    :goto_4b
    if-ge v9, v7, :cond_b3

    .line 2702
    .line 2703
    move-object/from16 v17, v4

    .line 2704
    .line 2705
    aget v4, v17, v9

    .line 2706
    .line 2707
    invoke-virtual {v14, v4}, Landroidx/collection/a0;->a(I)V

    .line 2708
    .line 2709
    .line 2710
    add-int/lit8 v9, v9, 0x1

    .line 2711
    .line 2712
    move-object/from16 v4, v17

    .line 2713
    .line 2714
    goto :goto_4b

    .line 2715
    :cond_b3
    new-instance v4, Ljava/util/ArrayList;

    .line 2716
    .line 2717
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 2718
    .line 2719
    .line 2720
    move-object v7, v2

    .line 2721
    check-cast v7, Ljava/util/Collection;

    .line 2722
    .line 2723
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 2724
    .line 2725
    .line 2726
    move-result v7

    .line 2727
    const/4 v9, 0x0

    .line 2728
    :goto_4c
    if-ge v9, v7, :cond_b9

    .line 2729
    .line 2730
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 2731
    .line 2732
    .line 2733
    move-result-object v17

    .line 2734
    move/from16 v18, v7

    .line 2735
    .line 2736
    move-object/from16 v7, v17

    .line 2737
    .line 2738
    check-cast v7, Ld4/d;

    .line 2739
    .line 2740
    invoke-static {v12}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2741
    .line 2742
    .line 2743
    move/from16 v17, v9

    .line 2744
    .line 2745
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2746
    .line 2747
    .line 2748
    move-result-object v9

    .line 2749
    invoke-virtual {v12, v9}, Landroidx/collection/h0;->d(Ljava/lang/Object;)I

    .line 2750
    .line 2751
    .line 2752
    move-result v9

    .line 2753
    if-ltz v9, :cond_b4

    .line 2754
    .line 2755
    const/4 v9, 0x1

    .line 2756
    goto :goto_4d

    .line 2757
    :cond_b4
    const/4 v9, 0x0

    .line 2758
    :goto_4d
    if-eqz v9, :cond_b8

    .line 2759
    .line 2760
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2761
    .line 2762
    .line 2763
    move-result-object v9

    .line 2764
    invoke-virtual {v12, v9}, Landroidx/collection/h0;->e(Ljava/lang/Object;)I

    .line 2765
    .line 2766
    .line 2767
    move-result v9

    .line 2768
    move-object/from16 v19, v12

    .line 2769
    .line 2770
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2771
    .line 2772
    .line 2773
    move-result-object v12

    .line 2774
    invoke-virtual {v5, v9, v12}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 2775
    .line 2776
    .line 2777
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2778
    .line 2779
    .line 2780
    move-result-object v12

    .line 2781
    invoke-virtual {v10, v9, v12}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 2782
    .line 2783
    .line 2784
    iget-object v12, v14, Landroidx/collection/a0;->a:[I

    .line 2785
    .line 2786
    move-object/from16 v20, v12

    .line 2787
    .line 2788
    iget v12, v14, Landroidx/collection/a0;->b:I

    .line 2789
    .line 2790
    const/16 v21, 0x0

    .line 2791
    .line 2792
    move-object/from16 v22, v3

    .line 2793
    .line 2794
    move/from16 v3, v21

    .line 2795
    .line 2796
    :goto_4e
    if-ge v3, v12, :cond_b6

    .line 2797
    .line 2798
    move/from16 v21, v3

    .line 2799
    .line 2800
    aget v3, v20, v21

    .line 2801
    .line 2802
    if-ne v9, v3, :cond_b5

    .line 2803
    .line 2804
    move/from16 v3, v21

    .line 2805
    .line 2806
    goto :goto_4f

    .line 2807
    :cond_b5
    add-int/lit8 v3, v21, 0x1

    .line 2808
    .line 2809
    goto :goto_4e

    .line 2810
    :cond_b6
    const/4 v3, -0x1

    .line 2811
    :goto_4f
    if-ltz v3, :cond_b7

    .line 2812
    .line 2813
    invoke-virtual {v14, v3}, Landroidx/collection/a0;->e(I)V

    .line 2814
    .line 2815
    .line 2816
    :cond_b7
    new-instance v3, Le6/c;

    .line 2817
    .line 2818
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2819
    .line 2820
    .line 2821
    move-result-object v7

    .line 2822
    invoke-direct {v3, v9, v7}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2823
    .line 2824
    .line 2825
    invoke-virtual {v13, v3}, Le6/d;->b(Le6/c;)V

    .line 2826
    .line 2827
    .line 2828
    goto :goto_50

    .line 2829
    :cond_b8
    move-object/from16 v22, v3

    .line 2830
    .line 2831
    move-object/from16 v19, v12

    .line 2832
    .line 2833
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2834
    .line 2835
    .line 2836
    :goto_50
    add-int/lit8 v9, v17, 0x1

    .line 2837
    .line 2838
    move/from16 v7, v18

    .line 2839
    .line 2840
    move-object/from16 v12, v19

    .line 2841
    .line 2842
    move-object/from16 v3, v22

    .line 2843
    .line 2844
    goto :goto_4c

    .line 2845
    :cond_b9
    move-object/from16 v22, v3

    .line 2846
    .line 2847
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 2848
    .line 2849
    .line 2850
    move-result v2

    .line 2851
    const/4 v3, 0x0

    .line 2852
    :goto_51
    if-ge v3, v2, :cond_bb

    .line 2853
    .line 2854
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2855
    .line 2856
    .line 2857
    move-result-object v7

    .line 2858
    check-cast v7, Ld4/d;

    .line 2859
    .line 2860
    invoke-virtual {v14, v3}, Landroidx/collection/a0;->c(I)I

    .line 2861
    .line 2862
    .line 2863
    move-result v9

    .line 2864
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2865
    .line 2866
    .line 2867
    move-result-object v12

    .line 2868
    invoke-virtual {v5, v9, v12}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 2869
    .line 2870
    .line 2871
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2872
    .line 2873
    .line 2874
    move-result-object v12

    .line 2875
    invoke-virtual {v10, v9, v12}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 2876
    .line 2877
    .line 2878
    new-instance v12, Le6/c;

    .line 2879
    .line 2880
    invoke-virtual {v7}, Ld4/d;->a()Ljava/lang/String;

    .line 2881
    .line 2882
    .line 2883
    move-result-object v7

    .line 2884
    invoke-direct {v12, v9, v7}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2885
    .line 2886
    .line 2887
    invoke-virtual {v13, v12}, Le6/d;->b(Le6/c;)V

    .line 2888
    .line 2889
    .line 2890
    add-int/lit8 v3, v3, 0x1

    .line 2891
    .line 2892
    goto :goto_51

    .line 2893
    :cond_ba
    move-object/from16 v22, v3

    .line 2894
    .line 2895
    move-object v3, v2

    .line 2896
    check-cast v3, Ljava/util/Collection;

    .line 2897
    .line 2898
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 2899
    .line 2900
    .line 2901
    move-result v3

    .line 2902
    const/4 v4, 0x0

    .line 2903
    :goto_52
    if-ge v4, v3, :cond_bb

    .line 2904
    .line 2905
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 2906
    .line 2907
    .line 2908
    move-result-object v9

    .line 2909
    check-cast v9, Ld4/d;

    .line 2910
    .line 2911
    invoke-virtual {v7, v4}, Landroidx/collection/a0;->c(I)I

    .line 2912
    .line 2913
    .line 2914
    move-result v12

    .line 2915
    invoke-virtual {v9}, Ld4/d;->a()Ljava/lang/String;

    .line 2916
    .line 2917
    .line 2918
    move-result-object v14

    .line 2919
    invoke-virtual {v5, v12, v14}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 2920
    .line 2921
    .line 2922
    invoke-virtual {v9}, Ld4/d;->a()Ljava/lang/String;

    .line 2923
    .line 2924
    .line 2925
    move-result-object v14

    .line 2926
    invoke-virtual {v10, v12, v14}, Landroidx/collection/h0;->h(ILjava/lang/Object;)V

    .line 2927
    .line 2928
    .line 2929
    new-instance v14, Le6/c;

    .line 2930
    .line 2931
    invoke-virtual {v9}, Ld4/d;->a()Ljava/lang/String;

    .line 2932
    .line 2933
    .line 2934
    move-result-object v9

    .line 2935
    invoke-direct {v14, v12, v9}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 2936
    .line 2937
    .line 2938
    invoke-virtual {v13, v14}, Le6/d;->b(Le6/c;)V

    .line 2939
    .line 2940
    .line 2941
    add-int/lit8 v4, v4, 0x1

    .line 2942
    .line 2943
    goto :goto_52

    .line 2944
    :cond_bb
    iget-object v2, v0, Lw3/z;->u:Landroidx/collection/b1;

    .line 2945
    .line 2946
    invoke-virtual {v2, v1, v5}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 2947
    .line 2948
    .line 2949
    invoke-virtual {v11, v1, v10}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 2950
    .line 2951
    .line 2952
    goto :goto_53

    .line 2953
    :cond_bc
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2954
    .line 2955
    new-instance v1, Ljava/lang/StringBuilder;

    .line 2956
    .line 2957
    const-string v2, "Can\'t have more than "

    .line 2958
    .line 2959
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 2960
    .line 2961
    .line 2962
    iget v2, v7, Landroidx/collection/a0;->b:I

    .line 2963
    .line 2964
    const-string v3, " custom actions for one widget"

    .line 2965
    .line 2966
    invoke-static {v2, v3, v1}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 2967
    .line 2968
    .line 2969
    move-result-object v1

    .line 2970
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2971
    .line 2972
    .line 2973
    throw v0

    .line 2974
    :cond_bd
    move-object/from16 v22, v3

    .line 2975
    .line 2976
    :goto_53
    invoke-static {v6, v15}, Lw3/h0;->k(Ld4/q;Landroid/content/res/Resources;)Z

    .line 2977
    .line 2978
    .line 2979
    move-result v2

    .line 2980
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setScreenReaderFocusable(Z)V

    .line 2981
    .line 2982
    .line 2983
    iget-object v2, v0, Lw3/z;->E:Landroidx/collection/z;

    .line 2984
    .line 2985
    invoke-virtual {v2, v1}, Landroidx/collection/z;->d(I)I

    .line 2986
    .line 2987
    .line 2988
    move-result v2

    .line 2989
    const/4 v11, -0x1

    .line 2990
    if-eq v2, v11, :cond_bf

    .line 2991
    .line 2992
    invoke-virtual/range {v22 .. v22}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 2993
    .line 2994
    .line 2995
    move-result-object v3

    .line 2996
    invoke-static {v3, v2}, Lw3/h0;->z(Lw3/t0;I)Lw4/g;

    .line 2997
    .line 2998
    .line 2999
    move-result-object v3

    .line 3000
    if-eqz v3, :cond_be

    .line 3001
    .line 3002
    invoke-virtual {v8, v3}, Landroid/view/accessibility/AccessibilityNodeInfo;->setTraversalBefore(Landroid/view/View;)V

    .line 3003
    .line 3004
    .line 3005
    move-object/from16 v3, v22

    .line 3006
    .line 3007
    goto :goto_54

    .line 3008
    :cond_be
    move-object/from16 v3, v22

    .line 3009
    .line 3010
    invoke-virtual {v8, v3, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setTraversalBefore(Landroid/view/View;I)V

    .line 3011
    .line 3012
    .line 3013
    :goto_54
    iget-object v2, v0, Lw3/z;->G:Ljava/lang/String;

    .line 3014
    .line 3015
    const/4 v4, 0x0

    .line 3016
    invoke-virtual {v0, v1, v13, v2, v4}, Lw3/z;->j(ILe6/d;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 3017
    .line 3018
    .line 3019
    goto :goto_55

    .line 3020
    :cond_bf
    move-object/from16 v3, v22

    .line 3021
    .line 3022
    const/4 v4, 0x0

    .line 3023
    :goto_55
    iget-object v2, v0, Lw3/z;->F:Landroidx/collection/z;

    .line 3024
    .line 3025
    invoke-virtual {v2, v1}, Landroidx/collection/z;->d(I)I

    .line 3026
    .line 3027
    .line 3028
    move-result v2

    .line 3029
    const/4 v11, -0x1

    .line 3030
    if-eq v2, v11, :cond_c0

    .line 3031
    .line 3032
    invoke-virtual {v3}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 3033
    .line 3034
    .line 3035
    move-result-object v3

    .line 3036
    invoke-static {v3, v2}, Lw3/h0;->z(Lw3/t0;I)Lw4/g;

    .line 3037
    .line 3038
    .line 3039
    move-result-object v2

    .line 3040
    if-eqz v2, :cond_c0

    .line 3041
    .line 3042
    invoke-virtual {v8, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setTraversalAfter(Landroid/view/View;)V

    .line 3043
    .line 3044
    .line 3045
    iget-object v2, v0, Lw3/z;->H:Ljava/lang/String;

    .line 3046
    .line 3047
    invoke-virtual {v0, v1, v13, v2, v4}, Lw3/z;->j(ILe6/d;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 3048
    .line 3049
    .line 3050
    :cond_c0
    invoke-virtual {v6}, Ld4/q;->m()Ld4/l;

    .line 3051
    .line 3052
    .line 3053
    move-result-object v2

    .line 3054
    sget-object v3, Ld4/w;->b:Ld4/z;

    .line 3055
    .line 3056
    invoke-static {v2, v3}, Ld4/t;->d(Ld4/l;Ld4/z;)Ljava/lang/Object;

    .line 3057
    .line 3058
    .line 3059
    move-result-object v2

    .line 3060
    check-cast v2, Ljava/lang/String;

    .line 3061
    .line 3062
    if-eqz v2, :cond_c1

    .line 3063
    .line 3064
    invoke-virtual {v13, v2}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 3065
    .line 3066
    .line 3067
    :cond_c1
    move-object v5, v13

    .line 3068
    :goto_56
    iget-boolean v2, v0, Lw3/z;->r:Z

    .line 3069
    .line 3070
    if-eqz v2, :cond_c3

    .line 3071
    .line 3072
    iget v2, v0, Lw3/z;->n:I

    .line 3073
    .line 3074
    if-ne v1, v2, :cond_c2

    .line 3075
    .line 3076
    iput-object v5, v0, Lw3/z;->p:Le6/d;

    .line 3077
    .line 3078
    :cond_c2
    iget v2, v0, Lw3/z;->o:I

    .line 3079
    .line 3080
    if-ne v1, v2, :cond_c3

    .line 3081
    .line 3082
    iput-object v5, v0, Lw3/z;->q:Le6/d;

    .line 3083
    .line 3084
    :cond_c3
    return-object v5

    .line 3085
    :cond_c4
    new-instance v0, Ljava/lang/ClassCastException;

    .line 3086
    .line 3087
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 3088
    .line 3089
    .line 3090
    throw v0

    .line 3091
    :cond_c5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 3092
    .line 3093
    const-string v2, "semanticsNode "

    .line 3094
    .line 3095
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3096
    .line 3097
    .line 3098
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 3099
    .line 3100
    .line 3101
    const-string v1, " has null parent"

    .line 3102
    .line 3103
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3104
    .line 3105
    .line 3106
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3107
    .line 3108
    .line 3109
    move-result-object v0

    .line 3110
    invoke-static {v0}, Ls3/a;->c(Ljava/lang/String;)Ljava/lang/Void;

    .line 3111
    .line 3112
    .line 3113
    new-instance v0, La8/r0;

    .line 3114
    .line 3115
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 3116
    .line 3117
    .line 3118
    throw v0

    .line 3119
    :pswitch_0
    invoke-direct/range {p0 .. p1}, Lk6/a;->C(I)Le6/d;

    .line 3120
    .line 3121
    .line 3122
    move-result-object v0

    .line 3123
    return-object v0

    .line 3124
    nop

    .line 3125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final t(I)Le6/d;
    .locals 2

    .line 1
    iget v0, p0, Lk6/a;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk6/a;->h:Ld6/b;

    .line 7
    .line 8
    check-cast v0, Lw3/z;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    if-eq p1, v1, :cond_1

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    if-ne p1, v1, :cond_0

    .line 15
    .line 16
    iget p1, v0, Lw3/z;->n:I

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lk6/a;->j(I)Le6/d;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string v0, "Unknown focus type: "

    .line 26
    .line 27
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    iget p1, v0, Lw3/z;->o:I

    .line 36
    .line 37
    const/high16 v0, -0x80000000

    .line 38
    .line 39
    if-ne p1, v0, :cond_2

    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-virtual {p0, p1}, Lk6/a;->j(I)Le6/d;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    :goto_0
    return-object p0

    .line 48
    :pswitch_0
    iget-object v0, p0, Lk6/a;->h:Ld6/b;

    .line 49
    .line 50
    check-cast v0, Lk6/b;

    .line 51
    .line 52
    const/4 v1, 0x2

    .line 53
    if-ne p1, v1, :cond_3

    .line 54
    .line 55
    iget p1, v0, Lk6/b;->k:I

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    iget p1, v0, Lk6/b;->l:I

    .line 59
    .line 60
    :goto_1
    const/high16 v0, -0x80000000

    .line 61
    .line 62
    if-ne p1, v0, :cond_4

    .line 63
    .line 64
    const/4 p0, 0x0

    .line 65
    goto :goto_2

    .line 66
    :cond_4
    invoke-virtual {p0, p1}, Lk6/a;->j(I)Le6/d;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    :goto_2
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final w(IILandroid/os/Bundle;)Z
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    iget v4, v0, Lk6/a;->g:I

    .line 10
    .line 11
    const/16 v8, 0x40

    .line 12
    .line 13
    iget-object v0, v0, Lk6/a;->h:Ld6/b;

    .line 14
    .line 15
    packed-switch v4, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    check-cast v0, Lw3/z;

    .line 19
    .line 20
    iget-object v4, v0, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 21
    .line 22
    const/16 p0, 0x0

    .line 23
    .line 24
    invoke-static/range {p0 .. p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 25
    .line 26
    .line 27
    move-result-object v15

    .line 28
    iget-object v5, v0, Lw3/z;->d:Lw3/t;

    .line 29
    .line 30
    invoke-virtual {v0}, Lw3/z;->t()Landroidx/collection/p;

    .line 31
    .line 32
    .line 33
    move-result-object v12

    .line 34
    invoke-virtual {v12, v1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v12

    .line 38
    check-cast v12, Ld4/r;

    .line 39
    .line 40
    if-eqz v12, :cond_8e

    .line 41
    .line 42
    iget-object v12, v12, Ld4/r;->a:Ld4/q;

    .line 43
    .line 44
    if-nez v12, :cond_0

    .line 45
    .line 46
    goto/16 :goto_49

    .line 47
    .line 48
    :cond_0
    iget-object v11, v12, Ld4/q;->c:Lv3/h0;

    .line 49
    .line 50
    iget v6, v12, Ld4/q;->g:I

    .line 51
    .line 52
    iget-object v9, v12, Ld4/q;->d:Ld4/l;

    .line 53
    .line 54
    iget-object v13, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 55
    .line 56
    sget-object v10, Ld4/v;->n:Ld4/z;

    .line 57
    .line 58
    invoke-virtual {v13, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v10

    .line 62
    if-nez v10, :cond_1

    .line 63
    .line 64
    const/4 v10, 0x0

    .line 65
    :cond_1
    sget-object v14, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 66
    .line 67
    invoke-static {v10, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v10

    .line 71
    if-eqz v10, :cond_3

    .line 72
    .line 73
    sget v10, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 74
    .line 75
    const/16 v7, 0x22

    .line 76
    .line 77
    if-lt v10, v7, :cond_2

    .line 78
    .line 79
    invoke-static {v4}, Lb/a;->k(Landroid/view/accessibility/AccessibilityManager;)Z

    .line 80
    .line 81
    .line 82
    move-result v7

    .line 83
    goto :goto_0

    .line 84
    :cond_2
    const/4 v7, 0x1

    .line 85
    :goto_0
    if-nez v7, :cond_3

    .line 86
    .line 87
    goto/16 :goto_49

    .line 88
    .line 89
    :cond_3
    const/16 v7, 0xc

    .line 90
    .line 91
    if-eq v2, v8, :cond_89

    .line 92
    .line 93
    const/16 v8, 0x80

    .line 94
    .line 95
    if-eq v2, v8, :cond_87

    .line 96
    .line 97
    const/16 v4, 0x8

    .line 98
    .line 99
    const/16 v8, 0x200

    .line 100
    .line 101
    const/16 v10, 0x100

    .line 102
    .line 103
    if-eq v2, v10, :cond_69

    .line 104
    .line 105
    if-eq v2, v8, :cond_69

    .line 106
    .line 107
    const/16 v8, 0x4000

    .line 108
    .line 109
    if-eq v2, v8, :cond_67

    .line 110
    .line 111
    const/high16 v8, 0x20000

    .line 112
    .line 113
    if-eq v2, v8, :cond_63

    .line 114
    .line 115
    invoke-static {v12}, Lw3/h0;->h(Ld4/q;)Z

    .line 116
    .line 117
    .line 118
    move-result v6

    .line 119
    if-nez v6, :cond_4

    .line 120
    .line 121
    goto/16 :goto_49

    .line 122
    .line 123
    :cond_4
    const/4 v6, 0x1

    .line 124
    if-eq v2, v6, :cond_60

    .line 125
    .line 126
    const/4 v6, 0x2

    .line 127
    if-eq v2, v6, :cond_5e

    .line 128
    .line 129
    sparse-switch v2, :sswitch_data_0

    .line 130
    .line 131
    .line 132
    packed-switch v2, :pswitch_data_1

    .line 133
    .line 134
    .line 135
    packed-switch v2, :pswitch_data_2

    .line 136
    .line 137
    .line 138
    iget-object v0, v0, Lw3/z;->u:Landroidx/collection/b1;

    .line 139
    .line 140
    invoke-virtual {v0, v1}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    check-cast v0, Landroidx/collection/b1;

    .line 145
    .line 146
    if-eqz v0, :cond_8e

    .line 147
    .line 148
    invoke-virtual {v0, v2}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Ljava/lang/CharSequence;

    .line 153
    .line 154
    if-nez v0, :cond_5

    .line 155
    .line 156
    goto/16 :goto_49

    .line 157
    .line 158
    :cond_5
    sget-object v1, Ld4/k;->w:Ld4/z;

    .line 159
    .line 160
    invoke-virtual {v13, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    if-nez v1, :cond_6

    .line 165
    .line 166
    const/4 v14, 0x0

    .line 167
    goto :goto_1

    .line 168
    :cond_6
    move-object v14, v1

    .line 169
    :goto_1
    check-cast v14, Ljava/util/List;

    .line 170
    .line 171
    if-nez v14, :cond_7

    .line 172
    .line 173
    goto/16 :goto_49

    .line 174
    .line 175
    :cond_7
    move-object v1, v14

    .line 176
    check-cast v1, Ljava/util/Collection;

    .line 177
    .line 178
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    const/4 v2, 0x0

    .line 183
    :goto_2
    if-ge v2, v1, :cond_8e

    .line 184
    .line 185
    invoke-interface {v14, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    check-cast v3, Ld4/d;

    .line 190
    .line 191
    iget-object v4, v3, Ld4/d;->a:Ljava/lang/String;

    .line 192
    .line 193
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    if-eqz v4, :cond_8

    .line 198
    .line 199
    iget-object v0, v3, Ld4/d;->b:Lay0/a;

    .line 200
    .line 201
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    check-cast v0, Ljava/lang/Boolean;

    .line 206
    .line 207
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 208
    .line 209
    .line 210
    move-result v13

    .line 211
    goto/16 :goto_4a

    .line 212
    .line 213
    :cond_8
    add-int/lit8 v2, v2, 0x1

    .line 214
    .line 215
    goto :goto_2

    .line 216
    :pswitch_0
    sget-object v0, Ld4/k;->A:Ld4/z;

    .line 217
    .line 218
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    if-nez v0, :cond_9

    .line 223
    .line 224
    const/4 v14, 0x0

    .line 225
    goto :goto_3

    .line 226
    :cond_9
    move-object v14, v0

    .line 227
    :goto_3
    check-cast v14, Ld4/a;

    .line 228
    .line 229
    if-eqz v14, :cond_8e

    .line 230
    .line 231
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 232
    .line 233
    check-cast v0, Lay0/a;

    .line 234
    .line 235
    if-eqz v0, :cond_8e

    .line 236
    .line 237
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    check-cast v0, Ljava/lang/Boolean;

    .line 242
    .line 243
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 244
    .line 245
    .line 246
    move-result v13

    .line 247
    goto/16 :goto_4a

    .line 248
    .line 249
    :pswitch_1
    sget-object v0, Ld4/k;->y:Ld4/z;

    .line 250
    .line 251
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    if-nez v0, :cond_a

    .line 256
    .line 257
    const/4 v14, 0x0

    .line 258
    goto :goto_4

    .line 259
    :cond_a
    move-object v14, v0

    .line 260
    :goto_4
    check-cast v14, Ld4/a;

    .line 261
    .line 262
    if-eqz v14, :cond_8e

    .line 263
    .line 264
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 265
    .line 266
    check-cast v0, Lay0/a;

    .line 267
    .line 268
    if-eqz v0, :cond_8e

    .line 269
    .line 270
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v0

    .line 274
    check-cast v0, Ljava/lang/Boolean;

    .line 275
    .line 276
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 277
    .line 278
    .line 279
    move-result v13

    .line 280
    goto/16 :goto_4a

    .line 281
    .line 282
    :pswitch_2
    sget-object v0, Ld4/k;->z:Ld4/z;

    .line 283
    .line 284
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    if-nez v0, :cond_b

    .line 289
    .line 290
    const/4 v14, 0x0

    .line 291
    goto :goto_5

    .line 292
    :cond_b
    move-object v14, v0

    .line 293
    :goto_5
    check-cast v14, Ld4/a;

    .line 294
    .line 295
    if-eqz v14, :cond_8e

    .line 296
    .line 297
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 298
    .line 299
    check-cast v0, Lay0/a;

    .line 300
    .line 301
    if-eqz v0, :cond_8e

    .line 302
    .line 303
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    check-cast v0, Ljava/lang/Boolean;

    .line 308
    .line 309
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 310
    .line 311
    .line 312
    move-result v13

    .line 313
    goto/16 :goto_4a

    .line 314
    .line 315
    :pswitch_3
    sget-object v0, Ld4/k;->x:Ld4/z;

    .line 316
    .line 317
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v0

    .line 321
    if-nez v0, :cond_c

    .line 322
    .line 323
    const/4 v14, 0x0

    .line 324
    goto :goto_6

    .line 325
    :cond_c
    move-object v14, v0

    .line 326
    :goto_6
    check-cast v14, Ld4/a;

    .line 327
    .line 328
    if-eqz v14, :cond_8e

    .line 329
    .line 330
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 331
    .line 332
    check-cast v0, Lay0/a;

    .line 333
    .line 334
    if-eqz v0, :cond_8e

    .line 335
    .line 336
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    check-cast v0, Ljava/lang/Boolean;

    .line 341
    .line 342
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 343
    .line 344
    .line 345
    move-result v13

    .line 346
    goto/16 :goto_4a

    .line 347
    .line 348
    :sswitch_0
    sget-object v0, Ld4/k;->o:Ld4/z;

    .line 349
    .line 350
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    if-nez v0, :cond_d

    .line 355
    .line 356
    const/4 v14, 0x0

    .line 357
    goto :goto_7

    .line 358
    :cond_d
    move-object v14, v0

    .line 359
    :goto_7
    check-cast v14, Ld4/a;

    .line 360
    .line 361
    if-eqz v14, :cond_8e

    .line 362
    .line 363
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 364
    .line 365
    check-cast v0, Lay0/a;

    .line 366
    .line 367
    if-eqz v0, :cond_8e

    .line 368
    .line 369
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v0

    .line 373
    check-cast v0, Ljava/lang/Boolean;

    .line 374
    .line 375
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 376
    .line 377
    .line 378
    move-result v13

    .line 379
    goto/16 :goto_4a

    .line 380
    .line 381
    :sswitch_1
    if-eqz v3, :cond_8e

    .line 382
    .line 383
    const-string v0, "android.view.accessibility.action.ARGUMENT_PROGRESS_VALUE"

    .line 384
    .line 385
    invoke-virtual {v3, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 386
    .line 387
    .line 388
    move-result v1

    .line 389
    if-nez v1, :cond_e

    .line 390
    .line 391
    goto/16 :goto_49

    .line 392
    .line 393
    :cond_e
    sget-object v1, Ld4/k;->h:Ld4/z;

    .line 394
    .line 395
    invoke-virtual {v13, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v1

    .line 399
    if-nez v1, :cond_f

    .line 400
    .line 401
    const/4 v14, 0x0

    .line 402
    goto :goto_8

    .line 403
    :cond_f
    move-object v14, v1

    .line 404
    :goto_8
    check-cast v14, Ld4/a;

    .line 405
    .line 406
    if-eqz v14, :cond_8e

    .line 407
    .line 408
    iget-object v1, v14, Ld4/a;->b:Llx0/e;

    .line 409
    .line 410
    check-cast v1, Lay0/k;

    .line 411
    .line 412
    if-eqz v1, :cond_8e

    .line 413
    .line 414
    invoke-virtual {v3, v0}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 415
    .line 416
    .line 417
    move-result v0

    .line 418
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    check-cast v0, Ljava/lang/Boolean;

    .line 427
    .line 428
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 429
    .line 430
    .line 431
    move-result v13

    .line 432
    goto/16 :goto_4a

    .line 433
    .line 434
    :sswitch_2
    invoke-virtual {v12}, Ld4/q;->l()Ld4/q;

    .line 435
    .line 436
    .line 437
    move-result-object v0

    .line 438
    if-eqz v0, :cond_11

    .line 439
    .line 440
    iget-object v1, v0, Ld4/q;->d:Ld4/l;

    .line 441
    .line 442
    sget-object v2, Ld4/k;->d:Ld4/z;

    .line 443
    .line 444
    iget-object v1, v1, Ld4/l;->d:Landroidx/collection/q0;

    .line 445
    .line 446
    invoke-virtual {v1, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    if-nez v1, :cond_10

    .line 451
    .line 452
    const/4 v1, 0x0

    .line 453
    :cond_10
    check-cast v1, Ld4/a;

    .line 454
    .line 455
    goto :goto_9

    .line 456
    :cond_11
    const/4 v1, 0x0

    .line 457
    :goto_9
    if-eqz v0, :cond_14

    .line 458
    .line 459
    if-eqz v1, :cond_12

    .line 460
    .line 461
    goto :goto_a

    .line 462
    :cond_12
    invoke-virtual {v0}, Ld4/q;->l()Ld4/q;

    .line 463
    .line 464
    .line 465
    move-result-object v0

    .line 466
    if-eqz v0, :cond_11

    .line 467
    .line 468
    iget-object v1, v0, Ld4/q;->d:Ld4/l;

    .line 469
    .line 470
    sget-object v2, Ld4/k;->d:Ld4/z;

    .line 471
    .line 472
    iget-object v1, v1, Ld4/l;->d:Landroidx/collection/q0;

    .line 473
    .line 474
    invoke-virtual {v1, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 475
    .line 476
    .line 477
    move-result-object v1

    .line 478
    if-nez v1, :cond_13

    .line 479
    .line 480
    const/4 v1, 0x0

    .line 481
    :cond_13
    check-cast v1, Ld4/a;

    .line 482
    .line 483
    goto :goto_9

    .line 484
    :cond_14
    :goto_a
    if-nez v0, :cond_15

    .line 485
    .line 486
    invoke-virtual {v12}, Ld4/q;->g()Ld3/c;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    new-instance v1, Landroid/graphics/Rect;

    .line 491
    .line 492
    iget v2, v0, Ld3/c;->a:F

    .line 493
    .line 494
    float-to-double v2, v2

    .line 495
    invoke-static {v2, v3}, Ljava/lang/Math;->floor(D)D

    .line 496
    .line 497
    .line 498
    move-result-wide v2

    .line 499
    double-to-float v2, v2

    .line 500
    float-to-int v2, v2

    .line 501
    iget v3, v0, Ld3/c;->b:F

    .line 502
    .line 503
    float-to-double v3, v3

    .line 504
    invoke-static {v3, v4}, Ljava/lang/Math;->floor(D)D

    .line 505
    .line 506
    .line 507
    move-result-wide v3

    .line 508
    double-to-float v3, v3

    .line 509
    float-to-int v3, v3

    .line 510
    iget v4, v0, Ld3/c;->c:F

    .line 511
    .line 512
    float-to-double v6, v4

    .line 513
    invoke-static {v6, v7}, Ljava/lang/Math;->ceil(D)D

    .line 514
    .line 515
    .line 516
    move-result-wide v6

    .line 517
    double-to-float v4, v6

    .line 518
    invoke-static {v4}, Lcy0/a;->i(F)I

    .line 519
    .line 520
    .line 521
    move-result v4

    .line 522
    iget v0, v0, Ld3/c;->d:F

    .line 523
    .line 524
    float-to-double v6, v0

    .line 525
    invoke-static {v6, v7}, Ljava/lang/Math;->ceil(D)D

    .line 526
    .line 527
    .line 528
    move-result-wide v6

    .line 529
    double-to-float v0, v6

    .line 530
    invoke-static {v0}, Lcy0/a;->i(F)I

    .line 531
    .line 532
    .line 533
    move-result v0

    .line 534
    invoke-direct {v1, v2, v3, v4, v0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 535
    .line 536
    .line 537
    invoke-virtual {v5, v1}, Landroid/view/View;->requestRectangleOnScreen(Landroid/graphics/Rect;)Z

    .line 538
    .line 539
    .line 540
    move-result v13

    .line 541
    goto/16 :goto_4a

    .line 542
    .line 543
    :cond_15
    iget-object v2, v0, Ld4/q;->d:Ld4/l;

    .line 544
    .line 545
    iget-object v2, v2, Ld4/l;->d:Landroidx/collection/q0;

    .line 546
    .line 547
    iget-object v0, v0, Ld4/q;->c:Lv3/h0;

    .line 548
    .line 549
    iget-object v3, v0, Lv3/h0;->H:Lg1/q;

    .line 550
    .line 551
    iget-object v3, v3, Lg1/q;->d:Ljava/lang/Object;

    .line 552
    .line 553
    check-cast v3, Lv3/u;

    .line 554
    .line 555
    invoke-static {v3}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 556
    .line 557
    .line 558
    move-result-object v3

    .line 559
    iget-object v0, v0, Lv3/h0;->H:Lg1/q;

    .line 560
    .line 561
    iget-object v0, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 562
    .line 563
    check-cast v0, Lv3/u;

    .line 564
    .line 565
    invoke-virtual {v0}, Lv3/f1;->O()Lt3/y;

    .line 566
    .line 567
    .line 568
    move-result-object v0

    .line 569
    const-wide/16 v4, 0x0

    .line 570
    .line 571
    if-eqz v0, :cond_16

    .line 572
    .line 573
    check-cast v0, Lv3/f1;

    .line 574
    .line 575
    invoke-virtual {v0, v4, v5}, Lv3/f1;->R(J)J

    .line 576
    .line 577
    .line 578
    move-result-wide v6

    .line 579
    goto :goto_b

    .line 580
    :cond_16
    move-wide v6, v4

    .line 581
    :goto_b
    invoke-virtual {v3, v6, v7}, Ld3/c;->i(J)Ld3/c;

    .line 582
    .line 583
    .line 584
    move-result-object v0

    .line 585
    invoke-virtual {v12}, Ld4/q;->d()Lv3/f1;

    .line 586
    .line 587
    .line 588
    move-result-object v3

    .line 589
    if-eqz v3, :cond_18

    .line 590
    .line 591
    invoke-virtual {v3}, Lv3/f1;->f1()Lx2/r;

    .line 592
    .line 593
    .line 594
    move-result-object v6

    .line 595
    iget-boolean v6, v6, Lx2/r;->q:Z

    .line 596
    .line 597
    if-eqz v6, :cond_17

    .line 598
    .line 599
    goto :goto_c

    .line 600
    :cond_17
    const/4 v3, 0x0

    .line 601
    :goto_c
    if-eqz v3, :cond_18

    .line 602
    .line 603
    invoke-virtual {v3, v4, v5}, Lv3/f1;->R(J)J

    .line 604
    .line 605
    .line 606
    move-result-wide v6

    .line 607
    goto :goto_d

    .line 608
    :cond_18
    move-wide v6, v4

    .line 609
    :goto_d
    invoke-virtual {v12}, Ld4/q;->d()Lv3/f1;

    .line 610
    .line 611
    .line 612
    move-result-object v3

    .line 613
    if-eqz v3, :cond_19

    .line 614
    .line 615
    iget-wide v4, v3, Lt3/e1;->f:J

    .line 616
    .line 617
    :cond_19
    invoke-static {v4, v5}, Lkp/f9;->c(J)J

    .line 618
    .line 619
    .line 620
    move-result-wide v3

    .line 621
    invoke-static {v6, v7, v3, v4}, Ljp/cf;->c(JJ)Ld3/c;

    .line 622
    .line 623
    .line 624
    move-result-object v3

    .line 625
    sget-object v4, Ld4/v;->t:Ld4/z;

    .line 626
    .line 627
    invoke-virtual {v2, v4}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 628
    .line 629
    .line 630
    move-result-object v4

    .line 631
    if-nez v4, :cond_1a

    .line 632
    .line 633
    const/4 v4, 0x0

    .line 634
    :cond_1a
    check-cast v4, Ld4/j;

    .line 635
    .line 636
    sget-object v5, Ld4/v;->u:Ld4/z;

    .line 637
    .line 638
    invoke-virtual {v2, v5}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 639
    .line 640
    .line 641
    move-result-object v2

    .line 642
    if-nez v2, :cond_1b

    .line 643
    .line 644
    const/4 v14, 0x0

    .line 645
    goto :goto_e

    .line 646
    :cond_1b
    move-object v14, v2

    .line 647
    :goto_e
    check-cast v14, Ld4/j;

    .line 648
    .line 649
    iget v2, v3, Ld3/c;->a:F

    .line 650
    .line 651
    iget v5, v0, Ld3/c;->a:F

    .line 652
    .line 653
    sub-float/2addr v2, v5

    .line 654
    iget v5, v3, Ld3/c;->c:F

    .line 655
    .line 656
    iget v6, v0, Ld3/c;->c:F

    .line 657
    .line 658
    sub-float/2addr v5, v6

    .line 659
    invoke-static {v2}, Ljava/lang/Math;->signum(F)F

    .line 660
    .line 661
    .line 662
    move-result v6

    .line 663
    invoke-static {v5}, Ljava/lang/Math;->signum(F)F

    .line 664
    .line 665
    .line 666
    move-result v7

    .line 667
    cmpg-float v6, v6, v7

    .line 668
    .line 669
    if-nez v6, :cond_1d

    .line 670
    .line 671
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 672
    .line 673
    .line 674
    move-result v6

    .line 675
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    .line 676
    .line 677
    .line 678
    move-result v7

    .line 679
    cmpg-float v6, v6, v7

    .line 680
    .line 681
    if-gez v6, :cond_1c

    .line 682
    .line 683
    goto :goto_f

    .line 684
    :cond_1c
    move v2, v5

    .line 685
    goto :goto_f

    .line 686
    :cond_1d
    move/from16 v2, p0

    .line 687
    .line 688
    :goto_f
    if-eqz v4, :cond_1e

    .line 689
    .line 690
    iget-boolean v4, v4, Ld4/j;->c:Z

    .line 691
    .line 692
    const/4 v6, 0x1

    .line 693
    if-ne v4, v6, :cond_1e

    .line 694
    .line 695
    neg-float v2, v2

    .line 696
    :cond_1e
    iget-object v4, v11, Lv3/h0;->B:Lt4/m;

    .line 697
    .line 698
    sget-object v5, Lt4/m;->e:Lt4/m;

    .line 699
    .line 700
    if-ne v4, v5, :cond_1f

    .line 701
    .line 702
    const/4 v4, 0x1

    .line 703
    goto :goto_10

    .line 704
    :cond_1f
    const/4 v4, 0x0

    .line 705
    :goto_10
    if-eqz v4, :cond_20

    .line 706
    .line 707
    neg-float v2, v2

    .line 708
    :cond_20
    iget v4, v3, Ld3/c;->b:F

    .line 709
    .line 710
    iget v5, v0, Ld3/c;->b:F

    .line 711
    .line 712
    sub-float/2addr v4, v5

    .line 713
    iget v3, v3, Ld3/c;->d:F

    .line 714
    .line 715
    iget v0, v0, Ld3/c;->d:F

    .line 716
    .line 717
    sub-float/2addr v3, v0

    .line 718
    invoke-static {v4}, Ljava/lang/Math;->signum(F)F

    .line 719
    .line 720
    .line 721
    move-result v0

    .line 722
    invoke-static {v3}, Ljava/lang/Math;->signum(F)F

    .line 723
    .line 724
    .line 725
    move-result v5

    .line 726
    cmpg-float v0, v0, v5

    .line 727
    .line 728
    if-nez v0, :cond_22

    .line 729
    .line 730
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    .line 731
    .line 732
    .line 733
    move-result v0

    .line 734
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 735
    .line 736
    .line 737
    move-result v5

    .line 738
    cmpg-float v0, v0, v5

    .line 739
    .line 740
    if-gez v0, :cond_21

    .line 741
    .line 742
    move v15, v4

    .line 743
    goto :goto_11

    .line 744
    :cond_21
    move v15, v3

    .line 745
    goto :goto_11

    .line 746
    :cond_22
    move/from16 v15, p0

    .line 747
    .line 748
    :goto_11
    if-eqz v14, :cond_23

    .line 749
    .line 750
    iget-boolean v0, v14, Ld4/j;->c:Z

    .line 751
    .line 752
    const/4 v6, 0x1

    .line 753
    if-ne v0, v6, :cond_23

    .line 754
    .line 755
    neg-float v15, v15

    .line 756
    :cond_23
    if-eqz v1, :cond_8e

    .line 757
    .line 758
    iget-object v0, v1, Ld4/a;->b:Llx0/e;

    .line 759
    .line 760
    check-cast v0, Lay0/n;

    .line 761
    .line 762
    if-eqz v0, :cond_8e

    .line 763
    .line 764
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 765
    .line 766
    .line 767
    move-result-object v1

    .line 768
    invoke-static {v15}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 769
    .line 770
    .line 771
    move-result-object v2

    .line 772
    invoke-interface {v0, v1, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 773
    .line 774
    .line 775
    move-result-object v0

    .line 776
    check-cast v0, Ljava/lang/Boolean;

    .line 777
    .line 778
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 779
    .line 780
    .line 781
    move-result v0

    .line 782
    const/4 v6, 0x1

    .line 783
    if-ne v0, v6, :cond_8e

    .line 784
    .line 785
    :goto_12
    const/4 v13, 0x1

    .line 786
    goto/16 :goto_4a

    .line 787
    .line 788
    :sswitch_3
    if-eqz v3, :cond_24

    .line 789
    .line 790
    const-string v0, "ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE"

    .line 791
    .line 792
    invoke-virtual {v3, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 793
    .line 794
    .line 795
    move-result-object v0

    .line 796
    goto :goto_13

    .line 797
    :cond_24
    const/4 v0, 0x0

    .line 798
    :goto_13
    sget-object v1, Ld4/k;->j:Ld4/z;

    .line 799
    .line 800
    invoke-virtual {v13, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 801
    .line 802
    .line 803
    move-result-object v1

    .line 804
    if-nez v1, :cond_25

    .line 805
    .line 806
    const/4 v14, 0x0

    .line 807
    goto :goto_14

    .line 808
    :cond_25
    move-object v14, v1

    .line 809
    :goto_14
    check-cast v14, Ld4/a;

    .line 810
    .line 811
    if-eqz v14, :cond_8e

    .line 812
    .line 813
    iget-object v1, v14, Ld4/a;->b:Llx0/e;

    .line 814
    .line 815
    check-cast v1, Lay0/k;

    .line 816
    .line 817
    if-eqz v1, :cond_8e

    .line 818
    .line 819
    new-instance v2, Lg4/g;

    .line 820
    .line 821
    if-nez v0, :cond_26

    .line 822
    .line 823
    const-string v0, ""

    .line 824
    .line 825
    :cond_26
    invoke-direct {v2, v0}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    invoke-interface {v1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 829
    .line 830
    .line 831
    move-result-object v0

    .line 832
    check-cast v0, Ljava/lang/Boolean;

    .line 833
    .line 834
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 835
    .line 836
    .line 837
    move-result v13

    .line 838
    goto/16 :goto_4a

    .line 839
    .line 840
    :sswitch_4
    sget-object v0, Ld4/k;->u:Ld4/z;

    .line 841
    .line 842
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 843
    .line 844
    .line 845
    move-result-object v0

    .line 846
    if-nez v0, :cond_27

    .line 847
    .line 848
    const/4 v14, 0x0

    .line 849
    goto :goto_15

    .line 850
    :cond_27
    move-object v14, v0

    .line 851
    :goto_15
    check-cast v14, Ld4/a;

    .line 852
    .line 853
    if-eqz v14, :cond_8e

    .line 854
    .line 855
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 856
    .line 857
    check-cast v0, Lay0/a;

    .line 858
    .line 859
    if-eqz v0, :cond_8e

    .line 860
    .line 861
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 862
    .line 863
    .line 864
    move-result-object v0

    .line 865
    check-cast v0, Ljava/lang/Boolean;

    .line 866
    .line 867
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 868
    .line 869
    .line 870
    move-result v13

    .line 871
    goto/16 :goto_4a

    .line 872
    .line 873
    :sswitch_5
    sget-object v0, Ld4/k;->t:Ld4/z;

    .line 874
    .line 875
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 876
    .line 877
    .line 878
    move-result-object v0

    .line 879
    if-nez v0, :cond_28

    .line 880
    .line 881
    const/4 v14, 0x0

    .line 882
    goto :goto_16

    .line 883
    :cond_28
    move-object v14, v0

    .line 884
    :goto_16
    check-cast v14, Ld4/a;

    .line 885
    .line 886
    if-eqz v14, :cond_8e

    .line 887
    .line 888
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 889
    .line 890
    check-cast v0, Lay0/a;

    .line 891
    .line 892
    if-eqz v0, :cond_8e

    .line 893
    .line 894
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 895
    .line 896
    .line 897
    move-result-object v0

    .line 898
    check-cast v0, Ljava/lang/Boolean;

    .line 899
    .line 900
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 901
    .line 902
    .line 903
    move-result v13

    .line 904
    goto/16 :goto_4a

    .line 905
    .line 906
    :sswitch_6
    sget-object v0, Ld4/k;->s:Ld4/z;

    .line 907
    .line 908
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 909
    .line 910
    .line 911
    move-result-object v0

    .line 912
    if-nez v0, :cond_29

    .line 913
    .line 914
    const/4 v14, 0x0

    .line 915
    goto :goto_17

    .line 916
    :cond_29
    move-object v14, v0

    .line 917
    :goto_17
    check-cast v14, Ld4/a;

    .line 918
    .line 919
    if-eqz v14, :cond_8e

    .line 920
    .line 921
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 922
    .line 923
    check-cast v0, Lay0/a;

    .line 924
    .line 925
    if-eqz v0, :cond_8e

    .line 926
    .line 927
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 928
    .line 929
    .line 930
    move-result-object v0

    .line 931
    check-cast v0, Ljava/lang/Boolean;

    .line 932
    .line 933
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 934
    .line 935
    .line 936
    move-result v13

    .line 937
    goto/16 :goto_4a

    .line 938
    .line 939
    :sswitch_7
    sget-object v0, Ld4/k;->q:Ld4/z;

    .line 940
    .line 941
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    move-result-object v0

    .line 945
    if-nez v0, :cond_2a

    .line 946
    .line 947
    const/4 v14, 0x0

    .line 948
    goto :goto_18

    .line 949
    :cond_2a
    move-object v14, v0

    .line 950
    :goto_18
    check-cast v14, Ld4/a;

    .line 951
    .line 952
    if-eqz v14, :cond_8e

    .line 953
    .line 954
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 955
    .line 956
    check-cast v0, Lay0/a;

    .line 957
    .line 958
    if-eqz v0, :cond_8e

    .line 959
    .line 960
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 961
    .line 962
    .line 963
    move-result-object v0

    .line 964
    check-cast v0, Ljava/lang/Boolean;

    .line 965
    .line 966
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 967
    .line 968
    .line 969
    move-result v13

    .line 970
    goto/16 :goto_4a

    .line 971
    .line 972
    :sswitch_8
    sget-object v0, Ld4/k;->r:Ld4/z;

    .line 973
    .line 974
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 975
    .line 976
    .line 977
    move-result-object v0

    .line 978
    if-nez v0, :cond_2b

    .line 979
    .line 980
    const/4 v14, 0x0

    .line 981
    goto :goto_19

    .line 982
    :cond_2b
    move-object v14, v0

    .line 983
    :goto_19
    check-cast v14, Ld4/a;

    .line 984
    .line 985
    if-eqz v14, :cond_8e

    .line 986
    .line 987
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 988
    .line 989
    check-cast v0, Lay0/a;

    .line 990
    .line 991
    if-eqz v0, :cond_8e

    .line 992
    .line 993
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 994
    .line 995
    .line 996
    move-result-object v0

    .line 997
    check-cast v0, Ljava/lang/Boolean;

    .line 998
    .line 999
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1000
    .line 1001
    .line 1002
    move-result v13

    .line 1003
    goto/16 :goto_4a

    .line 1004
    .line 1005
    :pswitch_4
    :sswitch_9
    const/16 v0, 0x1000

    .line 1006
    .line 1007
    if-ne v2, v0, :cond_2c

    .line 1008
    .line 1009
    const/4 v0, 0x1

    .line 1010
    goto :goto_1a

    .line 1011
    :cond_2c
    const/4 v0, 0x0

    .line 1012
    :goto_1a
    const/16 v1, 0x2000

    .line 1013
    .line 1014
    if-ne v2, v1, :cond_2d

    .line 1015
    .line 1016
    const/4 v1, 0x1

    .line 1017
    goto :goto_1b

    .line 1018
    :cond_2d
    const/4 v1, 0x0

    .line 1019
    :goto_1b
    const v3, 0x1020039

    .line 1020
    .line 1021
    .line 1022
    if-ne v2, v3, :cond_2e

    .line 1023
    .line 1024
    const/4 v3, 0x1

    .line 1025
    goto :goto_1c

    .line 1026
    :cond_2e
    const/4 v3, 0x0

    .line 1027
    :goto_1c
    const v4, 0x102003b

    .line 1028
    .line 1029
    .line 1030
    if-ne v2, v4, :cond_2f

    .line 1031
    .line 1032
    const/4 v4, 0x1

    .line 1033
    goto :goto_1d

    .line 1034
    :cond_2f
    const/4 v4, 0x0

    .line 1035
    :goto_1d
    const v5, 0x1020038

    .line 1036
    .line 1037
    .line 1038
    if-ne v2, v5, :cond_30

    .line 1039
    .line 1040
    const/4 v5, 0x1

    .line 1041
    goto :goto_1e

    .line 1042
    :cond_30
    const/4 v5, 0x0

    .line 1043
    :goto_1e
    const v6, 0x102003a

    .line 1044
    .line 1045
    .line 1046
    if-ne v2, v6, :cond_31

    .line 1047
    .line 1048
    const/4 v2, 0x1

    .line 1049
    goto :goto_1f

    .line 1050
    :cond_31
    const/4 v2, 0x0

    .line 1051
    :goto_1f
    if-nez v3, :cond_33

    .line 1052
    .line 1053
    if-nez v4, :cond_33

    .line 1054
    .line 1055
    if-nez v0, :cond_33

    .line 1056
    .line 1057
    if-eqz v1, :cond_32

    .line 1058
    .line 1059
    goto :goto_20

    .line 1060
    :cond_32
    const/4 v6, 0x0

    .line 1061
    goto :goto_21

    .line 1062
    :cond_33
    :goto_20
    const/4 v6, 0x1

    .line 1063
    :goto_21
    if-nez v5, :cond_35

    .line 1064
    .line 1065
    if-nez v2, :cond_35

    .line 1066
    .line 1067
    if-nez v0, :cond_35

    .line 1068
    .line 1069
    if-eqz v1, :cond_34

    .line 1070
    .line 1071
    goto :goto_22

    .line 1072
    :cond_34
    const/4 v2, 0x0

    .line 1073
    goto :goto_23

    .line 1074
    :cond_35
    :goto_22
    const/4 v2, 0x1

    .line 1075
    :goto_23
    if-nez v0, :cond_36

    .line 1076
    .line 1077
    if-eqz v1, :cond_3d

    .line 1078
    .line 1079
    :cond_36
    sget-object v0, Ld4/v;->c:Ld4/z;

    .line 1080
    .line 1081
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v0

    .line 1085
    if-nez v0, :cond_37

    .line 1086
    .line 1087
    const/4 v0, 0x0

    .line 1088
    :cond_37
    check-cast v0, Ld4/h;

    .line 1089
    .line 1090
    sget-object v7, Ld4/k;->h:Ld4/z;

    .line 1091
    .line 1092
    invoke-virtual {v13, v7}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v7

    .line 1096
    if-nez v7, :cond_38

    .line 1097
    .line 1098
    const/4 v7, 0x0

    .line 1099
    :cond_38
    check-cast v7, Ld4/a;

    .line 1100
    .line 1101
    if-eqz v0, :cond_3d

    .line 1102
    .line 1103
    iget-object v8, v0, Ld4/h;->b:Lgy0/e;

    .line 1104
    .line 1105
    if-eqz v7, :cond_3d

    .line 1106
    .line 1107
    iget v2, v8, Lgy0/e;->e:F

    .line 1108
    .line 1109
    iget v3, v8, Lgy0/e;->d:F

    .line 1110
    .line 1111
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v2

    .line 1115
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1116
    .line 1117
    .line 1118
    move-result v2

    .line 1119
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v4

    .line 1123
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 1124
    .line 1125
    .line 1126
    move-result v4

    .line 1127
    cmpg-float v5, v2, v4

    .line 1128
    .line 1129
    if-gez v5, :cond_39

    .line 1130
    .line 1131
    move v2, v4

    .line 1132
    :cond_39
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v3

    .line 1136
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 1137
    .line 1138
    .line 1139
    move-result v3

    .line 1140
    iget v4, v8, Lgy0/e;->e:F

    .line 1141
    .line 1142
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1143
    .line 1144
    .line 1145
    move-result-object v4

    .line 1146
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 1147
    .line 1148
    .line 1149
    move-result v4

    .line 1150
    cmpl-float v5, v3, v4

    .line 1151
    .line 1152
    if-lez v5, :cond_3a

    .line 1153
    .line 1154
    move v3, v4

    .line 1155
    :cond_3a
    iget v4, v0, Ld4/h;->c:I

    .line 1156
    .line 1157
    if-lez v4, :cond_3b

    .line 1158
    .line 1159
    sub-float/2addr v2, v3

    .line 1160
    const/16 v24, 0x1

    .line 1161
    .line 1162
    add-int/lit8 v4, v4, 0x1

    .line 1163
    .line 1164
    int-to-float v3, v4

    .line 1165
    :goto_24
    div-float/2addr v2, v3

    .line 1166
    goto :goto_25

    .line 1167
    :cond_3b
    sub-float/2addr v2, v3

    .line 1168
    const/16 v3, 0x14

    .line 1169
    .line 1170
    int-to-float v3, v3

    .line 1171
    goto :goto_24

    .line 1172
    :goto_25
    if-eqz v1, :cond_3c

    .line 1173
    .line 1174
    neg-float v2, v2

    .line 1175
    :cond_3c
    iget-object v1, v7, Ld4/a;->b:Llx0/e;

    .line 1176
    .line 1177
    check-cast v1, Lay0/k;

    .line 1178
    .line 1179
    if-eqz v1, :cond_8e

    .line 1180
    .line 1181
    iget v0, v0, Ld4/h;->a:F

    .line 1182
    .line 1183
    add-float/2addr v0, v2

    .line 1184
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1185
    .line 1186
    .line 1187
    move-result-object v0

    .line 1188
    invoke-interface {v1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v0

    .line 1192
    check-cast v0, Ljava/lang/Boolean;

    .line 1193
    .line 1194
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1195
    .line 1196
    .line 1197
    move-result v13

    .line 1198
    goto/16 :goto_4a

    .line 1199
    .line 1200
    :cond_3d
    iget-object v0, v11, Lv3/h0;->H:Lg1/q;

    .line 1201
    .line 1202
    iget-object v0, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 1203
    .line 1204
    check-cast v0, Lv3/u;

    .line 1205
    .line 1206
    invoke-static {v0}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 1207
    .line 1208
    .line 1209
    move-result-object v0

    .line 1210
    invoke-virtual {v0}, Ld3/c;->c()J

    .line 1211
    .line 1212
    .line 1213
    move-result-wide v7

    .line 1214
    new-instance v0, Ljava/util/ArrayList;

    .line 1215
    .line 1216
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1217
    .line 1218
    .line 1219
    sget-object v9, Ld4/k;->B:Ld4/z;

    .line 1220
    .line 1221
    invoke-virtual {v13, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v9

    .line 1225
    if-nez v9, :cond_3e

    .line 1226
    .line 1227
    const/4 v9, 0x0

    .line 1228
    :cond_3e
    check-cast v9, Ld4/a;

    .line 1229
    .line 1230
    if-eqz v9, :cond_3f

    .line 1231
    .line 1232
    iget-object v9, v9, Ld4/a;->b:Llx0/e;

    .line 1233
    .line 1234
    check-cast v9, Lay0/k;

    .line 1235
    .line 1236
    if-eqz v9, :cond_3f

    .line 1237
    .line 1238
    invoke-interface {v9, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1239
    .line 1240
    .line 1241
    move-result-object v9

    .line 1242
    check-cast v9, Ljava/lang/Boolean;

    .line 1243
    .line 1244
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1245
    .line 1246
    .line 1247
    move-result v9

    .line 1248
    if-eqz v9, :cond_3f

    .line 1249
    .line 1250
    const/4 v9, 0x0

    .line 1251
    invoke-virtual {v0, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v0

    .line 1255
    check-cast v0, Ljava/lang/Float;

    .line 1256
    .line 1257
    goto :goto_26

    .line 1258
    :cond_3f
    const/4 v0, 0x0

    .line 1259
    :goto_26
    sget-object v9, Ld4/k;->d:Ld4/z;

    .line 1260
    .line 1261
    invoke-virtual {v13, v9}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v9

    .line 1265
    if-nez v9, :cond_40

    .line 1266
    .line 1267
    const/4 v9, 0x0

    .line 1268
    :cond_40
    check-cast v9, Ld4/a;

    .line 1269
    .line 1270
    if-nez v9, :cond_41

    .line 1271
    .line 1272
    goto/16 :goto_49

    .line 1273
    .line 1274
    :cond_41
    iget-object v9, v9, Ld4/a;->b:Llx0/e;

    .line 1275
    .line 1276
    sget-object v10, Ld4/v;->t:Ld4/z;

    .line 1277
    .line 1278
    invoke-virtual {v13, v10}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1279
    .line 1280
    .line 1281
    move-result-object v10

    .line 1282
    if-nez v10, :cond_42

    .line 1283
    .line 1284
    const/4 v10, 0x0

    .line 1285
    :cond_42
    check-cast v10, Ld4/j;

    .line 1286
    .line 1287
    if-eqz v10, :cond_4f

    .line 1288
    .line 1289
    if-eqz v6, :cond_4f

    .line 1290
    .line 1291
    if-eqz v0, :cond_43

    .line 1292
    .line 1293
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 1294
    .line 1295
    .line 1296
    move-result v6

    .line 1297
    move-object/from16 p2, v0

    .line 1298
    .line 1299
    move/from16 p1, v1

    .line 1300
    .line 1301
    goto :goto_27

    .line 1302
    :cond_43
    const/16 v6, 0x20

    .line 1303
    .line 1304
    move-object/from16 p2, v0

    .line 1305
    .line 1306
    move/from16 p1, v1

    .line 1307
    .line 1308
    shr-long v0, v7, v6

    .line 1309
    .line 1310
    long-to-int v0, v0

    .line 1311
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1312
    .line 1313
    .line 1314
    move-result v6

    .line 1315
    :goto_27
    if-nez v3, :cond_44

    .line 1316
    .line 1317
    if-eqz p1, :cond_45

    .line 1318
    .line 1319
    :cond_44
    neg-float v6, v6

    .line 1320
    :cond_45
    iget-boolean v0, v10, Ld4/j;->c:Z

    .line 1321
    .line 1322
    if-eqz v0, :cond_46

    .line 1323
    .line 1324
    neg-float v6, v6

    .line 1325
    :cond_46
    iget-object v0, v11, Lv3/h0;->B:Lt4/m;

    .line 1326
    .line 1327
    sget-object v1, Lt4/m;->e:Lt4/m;

    .line 1328
    .line 1329
    if-ne v0, v1, :cond_47

    .line 1330
    .line 1331
    const/4 v14, 0x1

    .line 1332
    goto :goto_28

    .line 1333
    :cond_47
    const/4 v14, 0x0

    .line 1334
    :goto_28
    if-eqz v14, :cond_49

    .line 1335
    .line 1336
    if-nez v3, :cond_48

    .line 1337
    .line 1338
    if-eqz v4, :cond_49

    .line 1339
    .line 1340
    :cond_48
    neg-float v6, v6

    .line 1341
    :cond_49
    invoke-static {v10, v6}, Lw3/z;->x(Ld4/j;F)Z

    .line 1342
    .line 1343
    .line 1344
    move-result v0

    .line 1345
    if-eqz v0, :cond_50

    .line 1346
    .line 1347
    sget-object v0, Ld4/k;->y:Ld4/z;

    .line 1348
    .line 1349
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1350
    .line 1351
    .line 1352
    move-result v1

    .line 1353
    if-nez v1, :cond_4b

    .line 1354
    .line 1355
    sget-object v1, Ld4/k;->A:Ld4/z;

    .line 1356
    .line 1357
    invoke-virtual {v13, v1}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1358
    .line 1359
    .line 1360
    move-result v1

    .line 1361
    if-eqz v1, :cond_4a

    .line 1362
    .line 1363
    goto :goto_29

    .line 1364
    :cond_4a
    check-cast v9, Lay0/n;

    .line 1365
    .line 1366
    if-eqz v9, :cond_8e

    .line 1367
    .line 1368
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v0

    .line 1372
    invoke-interface {v9, v0, v15}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1373
    .line 1374
    .line 1375
    move-result-object v0

    .line 1376
    check-cast v0, Ljava/lang/Boolean;

    .line 1377
    .line 1378
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1379
    .line 1380
    .line 1381
    move-result v13

    .line 1382
    goto/16 :goto_4a

    .line 1383
    .line 1384
    :cond_4b
    :goto_29
    cmpl-float v1, v6, p0

    .line 1385
    .line 1386
    if-lez v1, :cond_4d

    .line 1387
    .line 1388
    sget-object v0, Ld4/k;->A:Ld4/z;

    .line 1389
    .line 1390
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1391
    .line 1392
    .line 1393
    move-result-object v0

    .line 1394
    if-nez v0, :cond_4c

    .line 1395
    .line 1396
    const/4 v14, 0x0

    .line 1397
    goto :goto_2a

    .line 1398
    :cond_4c
    move-object v14, v0

    .line 1399
    :goto_2a
    check-cast v14, Ld4/a;

    .line 1400
    .line 1401
    goto :goto_2c

    .line 1402
    :cond_4d
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1403
    .line 1404
    .line 1405
    move-result-object v0

    .line 1406
    if-nez v0, :cond_4e

    .line 1407
    .line 1408
    const/4 v14, 0x0

    .line 1409
    goto :goto_2b

    .line 1410
    :cond_4e
    move-object v14, v0

    .line 1411
    :goto_2b
    check-cast v14, Ld4/a;

    .line 1412
    .line 1413
    :goto_2c
    if-eqz v14, :cond_8e

    .line 1414
    .line 1415
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 1416
    .line 1417
    check-cast v0, Lay0/a;

    .line 1418
    .line 1419
    if-eqz v0, :cond_8e

    .line 1420
    .line 1421
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1422
    .line 1423
    .line 1424
    move-result-object v0

    .line 1425
    check-cast v0, Ljava/lang/Boolean;

    .line 1426
    .line 1427
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1428
    .line 1429
    .line 1430
    move-result v13

    .line 1431
    goto/16 :goto_4a

    .line 1432
    .line 1433
    :cond_4f
    move-object/from16 p2, v0

    .line 1434
    .line 1435
    move/from16 p1, v1

    .line 1436
    .line 1437
    :cond_50
    sget-object v0, Ld4/v;->u:Ld4/z;

    .line 1438
    .line 1439
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1440
    .line 1441
    .line 1442
    move-result-object v0

    .line 1443
    if-nez v0, :cond_51

    .line 1444
    .line 1445
    const/4 v0, 0x0

    .line 1446
    :cond_51
    check-cast v0, Ld4/j;

    .line 1447
    .line 1448
    if-eqz v0, :cond_8e

    .line 1449
    .line 1450
    if-eqz v2, :cond_8e

    .line 1451
    .line 1452
    if-eqz p2, :cond_52

    .line 1453
    .line 1454
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Float;->floatValue()F

    .line 1455
    .line 1456
    .line 1457
    move-result v1

    .line 1458
    goto :goto_2d

    .line 1459
    :cond_52
    const-wide v1, 0xffffffffL

    .line 1460
    .line 1461
    .line 1462
    .line 1463
    .line 1464
    and-long/2addr v1, v7

    .line 1465
    long-to-int v1, v1

    .line 1466
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1467
    .line 1468
    .line 1469
    move-result v1

    .line 1470
    :goto_2d
    if-nez v5, :cond_53

    .line 1471
    .line 1472
    if-eqz p1, :cond_54

    .line 1473
    .line 1474
    :cond_53
    neg-float v1, v1

    .line 1475
    :cond_54
    iget-boolean v2, v0, Ld4/j;->c:Z

    .line 1476
    .line 1477
    if-eqz v2, :cond_55

    .line 1478
    .line 1479
    neg-float v1, v1

    .line 1480
    :cond_55
    invoke-static {v0, v1}, Lw3/z;->x(Ld4/j;F)Z

    .line 1481
    .line 1482
    .line 1483
    move-result v0

    .line 1484
    if-eqz v0, :cond_8e

    .line 1485
    .line 1486
    sget-object v0, Ld4/k;->x:Ld4/z;

    .line 1487
    .line 1488
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1489
    .line 1490
    .line 1491
    move-result v2

    .line 1492
    if-nez v2, :cond_57

    .line 1493
    .line 1494
    sget-object v2, Ld4/k;->z:Ld4/z;

    .line 1495
    .line 1496
    invoke-virtual {v13, v2}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1497
    .line 1498
    .line 1499
    move-result v2

    .line 1500
    if-eqz v2, :cond_56

    .line 1501
    .line 1502
    goto :goto_2e

    .line 1503
    :cond_56
    check-cast v9, Lay0/n;

    .line 1504
    .line 1505
    if-eqz v9, :cond_8e

    .line 1506
    .line 1507
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1508
    .line 1509
    .line 1510
    move-result-object v0

    .line 1511
    invoke-interface {v9, v15, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1512
    .line 1513
    .line 1514
    move-result-object v0

    .line 1515
    check-cast v0, Ljava/lang/Boolean;

    .line 1516
    .line 1517
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1518
    .line 1519
    .line 1520
    move-result v13

    .line 1521
    goto/16 :goto_4a

    .line 1522
    .line 1523
    :cond_57
    :goto_2e
    cmpl-float v1, v1, p0

    .line 1524
    .line 1525
    if-lez v1, :cond_59

    .line 1526
    .line 1527
    sget-object v0, Ld4/k;->z:Ld4/z;

    .line 1528
    .line 1529
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1530
    .line 1531
    .line 1532
    move-result-object v0

    .line 1533
    if-nez v0, :cond_58

    .line 1534
    .line 1535
    const/4 v14, 0x0

    .line 1536
    goto :goto_2f

    .line 1537
    :cond_58
    move-object v14, v0

    .line 1538
    :goto_2f
    check-cast v14, Ld4/a;

    .line 1539
    .line 1540
    goto :goto_31

    .line 1541
    :cond_59
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1542
    .line 1543
    .line 1544
    move-result-object v0

    .line 1545
    if-nez v0, :cond_5a

    .line 1546
    .line 1547
    const/4 v14, 0x0

    .line 1548
    goto :goto_30

    .line 1549
    :cond_5a
    move-object v14, v0

    .line 1550
    :goto_30
    check-cast v14, Ld4/a;

    .line 1551
    .line 1552
    :goto_31
    if-eqz v14, :cond_8e

    .line 1553
    .line 1554
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 1555
    .line 1556
    check-cast v0, Lay0/a;

    .line 1557
    .line 1558
    if-eqz v0, :cond_8e

    .line 1559
    .line 1560
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1561
    .line 1562
    .line 1563
    move-result-object v0

    .line 1564
    check-cast v0, Ljava/lang/Boolean;

    .line 1565
    .line 1566
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1567
    .line 1568
    .line 1569
    move-result v13

    .line 1570
    goto/16 :goto_4a

    .line 1571
    .line 1572
    :sswitch_a
    sget-object v0, Ld4/k;->c:Ld4/z;

    .line 1573
    .line 1574
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1575
    .line 1576
    .line 1577
    move-result-object v0

    .line 1578
    if-nez v0, :cond_5b

    .line 1579
    .line 1580
    const/4 v14, 0x0

    .line 1581
    goto :goto_32

    .line 1582
    :cond_5b
    move-object v14, v0

    .line 1583
    :goto_32
    check-cast v14, Ld4/a;

    .line 1584
    .line 1585
    if-eqz v14, :cond_8e

    .line 1586
    .line 1587
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 1588
    .line 1589
    check-cast v0, Lay0/a;

    .line 1590
    .line 1591
    if-eqz v0, :cond_8e

    .line 1592
    .line 1593
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1594
    .line 1595
    .line 1596
    move-result-object v0

    .line 1597
    check-cast v0, Ljava/lang/Boolean;

    .line 1598
    .line 1599
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1600
    .line 1601
    .line 1602
    move-result v13

    .line 1603
    goto/16 :goto_4a

    .line 1604
    .line 1605
    :sswitch_b
    sget-object v2, Ld4/k;->b:Ld4/z;

    .line 1606
    .line 1607
    invoke-virtual {v13, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1608
    .line 1609
    .line 1610
    move-result-object v2

    .line 1611
    if-nez v2, :cond_5c

    .line 1612
    .line 1613
    const/4 v2, 0x0

    .line 1614
    :cond_5c
    check-cast v2, Ld4/a;

    .line 1615
    .line 1616
    if-eqz v2, :cond_5d

    .line 1617
    .line 1618
    iget-object v2, v2, Ld4/a;->b:Llx0/e;

    .line 1619
    .line 1620
    check-cast v2, Lay0/a;

    .line 1621
    .line 1622
    if-eqz v2, :cond_5d

    .line 1623
    .line 1624
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1625
    .line 1626
    .line 1627
    move-result-object v2

    .line 1628
    check-cast v2, Ljava/lang/Boolean;

    .line 1629
    .line 1630
    move-object/from16 v21, v2

    .line 1631
    .line 1632
    :goto_33
    const/4 v2, 0x0

    .line 1633
    const/4 v6, 0x1

    .line 1634
    goto :goto_34

    .line 1635
    :cond_5d
    const/16 v21, 0x0

    .line 1636
    .line 1637
    goto :goto_33

    .line 1638
    :goto_34
    invoke-static {v0, v1, v6, v2, v7}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 1639
    .line 1640
    .line 1641
    if-eqz v21, :cond_8e

    .line 1642
    .line 1643
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1644
    .line 1645
    .line 1646
    move-result v13

    .line 1647
    goto/16 :goto_4a

    .line 1648
    .line 1649
    :cond_5e
    sget-object v0, Ld4/v;->k:Ld4/z;

    .line 1650
    .line 1651
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1652
    .line 1653
    .line 1654
    move-result-object v0

    .line 1655
    if-nez v0, :cond_5f

    .line 1656
    .line 1657
    const/4 v0, 0x0

    .line 1658
    :cond_5f
    invoke-static {v0, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1659
    .line 1660
    .line 1661
    move-result v0

    .line 1662
    if-eqz v0, :cond_8e

    .line 1663
    .line 1664
    invoke-virtual {v5}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 1665
    .line 1666
    .line 1667
    move-result-object v0

    .line 1668
    check-cast v0, Lc3/l;

    .line 1669
    .line 1670
    const/4 v6, 0x1

    .line 1671
    const/4 v9, 0x0

    .line 1672
    invoke-virtual {v0, v4, v9, v6}, Lc3/l;->d(IZZ)Z

    .line 1673
    .line 1674
    .line 1675
    goto/16 :goto_12

    .line 1676
    .line 1677
    :cond_60
    invoke-virtual {v5}, Landroid/view/View;->isInTouchMode()Z

    .line 1678
    .line 1679
    .line 1680
    move-result v0

    .line 1681
    if-eqz v0, :cond_61

    .line 1682
    .line 1683
    invoke-virtual {v5}, Landroid/view/View;->requestFocusFromTouch()Z

    .line 1684
    .line 1685
    .line 1686
    :cond_61
    sget-object v0, Ld4/k;->v:Ld4/z;

    .line 1687
    .line 1688
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1689
    .line 1690
    .line 1691
    move-result-object v0

    .line 1692
    if-nez v0, :cond_62

    .line 1693
    .line 1694
    const/4 v14, 0x0

    .line 1695
    goto :goto_35

    .line 1696
    :cond_62
    move-object v14, v0

    .line 1697
    :goto_35
    check-cast v14, Ld4/a;

    .line 1698
    .line 1699
    if-eqz v14, :cond_8e

    .line 1700
    .line 1701
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 1702
    .line 1703
    check-cast v0, Lay0/a;

    .line 1704
    .line 1705
    if-eqz v0, :cond_8e

    .line 1706
    .line 1707
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1708
    .line 1709
    .line 1710
    move-result-object v0

    .line 1711
    check-cast v0, Ljava/lang/Boolean;

    .line 1712
    .line 1713
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1714
    .line 1715
    .line 1716
    move-result v13

    .line 1717
    goto/16 :goto_4a

    .line 1718
    .line 1719
    :cond_63
    if-eqz v3, :cond_64

    .line 1720
    .line 1721
    const-string v1, "ACTION_ARGUMENT_SELECTION_START_INT"

    .line 1722
    .line 1723
    const/4 v2, -0x1

    .line 1724
    invoke-virtual {v3, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 1725
    .line 1726
    .line 1727
    move-result v18

    .line 1728
    move/from16 v1, v18

    .line 1729
    .line 1730
    goto :goto_36

    .line 1731
    :cond_64
    const/4 v2, -0x1

    .line 1732
    move v1, v2

    .line 1733
    :goto_36
    if-eqz v3, :cond_65

    .line 1734
    .line 1735
    const-string v4, "ACTION_ARGUMENT_SELECTION_END_INT"

    .line 1736
    .line 1737
    invoke-virtual {v3, v4, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 1738
    .line 1739
    .line 1740
    move-result v9

    .line 1741
    :goto_37
    const/4 v2, 0x0

    .line 1742
    goto :goto_38

    .line 1743
    :cond_65
    const/4 v9, -0x1

    .line 1744
    goto :goto_37

    .line 1745
    :goto_38
    invoke-virtual {v0, v12, v1, v9, v2}, Lw3/z;->K(Ld4/q;IIZ)Z

    .line 1746
    .line 1747
    .line 1748
    move-result v1

    .line 1749
    if-eqz v1, :cond_66

    .line 1750
    .line 1751
    invoke-virtual {v0, v6}, Lw3/z;->A(I)I

    .line 1752
    .line 1753
    .line 1754
    move-result v3

    .line 1755
    const/4 v4, 0x0

    .line 1756
    invoke-static {v0, v3, v2, v4, v7}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 1757
    .line 1758
    .line 1759
    :cond_66
    move v13, v1

    .line 1760
    goto/16 :goto_4a

    .line 1761
    .line 1762
    :cond_67
    sget-object v0, Ld4/k;->p:Ld4/z;

    .line 1763
    .line 1764
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1765
    .line 1766
    .line 1767
    move-result-object v0

    .line 1768
    if-nez v0, :cond_68

    .line 1769
    .line 1770
    const/4 v14, 0x0

    .line 1771
    goto :goto_39

    .line 1772
    :cond_68
    move-object v14, v0

    .line 1773
    :goto_39
    check-cast v14, Ld4/a;

    .line 1774
    .line 1775
    if-eqz v14, :cond_8e

    .line 1776
    .line 1777
    iget-object v0, v14, Ld4/a;->b:Llx0/e;

    .line 1778
    .line 1779
    check-cast v0, Lay0/a;

    .line 1780
    .line 1781
    if-eqz v0, :cond_8e

    .line 1782
    .line 1783
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1784
    .line 1785
    .line 1786
    move-result-object v0

    .line 1787
    check-cast v0, Ljava/lang/Boolean;

    .line 1788
    .line 1789
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1790
    .line 1791
    .line 1792
    move-result v13

    .line 1793
    goto/16 :goto_4a

    .line 1794
    .line 1795
    :cond_69
    if-eqz v3, :cond_8e

    .line 1796
    .line 1797
    const-string v1, "ACTION_ARGUMENT_MOVEMENT_GRANULARITY_INT"

    .line 1798
    .line 1799
    invoke-virtual {v3, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 1800
    .line 1801
    .line 1802
    move-result v1

    .line 1803
    const-string v7, "ACTION_ARGUMENT_EXTEND_SELECTION_BOOLEAN"

    .line 1804
    .line 1805
    invoke-virtual {v3, v7}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 1806
    .line 1807
    .line 1808
    move-result v3

    .line 1809
    if-ne v2, v10, :cond_6a

    .line 1810
    .line 1811
    const/4 v2, 0x1

    .line 1812
    goto :goto_3a

    .line 1813
    :cond_6a
    const/4 v2, 0x0

    .line 1814
    :goto_3a
    iget-object v7, v0, Lw3/z;->x:Ljava/lang/Integer;

    .line 1815
    .line 1816
    if-nez v7, :cond_6b

    .line 1817
    .line 1818
    :goto_3b
    const/4 v7, -0x1

    .line 1819
    goto :goto_3c

    .line 1820
    :cond_6b
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 1821
    .line 1822
    .line 1823
    move-result v7

    .line 1824
    if-eq v6, v7, :cond_6c

    .line 1825
    .line 1826
    goto :goto_3b

    .line 1827
    :goto_3c
    iput v7, v0, Lw3/z;->w:I

    .line 1828
    .line 1829
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1830
    .line 1831
    .line 1832
    move-result-object v6

    .line 1833
    iput-object v6, v0, Lw3/z;->x:Ljava/lang/Integer;

    .line 1834
    .line 1835
    :cond_6c
    invoke-static {v12}, Lw3/z;->u(Ld4/q;)Ljava/lang/String;

    .line 1836
    .line 1837
    .line 1838
    move-result-object v6

    .line 1839
    if-eqz v6, :cond_8e

    .line 1840
    .line 1841
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 1842
    .line 1843
    .line 1844
    move-result v7

    .line 1845
    if-nez v7, :cond_6d

    .line 1846
    .line 1847
    goto/16 :goto_49

    .line 1848
    .line 1849
    :cond_6d
    invoke-static {v12}, Lw3/z;->u(Ld4/q;)Ljava/lang/String;

    .line 1850
    .line 1851
    .line 1852
    move-result-object v7

    .line 1853
    if-eqz v7, :cond_6f

    .line 1854
    .line 1855
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 1856
    .line 1857
    .line 1858
    move-result v11

    .line 1859
    if-nez v11, :cond_6e

    .line 1860
    .line 1861
    goto :goto_3d

    .line 1862
    :cond_6e
    const/4 v11, 0x1

    .line 1863
    if-eq v1, v11, :cond_7a

    .line 1864
    .line 1865
    const/4 v11, 0x2

    .line 1866
    if-eq v1, v11, :cond_78

    .line 1867
    .line 1868
    const/4 v5, 0x4

    .line 1869
    if-eq v1, v5, :cond_72

    .line 1870
    .line 1871
    if-eq v1, v4, :cond_70

    .line 1872
    .line 1873
    const/16 v11, 0x10

    .line 1874
    .line 1875
    if-eq v1, v11, :cond_72

    .line 1876
    .line 1877
    :cond_6f
    :goto_3d
    const/4 v14, 0x0

    .line 1878
    goto/16 :goto_3e

    .line 1879
    .line 1880
    :cond_70
    sget-object v5, Lw3/e;->d:Lw3/e;

    .line 1881
    .line 1882
    if-nez v5, :cond_71

    .line 1883
    .line 1884
    new-instance v5, Lw3/e;

    .line 1885
    .line 1886
    invoke-direct {v5, v4}, Lh/w;-><init>(I)V

    .line 1887
    .line 1888
    .line 1889
    sput-object v5, Lw3/e;->d:Lw3/e;

    .line 1890
    .line 1891
    :cond_71
    sget-object v14, Lw3/e;->d:Lw3/e;

    .line 1892
    .line 1893
    const-string v4, "null cannot be cast to non-null type androidx.compose.ui.platform.AccessibilityIterators.ParagraphTextSegmentIterator"

    .line 1894
    .line 1895
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1896
    .line 1897
    .line 1898
    iput-object v7, v14, Lh/w;->b:Ljava/lang/Object;

    .line 1899
    .line 1900
    goto/16 :goto_3e

    .line 1901
    .line 1902
    :cond_72
    sget-object v11, Ld4/k;->a:Ld4/z;

    .line 1903
    .line 1904
    invoke-virtual {v13, v11}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 1905
    .line 1906
    .line 1907
    move-result v11

    .line 1908
    if-nez v11, :cond_73

    .line 1909
    .line 1910
    goto :goto_3d

    .line 1911
    :cond_73
    invoke-static {v9}, Lw3/h0;->v(Ld4/l;)Lg4/l0;

    .line 1912
    .line 1913
    .line 1914
    move-result-object v9

    .line 1915
    if-nez v9, :cond_74

    .line 1916
    .line 1917
    goto :goto_3d

    .line 1918
    :cond_74
    if-ne v1, v5, :cond_76

    .line 1919
    .line 1920
    sget-object v5, Lw3/c;->e:Lw3/c;

    .line 1921
    .line 1922
    if-nez v5, :cond_75

    .line 1923
    .line 1924
    new-instance v5, Lw3/c;

    .line 1925
    .line 1926
    invoke-direct {v5, v4}, Lh/w;-><init>(I)V

    .line 1927
    .line 1928
    .line 1929
    sput-object v5, Lw3/c;->e:Lw3/c;

    .line 1930
    .line 1931
    :cond_75
    sget-object v14, Lw3/c;->e:Lw3/c;

    .line 1932
    .line 1933
    const-string v4, "null cannot be cast to non-null type androidx.compose.ui.platform.AccessibilityIterators.LineTextSegmentIterator"

    .line 1934
    .line 1935
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1936
    .line 1937
    .line 1938
    iput-object v7, v14, Lh/w;->b:Ljava/lang/Object;

    .line 1939
    .line 1940
    iput-object v9, v14, Lw3/c;->d:Lg4/l0;

    .line 1941
    .line 1942
    goto :goto_3e

    .line 1943
    :cond_76
    sget-object v5, Lw3/d;->f:Lw3/d;

    .line 1944
    .line 1945
    if-nez v5, :cond_77

    .line 1946
    .line 1947
    new-instance v5, Lw3/d;

    .line 1948
    .line 1949
    invoke-direct {v5, v4}, Lh/w;-><init>(I)V

    .line 1950
    .line 1951
    .line 1952
    new-instance v4, Landroid/graphics/Rect;

    .line 1953
    .line 1954
    invoke-direct {v4}, Landroid/graphics/Rect;-><init>()V

    .line 1955
    .line 1956
    .line 1957
    sput-object v5, Lw3/d;->f:Lw3/d;

    .line 1958
    .line 1959
    :cond_77
    sget-object v14, Lw3/d;->f:Lw3/d;

    .line 1960
    .line 1961
    const-string v4, "null cannot be cast to non-null type androidx.compose.ui.platform.AccessibilityIterators.PageTextSegmentIterator"

    .line 1962
    .line 1963
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1964
    .line 1965
    .line 1966
    iput-object v7, v14, Lh/w;->b:Ljava/lang/Object;

    .line 1967
    .line 1968
    iput-object v9, v14, Lw3/d;->d:Lg4/l0;

    .line 1969
    .line 1970
    iput-object v12, v14, Lw3/d;->e:Ld4/q;

    .line 1971
    .line 1972
    goto :goto_3e

    .line 1973
    :cond_78
    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 1974
    .line 1975
    .line 1976
    move-result-object v4

    .line 1977
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1978
    .line 1979
    .line 1980
    move-result-object v4

    .line 1981
    invoke-virtual {v4}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 1982
    .line 1983
    .line 1984
    move-result-object v4

    .line 1985
    iget-object v4, v4, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    .line 1986
    .line 1987
    sget-object v5, Lw3/b;->g:Lw3/b;

    .line 1988
    .line 1989
    if-nez v5, :cond_79

    .line 1990
    .line 1991
    new-instance v5, Lw3/b;

    .line 1992
    .line 1993
    const/4 v11, 0x1

    .line 1994
    invoke-direct {v5, v11}, Lw3/b;-><init>(I)V

    .line 1995
    .line 1996
    .line 1997
    invoke-static {v4}, Ljava/text/BreakIterator;->getWordInstance(Ljava/util/Locale;)Ljava/text/BreakIterator;

    .line 1998
    .line 1999
    .line 2000
    move-result-object v4

    .line 2001
    iput-object v4, v5, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 2002
    .line 2003
    sput-object v5, Lw3/b;->g:Lw3/b;

    .line 2004
    .line 2005
    :cond_79
    sget-object v14, Lw3/b;->g:Lw3/b;

    .line 2006
    .line 2007
    const-string v4, "null cannot be cast to non-null type androidx.compose.ui.platform.AccessibilityIterators.WordTextSegmentIterator"

    .line 2008
    .line 2009
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2010
    .line 2011
    .line 2012
    invoke-virtual {v14, v7}, Lw3/b;->q(Ljava/lang/String;)V

    .line 2013
    .line 2014
    .line 2015
    goto :goto_3e

    .line 2016
    :cond_7a
    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2017
    .line 2018
    .line 2019
    move-result-object v4

    .line 2020
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2021
    .line 2022
    .line 2023
    move-result-object v4

    .line 2024
    invoke-virtual {v4}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 2025
    .line 2026
    .line 2027
    move-result-object v4

    .line 2028
    iget-object v4, v4, Landroid/content/res/Configuration;->locale:Ljava/util/Locale;

    .line 2029
    .line 2030
    sget-object v5, Lw3/b;->f:Lw3/b;

    .line 2031
    .line 2032
    if-nez v5, :cond_7b

    .line 2033
    .line 2034
    new-instance v5, Lw3/b;

    .line 2035
    .line 2036
    const/4 v9, 0x0

    .line 2037
    invoke-direct {v5, v9}, Lw3/b;-><init>(I)V

    .line 2038
    .line 2039
    .line 2040
    invoke-static {v4}, Ljava/text/BreakIterator;->getCharacterInstance(Ljava/util/Locale;)Ljava/text/BreakIterator;

    .line 2041
    .line 2042
    .line 2043
    move-result-object v4

    .line 2044
    iput-object v4, v5, Lw3/b;->e:Ljava/text/BreakIterator;

    .line 2045
    .line 2046
    sput-object v5, Lw3/b;->f:Lw3/b;

    .line 2047
    .line 2048
    :cond_7b
    sget-object v14, Lw3/b;->f:Lw3/b;

    .line 2049
    .line 2050
    const-string v4, "null cannot be cast to non-null type androidx.compose.ui.platform.AccessibilityIterators.CharacterTextSegmentIterator"

    .line 2051
    .line 2052
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2053
    .line 2054
    .line 2055
    invoke-virtual {v14, v7}, Lw3/b;->q(Ljava/lang/String;)V

    .line 2056
    .line 2057
    .line 2058
    :goto_3e
    if-nez v14, :cond_7c

    .line 2059
    .line 2060
    goto/16 :goto_49

    .line 2061
    .line 2062
    :cond_7c
    invoke-virtual {v0, v12}, Lw3/z;->r(Ld4/q;)I

    .line 2063
    .line 2064
    .line 2065
    move-result v4

    .line 2066
    const/4 v7, -0x1

    .line 2067
    if-ne v4, v7, :cond_7e

    .line 2068
    .line 2069
    if-eqz v2, :cond_7d

    .line 2070
    .line 2071
    const/4 v4, 0x0

    .line 2072
    goto :goto_3f

    .line 2073
    :cond_7d
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 2074
    .line 2075
    .line 2076
    move-result v4

    .line 2077
    :cond_7e
    :goto_3f
    if-eqz v2, :cond_7f

    .line 2078
    .line 2079
    invoke-virtual {v14, v4}, Lh/w;->e(I)[I

    .line 2080
    .line 2081
    .line 2082
    move-result-object v4

    .line 2083
    goto :goto_40

    .line 2084
    :cond_7f
    invoke-virtual {v14, v4}, Lh/w;->m(I)[I

    .line 2085
    .line 2086
    .line 2087
    move-result-object v4

    .line 2088
    :goto_40
    if-nez v4, :cond_80

    .line 2089
    .line 2090
    goto/16 :goto_49

    .line 2091
    .line 2092
    :cond_80
    const/16 v19, 0x0

    .line 2093
    .line 2094
    aget v20, v4, v19

    .line 2095
    .line 2096
    const/16 v24, 0x1

    .line 2097
    .line 2098
    aget v21, v4, v24

    .line 2099
    .line 2100
    if-eqz v3, :cond_84

    .line 2101
    .line 2102
    sget-object v3, Ld4/v;->a:Ld4/z;

    .line 2103
    .line 2104
    invoke-virtual {v13, v3}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 2105
    .line 2106
    .line 2107
    move-result v3

    .line 2108
    if-nez v3, :cond_84

    .line 2109
    .line 2110
    sget-object v3, Ld4/v;->E:Ld4/z;

    .line 2111
    .line 2112
    invoke-virtual {v13, v3}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 2113
    .line 2114
    .line 2115
    move-result v3

    .line 2116
    if-eqz v3, :cond_84

    .line 2117
    .line 2118
    invoke-virtual {v0, v12}, Lw3/z;->s(Ld4/q;)I

    .line 2119
    .line 2120
    .line 2121
    move-result v3

    .line 2122
    const/4 v7, -0x1

    .line 2123
    if-ne v3, v7, :cond_82

    .line 2124
    .line 2125
    if-eqz v2, :cond_81

    .line 2126
    .line 2127
    move/from16 v3, v20

    .line 2128
    .line 2129
    goto :goto_41

    .line 2130
    :cond_81
    move/from16 v3, v21

    .line 2131
    .line 2132
    :cond_82
    :goto_41
    if-eqz v2, :cond_83

    .line 2133
    .line 2134
    move/from16 v4, v21

    .line 2135
    .line 2136
    goto :goto_43

    .line 2137
    :cond_83
    move/from16 v4, v20

    .line 2138
    .line 2139
    goto :goto_43

    .line 2140
    :cond_84
    if-eqz v2, :cond_85

    .line 2141
    .line 2142
    move/from16 v3, v21

    .line 2143
    .line 2144
    goto :goto_42

    .line 2145
    :cond_85
    move/from16 v3, v20

    .line 2146
    .line 2147
    :goto_42
    move v4, v3

    .line 2148
    :goto_43
    if-eqz v2, :cond_86

    .line 2149
    .line 2150
    move/from16 v18, v10

    .line 2151
    .line 2152
    goto :goto_44

    .line 2153
    :cond_86
    move/from16 v18, v8

    .line 2154
    .line 2155
    :goto_44
    new-instance v16, Lw3/w;

    .line 2156
    .line 2157
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 2158
    .line 2159
    .line 2160
    move-result-wide v22

    .line 2161
    move/from16 v19, v1

    .line 2162
    .line 2163
    move-object/from16 v17, v12

    .line 2164
    .line 2165
    invoke-direct/range {v16 .. v23}, Lw3/w;-><init>(Ld4/q;IIIIJ)V

    .line 2166
    .line 2167
    .line 2168
    move-object/from16 v2, v16

    .line 2169
    .line 2170
    move-object/from16 v1, v17

    .line 2171
    .line 2172
    iput-object v2, v0, Lw3/z;->B:Lw3/w;

    .line 2173
    .line 2174
    const/4 v6, 0x1

    .line 2175
    invoke-virtual {v0, v1, v3, v4, v6}, Lw3/z;->K(Ld4/q;IIZ)Z

    .line 2176
    .line 2177
    .line 2178
    goto/16 :goto_12

    .line 2179
    .line 2180
    :cond_87
    iget v2, v0, Lw3/z;->n:I

    .line 2181
    .line 2182
    if-ne v2, v1, :cond_88

    .line 2183
    .line 2184
    const/4 v6, 0x1

    .line 2185
    goto :goto_45

    .line 2186
    :cond_88
    const/4 v6, 0x0

    .line 2187
    :goto_45
    if-eqz v6, :cond_8e

    .line 2188
    .line 2189
    const/high16 v2, -0x80000000

    .line 2190
    .line 2191
    iput v2, v0, Lw3/z;->n:I

    .line 2192
    .line 2193
    const/4 v2, 0x0

    .line 2194
    iput-object v2, v0, Lw3/z;->p:Le6/d;

    .line 2195
    .line 2196
    invoke-virtual {v5}, Landroid/view/View;->invalidate()V

    .line 2197
    .line 2198
    .line 2199
    const/high16 v3, 0x10000

    .line 2200
    .line 2201
    invoke-static {v0, v1, v3, v2, v7}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 2202
    .line 2203
    .line 2204
    goto/16 :goto_12

    .line 2205
    .line 2206
    :cond_89
    invoke-virtual {v4}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 2207
    .line 2208
    .line 2209
    move-result v2

    .line 2210
    if-eqz v2, :cond_8a

    .line 2211
    .line 2212
    invoke-virtual {v4}, Landroid/view/accessibility/AccessibilityManager;->isTouchExplorationEnabled()Z

    .line 2213
    .line 2214
    .line 2215
    move-result v2

    .line 2216
    if-eqz v2, :cond_8a

    .line 2217
    .line 2218
    const/4 v6, 0x1

    .line 2219
    goto :goto_46

    .line 2220
    :cond_8a
    const/4 v6, 0x0

    .line 2221
    :goto_46
    if-nez v6, :cond_8b

    .line 2222
    .line 2223
    goto :goto_49

    .line 2224
    :cond_8b
    iget v2, v0, Lw3/z;->n:I

    .line 2225
    .line 2226
    if-ne v2, v1, :cond_8c

    .line 2227
    .line 2228
    const/4 v6, 0x1

    .line 2229
    goto :goto_47

    .line 2230
    :cond_8c
    const/4 v6, 0x0

    .line 2231
    :goto_47
    if-nez v6, :cond_8e

    .line 2232
    .line 2233
    const/high16 v3, -0x80000000

    .line 2234
    .line 2235
    if-eq v2, v3, :cond_8d

    .line 2236
    .line 2237
    const/high16 v3, 0x10000

    .line 2238
    .line 2239
    const/4 v4, 0x0

    .line 2240
    invoke-static {v0, v2, v3, v4, v7}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 2241
    .line 2242
    .line 2243
    goto :goto_48

    .line 2244
    :cond_8d
    const/4 v4, 0x0

    .line 2245
    :goto_48
    iput v1, v0, Lw3/z;->n:I

    .line 2246
    .line 2247
    invoke-virtual {v5}, Landroid/view/View;->invalidate()V

    .line 2248
    .line 2249
    .line 2250
    const v2, 0x8000

    .line 2251
    .line 2252
    .line 2253
    invoke-static {v0, v1, v2, v4, v7}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 2254
    .line 2255
    .line 2256
    goto/16 :goto_12

    .line 2257
    .line 2258
    :cond_8e
    :goto_49
    const/4 v13, 0x0

    .line 2259
    :goto_4a
    return v13

    .line 2260
    :pswitch_5
    check-cast v0, Lk6/b;

    .line 2261
    .line 2262
    iget-object v4, v0, Lk6/b;->i:Lcom/google/android/material/chip/Chip;

    .line 2263
    .line 2264
    const/4 v7, -0x1

    .line 2265
    if-eq v1, v7, :cond_99

    .line 2266
    .line 2267
    const/4 v6, 0x1

    .line 2268
    if-eq v2, v6, :cond_98

    .line 2269
    .line 2270
    const/4 v11, 0x2

    .line 2271
    if-eq v2, v11, :cond_97

    .line 2272
    .line 2273
    if-eq v2, v8, :cond_94

    .line 2274
    .line 2275
    const/16 v8, 0x80

    .line 2276
    .line 2277
    if-eq v2, v8, :cond_93

    .line 2278
    .line 2279
    check-cast v0, Lmq/d;

    .line 2280
    .line 2281
    iget-object v0, v0, Lmq/d;->q:Lcom/google/android/material/chip/Chip;

    .line 2282
    .line 2283
    const/16 v11, 0x10

    .line 2284
    .line 2285
    if-ne v2, v11, :cond_91

    .line 2286
    .line 2287
    if-nez v1, :cond_8f

    .line 2288
    .line 2289
    invoke-virtual {v0}, Landroid/view/View;->performClick()Z

    .line 2290
    .line 2291
    .line 2292
    move-result v13

    .line 2293
    goto/16 :goto_4e

    .line 2294
    .line 2295
    :cond_8f
    if-ne v1, v6, :cond_91

    .line 2296
    .line 2297
    const/4 v9, 0x0

    .line 2298
    invoke-virtual {v0, v9}, Landroid/view/View;->playSoundEffect(I)V

    .line 2299
    .line 2300
    .line 2301
    iget-object v1, v0, Lcom/google/android/material/chip/Chip;->k:Landroid/view/View$OnClickListener;

    .line 2302
    .line 2303
    if-eqz v1, :cond_90

    .line 2304
    .line 2305
    invoke-interface {v1, v0}, Landroid/view/View$OnClickListener;->onClick(Landroid/view/View;)V

    .line 2306
    .line 2307
    .line 2308
    move v13, v6

    .line 2309
    goto :goto_4b

    .line 2310
    :cond_90
    move v13, v9

    .line 2311
    :goto_4b
    iget-boolean v1, v0, Lcom/google/android/material/chip/Chip;->v:Z

    .line 2312
    .line 2313
    if-eqz v1, :cond_9a

    .line 2314
    .line 2315
    iget-object v0, v0, Lcom/google/android/material/chip/Chip;->u:Lmq/d;

    .line 2316
    .line 2317
    invoke-virtual {v0, v6, v6}, Lk6/b;->r(II)V

    .line 2318
    .line 2319
    .line 2320
    goto :goto_4e

    .line 2321
    :cond_91
    const/4 v9, 0x0

    .line 2322
    :cond_92
    :goto_4c
    move v13, v9

    .line 2323
    goto :goto_4e

    .line 2324
    :cond_93
    const/4 v9, 0x0

    .line 2325
    iget v2, v0, Lk6/b;->k:I

    .line 2326
    .line 2327
    if-ne v2, v1, :cond_92

    .line 2328
    .line 2329
    const/high16 v2, -0x80000000

    .line 2330
    .line 2331
    iput v2, v0, Lk6/b;->k:I

    .line 2332
    .line 2333
    invoke-virtual {v4}, Landroid/view/View;->invalidate()V

    .line 2334
    .line 2335
    .line 2336
    const/high16 v3, 0x10000

    .line 2337
    .line 2338
    invoke-virtual {v0, v1, v3}, Lk6/b;->r(II)V

    .line 2339
    .line 2340
    .line 2341
    :goto_4d
    move v13, v6

    .line 2342
    goto :goto_4e

    .line 2343
    :cond_94
    const/4 v9, 0x0

    .line 2344
    iget-object v2, v0, Lk6/b;->h:Landroid/view/accessibility/AccessibilityManager;

    .line 2345
    .line 2346
    invoke-virtual {v2}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 2347
    .line 2348
    .line 2349
    move-result v3

    .line 2350
    if-eqz v3, :cond_92

    .line 2351
    .line 2352
    invoke-virtual {v2}, Landroid/view/accessibility/AccessibilityManager;->isTouchExplorationEnabled()Z

    .line 2353
    .line 2354
    .line 2355
    move-result v2

    .line 2356
    if-nez v2, :cond_95

    .line 2357
    .line 2358
    goto :goto_4c

    .line 2359
    :cond_95
    iget v2, v0, Lk6/b;->k:I

    .line 2360
    .line 2361
    if-eq v2, v1, :cond_92

    .line 2362
    .line 2363
    const/high16 v3, -0x80000000

    .line 2364
    .line 2365
    if-eq v2, v3, :cond_96

    .line 2366
    .line 2367
    iput v3, v0, Lk6/b;->k:I

    .line 2368
    .line 2369
    invoke-virtual {v4}, Landroid/view/View;->invalidate()V

    .line 2370
    .line 2371
    .line 2372
    const/high16 v3, 0x10000

    .line 2373
    .line 2374
    invoke-virtual {v0, v2, v3}, Lk6/b;->r(II)V

    .line 2375
    .line 2376
    .line 2377
    :cond_96
    iput v1, v0, Lk6/b;->k:I

    .line 2378
    .line 2379
    invoke-virtual {v4}, Landroid/view/View;->invalidate()V

    .line 2380
    .line 2381
    .line 2382
    const v2, 0x8000

    .line 2383
    .line 2384
    .line 2385
    invoke-virtual {v0, v1, v2}, Lk6/b;->r(II)V

    .line 2386
    .line 2387
    .line 2388
    goto :goto_4d

    .line 2389
    :cond_97
    invoke-virtual {v0, v1}, Lk6/b;->j(I)Z

    .line 2390
    .line 2391
    .line 2392
    move-result v13

    .line 2393
    goto :goto_4e

    .line 2394
    :cond_98
    invoke-virtual {v0, v1}, Lk6/b;->q(I)Z

    .line 2395
    .line 2396
    .line 2397
    move-result v13

    .line 2398
    goto :goto_4e

    .line 2399
    :cond_99
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 2400
    .line 2401
    invoke-virtual {v4, v2, v3}, Landroid/view/View;->performAccessibilityAction(ILandroid/os/Bundle;)Z

    .line 2402
    .line 2403
    .line 2404
    move-result v13

    .line 2405
    :cond_9a
    :goto_4e
    return v13

    .line 2406
    nop

    .line 2407
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
    .end packed-switch

    .line 2408
    .line 2409
    .line 2410
    .line 2411
    .line 2412
    .line 2413
    :sswitch_data_0
    .sparse-switch
        0x10 -> :sswitch_b
        0x20 -> :sswitch_a
        0x1000 -> :sswitch_9
        0x2000 -> :sswitch_9
        0x8000 -> :sswitch_8
        0x10000 -> :sswitch_7
        0x40000 -> :sswitch_6
        0x80000 -> :sswitch_5
        0x100000 -> :sswitch_4
        0x200000 -> :sswitch_3
        0x1020036 -> :sswitch_2
        0x102003d -> :sswitch_1
        0x1020054 -> :sswitch_0
    .end sparse-switch

    .line 2414
    .line 2415
    .line 2416
    .line 2417
    .line 2418
    .line 2419
    .line 2420
    .line 2421
    .line 2422
    .line 2423
    .line 2424
    .line 2425
    .line 2426
    .line 2427
    .line 2428
    .line 2429
    .line 2430
    .line 2431
    .line 2432
    .line 2433
    .line 2434
    .line 2435
    .line 2436
    .line 2437
    .line 2438
    .line 2439
    .line 2440
    .line 2441
    .line 2442
    .line 2443
    .line 2444
    .line 2445
    .line 2446
    .line 2447
    .line 2448
    .line 2449
    .line 2450
    .line 2451
    .line 2452
    .line 2453
    .line 2454
    .line 2455
    .line 2456
    .line 2457
    .line 2458
    .line 2459
    .line 2460
    .line 2461
    .line 2462
    .line 2463
    .line 2464
    .line 2465
    .line 2466
    .line 2467
    :pswitch_data_1
    .packed-switch 0x1020038
        :pswitch_4
        :pswitch_4
        :pswitch_4
        :pswitch_4
    .end packed-switch

    .line 2468
    .line 2469
    .line 2470
    .line 2471
    .line 2472
    .line 2473
    .line 2474
    .line 2475
    .line 2476
    .line 2477
    .line 2478
    .line 2479
    :pswitch_data_2
    .packed-switch 0x1020046
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
