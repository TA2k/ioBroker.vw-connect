.class public final Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\" \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00010\u00008FX\u0087\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u0004\u0010\u0005\u001a\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\t\u00b2\u0006\u000e\u0010\u0008\u001a\u00020\u00078\n@\nX\u008a\u008e\u0002"
    }
    d2 = {
        "Ll2/s1;",
        "Landroidx/lifecycle/x;",
        "getLocalLifecycleOwner",
        "()Ll2/s1;",
        "getLocalLifecycleOwner$annotations",
        "()V",
        "LocalLifecycleOwner",
        "Landroid/content/res/Configuration;",
        "configuration",
        "ui_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final a:Ll2/e0;

.field public static final b:Ll2/u2;

.field public static final c:Ll2/e0;

.field public static final d:Ll2/u2;

.field public static final e:Ll2/u2;

.field public static final f:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lw3/i0;->g:Lw3/i0;

    .line 2
    .line 3
    new-instance v1, Ll2/e0;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 9
    .line 10
    sget-object v0, Lw3/i0;->h:Lw3/i0;

    .line 11
    .line 12
    new-instance v1, Ll2/u2;

    .line 13
    .line 14
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 18
    .line 19
    sget-object v0, Lw3/o;->j:Lw3/o;

    .line 20
    .line 21
    new-instance v1, Ll2/e0;

    .line 22
    .line 23
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/k;)V

    .line 24
    .line 25
    .line 26
    sput-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 27
    .line 28
    sget-object v0, Lw3/i0;->i:Lw3/i0;

    .line 29
    .line 30
    new-instance v1, Ll2/u2;

    .line 31
    .line 32
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 33
    .line 34
    .line 35
    sput-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->d:Ll2/u2;

    .line 36
    .line 37
    sget-object v0, Lw3/i0;->j:Lw3/i0;

    .line 38
    .line 39
    new-instance v1, Ll2/u2;

    .line 40
    .line 41
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 42
    .line 43
    .line 44
    sput-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->e:Ll2/u2;

    .line 45
    .line 46
    sget-object v0, Lw3/i0;->k:Lw3/i0;

    .line 47
    .line 48
    new-instance v1, Ll2/u2;

    .line 49
    .line 50
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 51
    .line 52
    .line 53
    sput-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 54
    .line 55
    return-void
.end method

.method public static final a(Lw3/t;Lay0/n;Ll2/o;I)V
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x1f032317

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    const/4 v6, 0x2

    .line 22
    if-eqz v4, :cond_0

    .line 23
    .line 24
    const/4 v4, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move v4, v6

    .line 27
    :goto_0
    or-int/2addr v4, v2

    .line 28
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v7

    .line 32
    if-eqz v7, :cond_1

    .line 33
    .line 34
    const/16 v7, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v7, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v4, v7

    .line 40
    and-int/lit8 v7, v4, 0x13

    .line 41
    .line 42
    const/16 v8, 0x12

    .line 43
    .line 44
    const/4 v10, 0x1

    .line 45
    if-eq v7, v8, :cond_2

    .line 46
    .line 47
    move v7, v10

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v7, 0x0

    .line 50
    :goto_2
    and-int/2addr v4, v10

    .line 51
    invoke-virtual {v3, v4, v7}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    if-eqz v4, :cond_1a

    .line 56
    .line 57
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 66
    .line 67
    if-ne v7, v8, :cond_3

    .line 68
    .line 69
    new-instance v7, Landroid/content/res/Configuration;

    .line 70
    .line 71
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 72
    .line 73
    .line 74
    move-result-object v11

    .line 75
    invoke-virtual {v11}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 76
    .line 77
    .line 78
    move-result-object v11

    .line 79
    invoke-direct {v7, v11}, Landroid/content/res/Configuration;-><init>(Landroid/content/res/Configuration;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v7}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    invoke-virtual {v3, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_3
    check-cast v7, Ll2/b1;

    .line 90
    .line 91
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v11

    .line 95
    if-ne v11, v8, :cond_4

    .line 96
    .line 97
    new-instance v11, Lkn/m;

    .line 98
    .line 99
    invoke-direct {v11, v7, v6}, Lkn/m;-><init>(Ll2/b1;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :cond_4
    check-cast v11, Lay0/k;

    .line 106
    .line 107
    invoke-virtual {v0, v11}, Lw3/t;->setConfigurationChangeObserver(Lay0/k;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v11

    .line 114
    if-ne v11, v8, :cond_5

    .line 115
    .line 116
    new-instance v11, Lw3/r0;

    .line 117
    .line 118
    invoke-direct {v11, v4}, Lw3/r0;-><init>(Landroid/content/Context;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v3, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :cond_5
    check-cast v11, Lw3/r0;

    .line 125
    .line 126
    invoke-virtual {v0}, Lw3/t;->getViewTreeOwners()Lw3/l;

    .line 127
    .line 128
    .line 129
    move-result-object v12

    .line 130
    if-eqz v12, :cond_19

    .line 131
    .line 132
    iget-object v13, v12, Lw3/l;->b:Lra/f;

    .line 133
    .line 134
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v14

    .line 138
    if-ne v14, v8, :cond_a

    .line 139
    .line 140
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 141
    .line 142
    .line 143
    move-result-object v14

    .line 144
    const-string v15, "null cannot be cast to non-null type android.view.View"

    .line 145
    .line 146
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    check-cast v14, Landroid/view/View;

    .line 150
    .line 151
    const v15, 0x7f0a00e9

    .line 152
    .line 153
    .line 154
    invoke-virtual {v14, v15}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v15

    .line 158
    instance-of v9, v15, Ljava/lang/String;

    .line 159
    .line 160
    const/16 v16, 0x0

    .line 161
    .line 162
    if-eqz v9, :cond_6

    .line 163
    .line 164
    check-cast v15, Ljava/lang/String;

    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_6
    move-object/from16 v15, v16

    .line 168
    .line 169
    :goto_3
    if-nez v15, :cond_7

    .line 170
    .line 171
    invoke-virtual {v14}, Landroid/view/View;->getId()I

    .line 172
    .line 173
    .line 174
    move-result v9

    .line 175
    invoke-static {v9}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v15

    .line 179
    :cond_7
    new-instance v9, Ljava/lang/StringBuilder;

    .line 180
    .line 181
    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    .line 182
    .line 183
    .line 184
    const-class v14, Lu2/g;

    .line 185
    .line 186
    invoke-virtual {v14}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v14

    .line 190
    invoke-virtual {v9, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    const/16 v14, 0x3a

    .line 194
    .line 195
    invoke-virtual {v9, v14}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {v9, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v9

    .line 205
    invoke-interface {v13}, Lra/f;->getSavedStateRegistry()Lra/d;

    .line 206
    .line 207
    .line 208
    move-result-object v14

    .line 209
    invoke-virtual {v14, v9}, Lra/d;->a(Ljava/lang/String;)Landroid/os/Bundle;

    .line 210
    .line 211
    .line 212
    move-result-object v15

    .line 213
    if-eqz v15, :cond_9

    .line 214
    .line 215
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 216
    .line 217
    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v15}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 221
    .line 222
    .line 223
    move-result-object v16

    .line 224
    check-cast v16, Ljava/lang/Iterable;

    .line 225
    .line 226
    invoke-interface/range {v16 .. v16}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 227
    .line 228
    .line 229
    move-result-object v16

    .line 230
    :goto_4
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->hasNext()Z

    .line 231
    .line 232
    .line 233
    move-result v17

    .line 234
    if-eqz v17, :cond_8

    .line 235
    .line 236
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v17

    .line 240
    move-object/from16 v10, v17

    .line 241
    .line 242
    check-cast v10, Ljava/lang/String;

    .line 243
    .line 244
    invoke-virtual {v15, v10}, Landroid/os/Bundle;->getParcelableArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 245
    .line 246
    .line 247
    move-result-object v6

    .line 248
    move-object/from16 v19, v7

    .line 249
    .line 250
    const-string v7, "null cannot be cast to non-null type java.util.ArrayList<kotlin.Any?>"

    .line 251
    .line 252
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    invoke-interface {v5, v10, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-object/from16 v7, v19

    .line 259
    .line 260
    const/4 v6, 0x2

    .line 261
    const/4 v10, 0x1

    .line 262
    goto :goto_4

    .line 263
    :cond_8
    :goto_5
    move-object/from16 v19, v7

    .line 264
    .line 265
    goto :goto_6

    .line 266
    :cond_9
    move-object/from16 v5, v16

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :goto_6
    sget-object v6, Lw3/o;->k:Lw3/o;

    .line 270
    .line 271
    sget-object v7, Lu2/i;->a:Ll2/u2;

    .line 272
    .line 273
    new-instance v7, Lu2/h;

    .line 274
    .line 275
    invoke-direct {v7, v5, v6}, Lu2/h;-><init>(Ljava/util/Map;Lay0/k;)V

    .line 276
    .line 277
    .line 278
    :try_start_0
    new-instance v5, Lb/i;

    .line 279
    .line 280
    const/4 v6, 0x2

    .line 281
    invoke-direct {v5, v7, v6}, Lb/i;-><init>(Ljava/lang/Object;I)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v14, v9, v5}, Lra/d;->c(Ljava/lang/String;Lra/c;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 285
    .line 286
    .line 287
    const/4 v5, 0x1

    .line 288
    goto :goto_7

    .line 289
    :catch_0
    const/4 v5, 0x0

    .line 290
    :goto_7
    new-instance v6, Lw3/j1;

    .line 291
    .line 292
    new-instance v10, Lw3/k1;

    .line 293
    .line 294
    invoke-direct {v10, v5, v14, v9}, Lw3/k1;-><init>(ZLra/d;Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    invoke-direct {v6, v7, v10}, Lw3/j1;-><init>(Lu2/h;Lw3/k1;)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v3, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    move-object v14, v6

    .line 304
    goto :goto_8

    .line 305
    :cond_a
    move-object/from16 v19, v7

    .line 306
    .line 307
    :goto_8
    check-cast v14, Lw3/j1;

    .line 308
    .line 309
    invoke-virtual {v3, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    move-result v5

    .line 313
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v6

    .line 317
    if-nez v5, :cond_b

    .line 318
    .line 319
    if-ne v6, v8, :cond_c

    .line 320
    .line 321
    :cond_b
    new-instance v6, Lw3/a0;

    .line 322
    .line 323
    const/4 v5, 0x2

    .line 324
    invoke-direct {v6, v14, v5}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v3, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 328
    .line 329
    .line 330
    :cond_c
    check-cast v6, Lay0/k;

    .line 331
    .line 332
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 333
    .line 334
    invoke-static {v5, v6, v3}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v5

    .line 341
    if-ne v5, v8, :cond_e

    .line 342
    .line 343
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 344
    .line 345
    const/16 v6, 0x1f

    .line 346
    .line 347
    if-lt v5, v6, :cond_d

    .line 348
    .line 349
    const-class v5, Landroid/os/Vibrator;

    .line 350
    .line 351
    invoke-virtual {v4, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v5

    .line 355
    check-cast v5, Landroid/os/Vibrator;

    .line 356
    .line 357
    const/4 v6, 0x7

    .line 358
    const/4 v7, 0x2

    .line 359
    const/4 v9, 0x1

    .line 360
    filled-new-array {v9, v6, v7}, [I

    .line 361
    .line 362
    .line 363
    move-result-object v6

    .line 364
    invoke-static {v5, v6}, Ln01/a;->m(Landroid/os/Vibrator;[I)Z

    .line 365
    .line 366
    .line 367
    move-result v5

    .line 368
    if-eqz v5, :cond_d

    .line 369
    .line 370
    new-instance v5, Ll3/b;

    .line 371
    .line 372
    invoke-virtual {v0}, Lw3/t;->getView()Landroid/view/View;

    .line 373
    .line 374
    .line 375
    move-result-object v6

    .line 376
    invoke-direct {v5, v6, v9}, Ll3/b;-><init>(Landroid/view/View;I)V

    .line 377
    .line 378
    .line 379
    goto :goto_9

    .line 380
    :cond_d
    new-instance v5, Lw3/u1;

    .line 381
    .line 382
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 383
    .line 384
    .line 385
    :goto_9
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    :cond_e
    check-cast v5, Ll3/a;

    .line 389
    .line 390
    invoke-interface/range {v19 .. v19}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v6

    .line 394
    check-cast v6, Landroid/content/res/Configuration;

    .line 395
    .line 396
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    move-result-object v7

    .line 400
    if-ne v7, v8, :cond_f

    .line 401
    .line 402
    new-instance v7, Lb4/c;

    .line 403
    .line 404
    invoke-direct {v7}, Lb4/c;-><init>()V

    .line 405
    .line 406
    .line 407
    invoke-virtual {v3, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 408
    .line 409
    .line 410
    :cond_f
    check-cast v7, Lb4/c;

    .line 411
    .line 412
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v9

    .line 416
    if-ne v9, v8, :cond_11

    .line 417
    .line 418
    new-instance v9, Landroid/content/res/Configuration;

    .line 419
    .line 420
    invoke-direct {v9}, Landroid/content/res/Configuration;-><init>()V

    .line 421
    .line 422
    .line 423
    if-eqz v6, :cond_10

    .line 424
    .line 425
    invoke-virtual {v9, v6}, Landroid/content/res/Configuration;->setTo(Landroid/content/res/Configuration;)V

    .line 426
    .line 427
    .line 428
    :cond_10
    invoke-virtual {v3, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    :cond_11
    check-cast v9, Landroid/content/res/Configuration;

    .line 432
    .line 433
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object v6

    .line 437
    if-ne v6, v8, :cond_12

    .line 438
    .line 439
    new-instance v6, Lw3/j0;

    .line 440
    .line 441
    invoke-direct {v6, v9, v7}, Lw3/j0;-><init>(Landroid/content/res/Configuration;Lb4/c;)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v3, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 445
    .line 446
    .line 447
    :cond_12
    check-cast v6, Lw3/j0;

    .line 448
    .line 449
    invoke-virtual {v3, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 450
    .line 451
    .line 452
    move-result v9

    .line 453
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    move-result-object v10

    .line 457
    if-nez v9, :cond_13

    .line 458
    .line 459
    if-ne v10, v8, :cond_14

    .line 460
    .line 461
    :cond_13
    new-instance v10, Lb1/e;

    .line 462
    .line 463
    const/16 v9, 0xc

    .line 464
    .line 465
    invoke-direct {v10, v9, v4, v6}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v3, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    :cond_14
    check-cast v10, Lay0/k;

    .line 472
    .line 473
    invoke-static {v7, v10, v3}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 474
    .line 475
    .line 476
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v6

    .line 480
    if-ne v6, v8, :cond_15

    .line 481
    .line 482
    new-instance v6, Lb4/d;

    .line 483
    .line 484
    invoke-direct {v6}, Lb4/d;-><init>()V

    .line 485
    .line 486
    .line 487
    invoke-virtual {v3, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 488
    .line 489
    .line 490
    :cond_15
    check-cast v6, Lb4/d;

    .line 491
    .line 492
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v9

    .line 496
    if-ne v9, v8, :cond_16

    .line 497
    .line 498
    new-instance v9, Lw3/k0;

    .line 499
    .line 500
    invoke-direct {v9, v6}, Lw3/k0;-><init>(Lb4/d;)V

    .line 501
    .line 502
    .line 503
    invoke-virtual {v3, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 504
    .line 505
    .line 506
    :cond_16
    check-cast v9, Lw3/k0;

    .line 507
    .line 508
    invoke-virtual {v3, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 509
    .line 510
    .line 511
    move-result v10

    .line 512
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 513
    .line 514
    .line 515
    move-result-object v15

    .line 516
    if-nez v10, :cond_17

    .line 517
    .line 518
    if-ne v15, v8, :cond_18

    .line 519
    .line 520
    :cond_17
    new-instance v15, Lb1/e;

    .line 521
    .line 522
    const/16 v8, 0xd

    .line 523
    .line 524
    invoke-direct {v15, v8, v4, v9}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 525
    .line 526
    .line 527
    invoke-virtual {v3, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 528
    .line 529
    .line 530
    :cond_18
    check-cast v15, Lay0/k;

    .line 531
    .line 532
    invoke-static {v6, v15, v3}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 533
    .line 534
    .line 535
    sget-object v8, Lw3/h1;->v:Ll2/e0;

    .line 536
    .line 537
    invoke-virtual {v3, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 538
    .line 539
    .line 540
    move-result-object v9

    .line 541
    check-cast v9, Ljava/lang/Boolean;

    .line 542
    .line 543
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 544
    .line 545
    .line 546
    move-result v9

    .line 547
    invoke-virtual {v0}, Lw3/t;->getScrollCaptureInProgress$ui_release()Z

    .line 548
    .line 549
    .line 550
    move-result v10

    .line 551
    or-int/2addr v9, v10

    .line 552
    invoke-interface/range {v19 .. v19}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    move-result-object v10

    .line 556
    check-cast v10, Landroid/content/res/Configuration;

    .line 557
    .line 558
    sget-object v15, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 559
    .line 560
    invoke-virtual {v15, v10}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 561
    .line 562
    .line 563
    move-result-object v17

    .line 564
    sget-object v10, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 565
    .line 566
    invoke-virtual {v10, v4}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 567
    .line 568
    .line 569
    move-result-object v18

    .line 570
    sget-object v4, Ln7/c;->a:Ll2/s1;

    .line 571
    .line 572
    iget-object v10, v12, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 573
    .line 574
    invoke-virtual {v4, v10}, Ll2/s1;->a(Ljava/lang/Object;)Ll2/t1;

    .line 575
    .line 576
    .line 577
    move-result-object v19

    .line 578
    sget-object v4, Lsa/a;->a:Ll2/s1;

    .line 579
    .line 580
    invoke-virtual {v4, v13}, Ll2/s1;->a(Ljava/lang/Object;)Ll2/t1;

    .line 581
    .line 582
    .line 583
    move-result-object v20

    .line 584
    sget-object v4, Lu2/i;->a:Ll2/u2;

    .line 585
    .line 586
    invoke-virtual {v4, v14}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 587
    .line 588
    .line 589
    move-result-object v21

    .line 590
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 591
    .line 592
    invoke-virtual {v0}, Lw3/t;->getView()Landroid/view/View;

    .line 593
    .line 594
    .line 595
    move-result-object v10

    .line 596
    invoke-virtual {v4, v10}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 597
    .line 598
    .line 599
    move-result-object v22

    .line 600
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->d:Ll2/u2;

    .line 601
    .line 602
    invoke-virtual {v4, v7}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 603
    .line 604
    .line 605
    move-result-object v23

    .line 606
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->e:Ll2/u2;

    .line 607
    .line 608
    invoke-virtual {v4, v6}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 609
    .line 610
    .line 611
    move-result-object v24

    .line 612
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 613
    .line 614
    .line 615
    move-result-object v4

    .line 616
    invoke-virtual {v8, v4}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 617
    .line 618
    .line 619
    move-result-object v25

    .line 620
    sget-object v4, Lw3/h1;->l:Ll2/u2;

    .line 621
    .line 622
    invoke-virtual {v4, v5}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 623
    .line 624
    .line 625
    move-result-object v26

    .line 626
    filled-new-array/range {v17 .. v26}, [Ll2/t1;

    .line 627
    .line 628
    .line 629
    move-result-object v4

    .line 630
    new-instance v5, Lf7/f;

    .line 631
    .line 632
    const/4 v6, 0x4

    .line 633
    invoke-direct {v5, v6, v0, v11, v1}, Lf7/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Llx0/e;)V

    .line 634
    .line 635
    .line 636
    const v6, 0x3f2ad1a9

    .line 637
    .line 638
    .line 639
    invoke-static {v6, v3, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 640
    .line 641
    .line 642
    move-result-object v5

    .line 643
    const/16 v6, 0x38

    .line 644
    .line 645
    invoke-static {v4, v5, v3, v6}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 646
    .line 647
    .line 648
    goto :goto_a

    .line 649
    :cond_19
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 650
    .line 651
    const-string v1, "Called when the ViewTreeOwnersAvailability is not yet in Available state"

    .line 652
    .line 653
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 654
    .line 655
    .line 656
    throw v0

    .line 657
    :cond_1a
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 658
    .line 659
    .line 660
    :goto_a
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 661
    .line 662
    .line 663
    move-result-object v3

    .line 664
    if-eqz v3, :cond_1b

    .line 665
    .line 666
    new-instance v4, Lkn/i0;

    .line 667
    .line 668
    const/4 v5, 0x6

    .line 669
    invoke-direct {v4, v2, v5, v0, v1}, Lkn/i0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 670
    .line 671
    .line 672
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 673
    .line 674
    :cond_1b
    return-void
.end method

.method public static final b(Ljava/lang/String;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "CompositionLocal "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, " not present"

    .line 14
    .line 15
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw v0
.end method

.method public static final getLocalLifecycleOwner()Ll2/s1;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ll2/s1;"
        }
    .end annotation

    .line 1
    sget-object v0, Ln7/c;->a:Ll2/s1;

    .line 2
    .line 3
    return-object v0
.end method
