.class public final synthetic La0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(La8/q0;La8/l1;)V
    .locals 0

    .line 1
    const/4 p1, 0x4

    iput p1, p0, La0/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, La0/d;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, La0/d;->d:I

    iput-object p1, p0, La0/d;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final a()V
    .locals 5

    .line 1
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lf8/h;

    .line 4
    .line 5
    iget-object v0, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    iget-boolean v1, p0, Lf8/h;->m:Z

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-wide v1, p0, Lf8/h;->l:J

    .line 17
    .line 18
    const-wide/16 v3, 0x1

    .line 19
    .line 20
    sub-long/2addr v1, v3

    .line 21
    iput-wide v1, p0, Lf8/h;->l:J

    .line 22
    .line 23
    const-wide/16 v3, 0x0

    .line 24
    .line 25
    cmp-long v1, v1, v3

    .line 26
    .line 27
    if-lez v1, :cond_1

    .line 28
    .line 29
    monitor-exit v0

    .line 30
    return-void

    .line 31
    :cond_1
    if-gez v1, :cond_2

    .line 32
    .line 33
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-direct {v1}, Ljava/lang/IllegalStateException;-><init>()V

    .line 36
    .line 37
    .line 38
    iget-object v2, p0, Lf8/h;->a:Ljava/lang/Object;

    .line 39
    .line 40
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    :try_start_1
    iput-object v1, p0, Lf8/h;->n:Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 44
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 45
    return-void

    .line 46
    :catchall_1
    move-exception p0

    .line 47
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 48
    :try_start_4
    throw p0

    .line 49
    :cond_2
    invoke-virtual {p0}, Lf8/h;->a()V

    .line 50
    .line 51
    .line 52
    monitor-exit v0

    .line 53
    return-void

    .line 54
    :goto_0
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 55
    throw p0
.end method


# virtual methods
.method public final run()V
    .locals 12

    .line 1
    iget v0, p0, La0/d;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x1

    .line 6
    const/4 v4, 0x0

    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lm8/c;

    .line 13
    .line 14
    iget-object p0, p0, Lm8/c;->g:Lm8/g0;

    .line 15
    .line 16
    invoke-interface {p0}, Lm8/g0;->d()V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ll4/y;

    .line 23
    .line 24
    iget-object v0, p0, Ll4/y;->b:Lil/g;

    .line 25
    .line 26
    iput-object v4, p0, Ll4/y;->n:La0/d;

    .line 27
    .line 28
    iget-object v5, p0, Ll4/y;->m:Ln2/b;

    .line 29
    .line 30
    iget-object p0, p0, Ll4/y;->a:Landroid/view/View;

    .line 31
    .line 32
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    if-nez v6, :cond_0

    .line 37
    .line 38
    invoke-virtual {p0}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-eqz p0, :cond_0

    .line 47
    .line 48
    invoke-virtual {p0}, Landroid/view/View;->onCheckIsTextEditor()Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-ne p0, v3, :cond_0

    .line 53
    .line 54
    invoke-virtual {v5}, Ln2/b;->i()V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_6

    .line 58
    .line 59
    :cond_0
    iget-object p0, v5, Ln2/b;->d:[Ljava/lang/Object;

    .line 60
    .line 61
    iget v6, v5, Ln2/b;->f:I

    .line 62
    .line 63
    move v8, v2

    .line 64
    move-object v7, v4

    .line 65
    :goto_0
    if-ge v8, v6, :cond_7

    .line 66
    .line 67
    aget-object v9, p0, v8

    .line 68
    .line 69
    check-cast v9, Ll4/x;

    .line 70
    .line 71
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 72
    .line 73
    .line 74
    move-result v10

    .line 75
    if-eqz v10, :cond_5

    .line 76
    .line 77
    if-eq v10, v3, :cond_4

    .line 78
    .line 79
    const/4 v11, 0x2

    .line 80
    if-eq v10, v11, :cond_2

    .line 81
    .line 82
    if-ne v10, v1, :cond_1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_1
    new-instance p0, La8/r0;

    .line 86
    .line 87
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_2
    :goto_1
    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 92
    .line 93
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v10

    .line 97
    if-nez v10, :cond_6

    .line 98
    .line 99
    sget-object v7, Ll4/x;->f:Ll4/x;

    .line 100
    .line 101
    if-ne v9, v7, :cond_3

    .line 102
    .line 103
    move v7, v3

    .line 104
    goto :goto_2

    .line 105
    :cond_3
    move v7, v2

    .line 106
    :goto_2
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    goto :goto_4

    .line 111
    :cond_4
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 112
    .line 113
    :goto_3
    move-object v7, v4

    .line 114
    goto :goto_4

    .line 115
    :cond_5
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_6
    :goto_4
    add-int/lit8 v8, v8, 0x1

    .line 119
    .line 120
    goto :goto_0

    .line 121
    :cond_7
    invoke-virtual {v5}, Ln2/b;->i()V

    .line 122
    .line 123
    .line 124
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    if-eqz p0, :cond_8

    .line 131
    .line 132
    iget-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 133
    .line 134
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    check-cast p0, Landroid/view/inputmethod/InputMethodManager;

    .line 139
    .line 140
    iget-object v1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v1, Landroid/view/View;

    .line 143
    .line 144
    invoke-virtual {p0, v1}, Landroid/view/inputmethod/InputMethodManager;->restartInput(Landroid/view/View;)V

    .line 145
    .line 146
    .line 147
    :cond_8
    if-eqz v7, :cond_a

    .line 148
    .line 149
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 150
    .line 151
    .line 152
    move-result p0

    .line 153
    if-eqz p0, :cond_9

    .line 154
    .line 155
    iget-object p0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast p0, Laq/a;

    .line 158
    .line 159
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast p0, Ld6/y;

    .line 162
    .line 163
    invoke-virtual {p0}, Ld6/y;->b()V

    .line 164
    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_9
    iget-object p0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast p0, Laq/a;

    .line 170
    .line 171
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast p0, Ld6/y;

    .line 174
    .line 175
    invoke-virtual {p0}, Ld6/y;->a()V

    .line 176
    .line 177
    .line 178
    :cond_a
    :goto_5
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 179
    .line 180
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result p0

    .line 184
    if-eqz p0, :cond_b

    .line 185
    .line 186
    iget-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 187
    .line 188
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    check-cast p0, Landroid/view/inputmethod/InputMethodManager;

    .line 193
    .line 194
    iget-object v0, v0, Lil/g;->e:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast v0, Landroid/view/View;

    .line 197
    .line 198
    invoke-virtual {p0, v0}, Landroid/view/inputmethod/InputMethodManager;->restartInput(Landroid/view/View;)V

    .line 199
    .line 200
    .line 201
    :cond_b
    :goto_6
    return-void

    .line 202
    :pswitch_1
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast p0, Lcom/google/android/material/carousel/CarouselLayoutManager;

    .line 205
    .line 206
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 207
    .line 208
    .line 209
    return-void

    .line 210
    :pswitch_2
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast p0, Ljava/util/concurrent/ScheduledFuture;

    .line 213
    .line 214
    invoke-interface {p0, v3}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 215
    .line 216
    .line 217
    return-void

    .line 218
    :pswitch_3
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast p0, Ly4/h;

    .line 221
    .line 222
    invoke-virtual {p0, v4}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    return-void

    .line 226
    :pswitch_4
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p0, Lcom/google/android/material/button/MaterialButton;

    .line 229
    .line 230
    invoke-static {p0}, Lcom/google/android/material/button/MaterialButton;->a(Lcom/google/android/material/button/MaterialButton;)V

    .line 231
    .line 232
    .line 233
    return-void

    .line 234
    :pswitch_5
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 237
    .line 238
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 239
    .line 240
    .line 241
    return-void

    .line 242
    :pswitch_6
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast p0, Ly4/k;

    .line 245
    .line 246
    invoke-virtual {p0, v3}, Ly4/k;->cancel(Z)Z

    .line 247
    .line 248
    .line 249
    return-void

    .line 250
    :pswitch_7
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast p0, Lt1/j0;

    .line 253
    .line 254
    iget-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v0, Lu/y;

    .line 257
    .line 258
    iget v0, v0, Lu/y;->O:I

    .line 259
    .line 260
    const/16 v1, 0xa

    .line 261
    .line 262
    if-ne v0, v1, :cond_c

    .line 263
    .line 264
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 265
    .line 266
    check-cast p0, Lu/y;

    .line 267
    .line 268
    invoke-virtual {p0}, Lu/y;->E()V

    .line 269
    .line 270
    .line 271
    :cond_c
    return-void

    .line 272
    :pswitch_8
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast p0, Lu/u;

    .line 275
    .line 276
    iget-object v0, p0, Lu/u;->c:Lu/y;

    .line 277
    .line 278
    iget v0, v0, Lu/y;->O:I

    .line 279
    .line 280
    const/4 v1, 0x4

    .line 281
    if-eq v0, v1, :cond_d

    .line 282
    .line 283
    iget-object v0, p0, Lu/u;->c:Lu/y;

    .line 284
    .line 285
    iget v0, v0, Lu/y;->O:I

    .line 286
    .line 287
    const/4 v1, 0x5

    .line 288
    if-ne v0, v1, :cond_e

    .line 289
    .line 290
    :cond_d
    iget-object p0, p0, Lu/u;->c:Lu/y;

    .line 291
    .line 292
    invoke-virtual {p0, v2}, Lu/y;->L(Z)V

    .line 293
    .line 294
    .line 295
    :cond_e
    return-void

    .line 296
    :pswitch_9
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast p0, Lg2/e;

    .line 299
    .line 300
    invoke-static {p0}, Lg2/e;->a(Lg2/e;)V

    .line 301
    .line 302
    .line 303
    return-void

    .line 304
    :pswitch_a
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast p0, Lg0/e;

    .line 307
    .line 308
    invoke-virtual {p0}, Lg0/e;->c()V

    .line 309
    .line 310
    .line 311
    return-void

    .line 312
    :pswitch_b
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 313
    .line 314
    check-cast p0, Lb0/e1;

    .line 315
    .line 316
    iget-object p0, p0, Lb0/e1;->b:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast p0, Lgw0/c;

    .line 319
    .line 320
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 321
    .line 322
    .line 323
    return-void

    .line 324
    :pswitch_c
    invoke-direct {p0}, La0/d;->a()V

    .line 325
    .line 326
    .line 327
    return-void

    .line 328
    :pswitch_d
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast p0, Lvy0/i1;

    .line 331
    .line 332
    if-eqz p0, :cond_f

    .line 333
    .line 334
    invoke-interface {p0, v4}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 335
    .line 336
    .line 337
    :cond_f
    return-void

    .line 338
    :pswitch_e
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast p0, Lcom/google/firebase/messaging/i0;

    .line 341
    .line 342
    const-string v0, "FirebaseMessaging"

    .line 343
    .line 344
    new-instance v1, Ljava/lang/StringBuilder;

    .line 345
    .line 346
    const-string v2, "Service took too long to process intent: "

    .line 347
    .line 348
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    iget-object v2, p0, Lcom/google/firebase/messaging/i0;->a:Landroid/content/Intent;

    .line 352
    .line 353
    invoke-virtual {v2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 354
    .line 355
    .line 356
    move-result-object v2

    .line 357
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 358
    .line 359
    .line 360
    const-string v2, " finishing."

    .line 361
    .line 362
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 363
    .line 364
    .line 365
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    invoke-static {v0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 370
    .line 371
    .line 372
    iget-object p0, p0, Lcom/google/firebase/messaging/i0;->b:Laq/k;

    .line 373
    .line 374
    invoke-virtual {p0, v4}, Laq/k;->d(Ljava/lang/Object;)V

    .line 375
    .line 376
    .line 377
    return-void

    .line 378
    :pswitch_f
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 379
    .line 380
    check-cast p0, Landroidx/lifecycle/c1;

    .line 381
    .line 382
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 383
    .line 384
    check-cast v0, Ljava/util/ArrayDeque;

    .line 385
    .line 386
    monitor-enter v0

    .line 387
    :try_start_0
    iget-object v1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 388
    .line 389
    check-cast v1, Landroid/content/SharedPreferences;

    .line 390
    .line 391
    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 392
    .line 393
    .line 394
    move-result-object v1

    .line 395
    iget-object v2, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 396
    .line 397
    check-cast v2, Ljava/lang/String;

    .line 398
    .line 399
    new-instance v3, Ljava/lang/StringBuilder;

    .line 400
    .line 401
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 402
    .line 403
    .line 404
    iget-object v4, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 405
    .line 406
    check-cast v4, Ljava/util/ArrayDeque;

    .line 407
    .line 408
    invoke-virtual {v4}, Ljava/util/ArrayDeque;->iterator()Ljava/util/Iterator;

    .line 409
    .line 410
    .line 411
    move-result-object v4

    .line 412
    :goto_7
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 413
    .line 414
    .line 415
    move-result v5

    .line 416
    if-eqz v5, :cond_10

    .line 417
    .line 418
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v5

    .line 422
    check-cast v5, Ljava/lang/String;

    .line 423
    .line 424
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 425
    .line 426
    .line 427
    iget-object v5, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 428
    .line 429
    check-cast v5, Ljava/lang/String;

    .line 430
    .line 431
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 432
    .line 433
    .line 434
    goto :goto_7

    .line 435
    :cond_10
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 436
    .line 437
    .line 438
    move-result-object p0

    .line 439
    invoke-interface {v1, v2, p0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 440
    .line 441
    .line 442
    move-result-object p0

    .line 443
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->commit()Z

    .line 444
    .line 445
    .line 446
    monitor-exit v0

    .line 447
    return-void

    .line 448
    :catchall_0
    move-exception p0

    .line 449
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 450
    throw p0

    .line 451
    :pswitch_10
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 452
    .line 453
    check-cast p0, Lc8/y;

    .line 454
    .line 455
    iget-wide v0, p0, Lc8/y;->h0:J

    .line 456
    .line 457
    const-wide/32 v4, 0x493e0

    .line 458
    .line 459
    .line 460
    cmp-long v0, v0, v4

    .line 461
    .line 462
    if-ltz v0, :cond_11

    .line 463
    .line 464
    iget-object v0, p0, Lc8/y;->s:Laq/a;

    .line 465
    .line 466
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 467
    .line 468
    check-cast v0, Lc8/a0;

    .line 469
    .line 470
    iput-boolean v3, v0, Lc8/a0;->a2:Z

    .line 471
    .line 472
    const-wide/16 v0, 0x0

    .line 473
    .line 474
    iput-wide v0, p0, Lc8/y;->h0:J

    .line 475
    .line 476
    :cond_11
    return-void

    .line 477
    :pswitch_11
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 478
    .line 479
    check-cast p0, Lb8/e;

    .line 480
    .line 481
    invoke-virtual {p0}, Lb8/e;->H()Lb8/a;

    .line 482
    .line 483
    .line 484
    move-result-object v0

    .line 485
    new-instance v1, La6/a;

    .line 486
    .line 487
    const/16 v2, 0x1b

    .line 488
    .line 489
    invoke-direct {v1, v2}, La6/a;-><init>(I)V

    .line 490
    .line 491
    .line 492
    const/16 v2, 0x404

    .line 493
    .line 494
    invoke-virtual {p0, v0, v2, v1}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 495
    .line 496
    .line 497
    iget-object p0, p0, Lb8/e;->i:Le30/v;

    .line 498
    .line 499
    invoke-virtual {p0}, Le30/v;->d()V

    .line 500
    .line 501
    .line 502
    return-void

    .line 503
    :pswitch_12
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 504
    .line 505
    check-cast p0, Lb0/k1;

    .line 506
    .line 507
    invoke-virtual {p0}, Lb0/z1;->p()V

    .line 508
    .line 509
    .line 510
    return-void

    .line 511
    :pswitch_13
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 512
    .line 513
    check-cast p0, Lb0/p0;

    .line 514
    .line 515
    iget-object v0, p0, Lb0/p0;->z:Ljava/lang/Object;

    .line 516
    .line 517
    monitor-enter v0

    .line 518
    :try_start_1
    iput-object v4, p0, Lb0/p0;->B:Lb0/o0;

    .line 519
    .line 520
    iget-object v1, p0, Lb0/p0;->A:Lb0/a1;

    .line 521
    .line 522
    if-eqz v1, :cond_12

    .line 523
    .line 524
    iput-object v4, p0, Lb0/p0;->A:Lb0/a1;

    .line 525
    .line 526
    invoke-virtual {p0, v1}, Lb0/p0;->f(Lb0/a1;)V

    .line 527
    .line 528
    .line 529
    goto :goto_8

    .line 530
    :catchall_1
    move-exception p0

    .line 531
    goto :goto_9

    .line 532
    :cond_12
    :goto_8
    monitor-exit v0

    .line 533
    return-void

    .line 534
    :goto_9
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 535
    throw p0

    .line 536
    :pswitch_14
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast p0, Ljava/lang/Runnable;

    .line 539
    .line 540
    const/4 v0, -0x3

    .line 541
    invoke-static {v0}, Landroid/os/Process;->setThreadPriority(I)V

    .line 542
    .line 543
    .line 544
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 545
    .line 546
    .line 547
    return-void

    .line 548
    :pswitch_15
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 549
    .line 550
    check-cast p0, Lb/t;

    .line 551
    .line 552
    invoke-static {p0}, Lb/t;->a(Lb/t;)V

    .line 553
    .line 554
    .line 555
    return-void

    .line 556
    :pswitch_16
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 557
    .line 558
    check-cast p0, Lb/o;

    .line 559
    .line 560
    iget-object v0, p0, Lb/o;->e:Ljava/lang/Runnable;

    .line 561
    .line 562
    if-eqz v0, :cond_13

    .line 563
    .line 564
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V

    .line 565
    .line 566
    .line 567
    iput-object v4, p0, Lb/o;->e:Ljava/lang/Runnable;

    .line 568
    .line 569
    :cond_13
    return-void

    .line 570
    :pswitch_17
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 571
    .line 572
    check-cast p0, Landroidx/lifecycle/m0;

    .line 573
    .line 574
    iget-object v0, p0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 575
    .line 576
    iget v1, p0, Landroidx/lifecycle/m0;->e:I

    .line 577
    .line 578
    if-nez v1, :cond_14

    .line 579
    .line 580
    iput-boolean v3, p0, Landroidx/lifecycle/m0;->f:Z

    .line 581
    .line 582
    sget-object v1, Landroidx/lifecycle/p;->ON_PAUSE:Landroidx/lifecycle/p;

    .line 583
    .line 584
    invoke-virtual {v0, v1}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 585
    .line 586
    .line 587
    :cond_14
    iget v1, p0, Landroidx/lifecycle/m0;->d:I

    .line 588
    .line 589
    if-nez v1, :cond_15

    .line 590
    .line 591
    iget-boolean v1, p0, Landroidx/lifecycle/m0;->f:Z

    .line 592
    .line 593
    if-eqz v1, :cond_15

    .line 594
    .line 595
    sget-object v1, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 596
    .line 597
    invoke-virtual {v0, v1}, Landroidx/lifecycle/z;->g(Landroidx/lifecycle/p;)V

    .line 598
    .line 599
    .line 600
    iput-boolean v3, p0, Landroidx/lifecycle/m0;->g:Z

    .line 601
    .line 602
    :cond_15
    return-void

    .line 603
    :pswitch_18
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 604
    .line 605
    check-cast p0, La8/l1;

    .line 606
    .line 607
    :try_start_2
    monitor-enter p0

    .line 608
    monitor-exit p0
    :try_end_2
    .catch La8/o; {:try_start_2 .. :try_end_2} :catch_0

    .line 609
    :try_start_3
    iget-object v0, p0, La8/l1;->a:La8/k1;

    .line 610
    .line 611
    iget v1, p0, La8/l1;->c:I

    .line 612
    .line 613
    iget-object v2, p0, La8/l1;->d:Ljava/lang/Object;

    .line 614
    .line 615
    invoke-interface {v0, v1, v2}, La8/k1;->a(ILjava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 616
    .line 617
    .line 618
    :try_start_4
    invoke-virtual {p0, v3}, La8/l1;->a(Z)V

    .line 619
    .line 620
    .line 621
    return-void

    .line 622
    :catchall_2
    move-exception v0

    .line 623
    invoke-virtual {p0, v3}, La8/l1;->a(Z)V

    .line 624
    .line 625
    .line 626
    throw v0
    :try_end_4
    .catch La8/o; {:try_start_4 .. :try_end_4} :catch_0

    .line 627
    :catch_0
    move-exception p0

    .line 628
    const-string v0, "ExoPlayerImplInternal"

    .line 629
    .line 630
    const-string v1, "Unexpected error delivering message on external thread."

    .line 631
    .line 632
    invoke-static {v0, v1, p0}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 633
    .line 634
    .line 635
    new-instance v0, Ljava/lang/RuntimeException;

    .line 636
    .line 637
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 638
    .line 639
    .line 640
    throw v0

    .line 641
    :pswitch_19
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 642
    .line 643
    check-cast p0, La8/i0;

    .line 644
    .line 645
    iget-object v0, p0, La8/i0;->J:Lca/j;

    .line 646
    .line 647
    iget-object p0, p0, La8/i0;->i:Landroid/content/Context;

    .line 648
    .line 649
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 650
    .line 651
    invoke-static {p0}, Lu7/b;->a(Landroid/content/Context;)Landroid/media/AudioManager;

    .line 652
    .line 653
    .line 654
    move-result-object p0

    .line 655
    invoke-virtual {p0}, Landroid/media/AudioManager;->generateAudioSessionId()I

    .line 656
    .line 657
    .line 658
    move-result p0

    .line 659
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 660
    .line 661
    .line 662
    move-result-object p0

    .line 663
    iput-object p0, v0, Lca/j;->f:Ljava/lang/Object;

    .line 664
    .line 665
    new-instance v1, Lw7/b;

    .line 666
    .line 667
    invoke-direct {v1, v0, p0, v2}, Lw7/b;-><init>(Lca/j;Ljava/lang/Object;I)V

    .line 668
    .line 669
    .line 670
    iget-object p0, v0, Lca/j;->c:Ljava/lang/Object;

    .line 671
    .line 672
    check-cast p0, Lw7/t;

    .line 673
    .line 674
    iget-object v0, p0, Lw7/t;->a:Landroid/os/Handler;

    .line 675
    .line 676
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 677
    .line 678
    .line 679
    move-result-object v0

    .line 680
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 681
    .line 682
    .line 683
    move-result-object v0

    .line 684
    invoke-virtual {v0}, Ljava/lang/Thread;->isAlive()Z

    .line 685
    .line 686
    .line 687
    move-result v0

    .line 688
    if-nez v0, :cond_16

    .line 689
    .line 690
    goto :goto_a

    .line 691
    :cond_16
    invoke-virtual {p0, v1}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 692
    .line 693
    .line 694
    :goto_a
    return-void

    .line 695
    :pswitch_1a
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 696
    .line 697
    check-cast p0, La8/a;

    .line 698
    .line 699
    iget-object v0, p0, La8/a;->c:La8/b;

    .line 700
    .line 701
    iget-boolean v0, v0, La8/b;->e:Z

    .line 702
    .line 703
    if-eqz v0, :cond_17

    .line 704
    .line 705
    iget-object p0, p0, La8/a;->a:La8/f0;

    .line 706
    .line 707
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 708
    .line 709
    invoke-virtual {p0, v1, v2}, La8/i0;->I0(IZ)V

    .line 710
    .line 711
    .line 712
    :cond_17
    return-void

    .line 713
    :pswitch_1b
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 714
    .line 715
    check-cast p0, La8/b;

    .line 716
    .line 717
    iget-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 718
    .line 719
    check-cast v0, Landroid/content/Context;

    .line 720
    .line 721
    iget-object p0, p0, La8/b;->g:Ljava/lang/Object;

    .line 722
    .line 723
    check-cast p0, La8/a;

    .line 724
    .line 725
    invoke-virtual {v0, p0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 726
    .line 727
    .line 728
    return-void

    .line 729
    :pswitch_1c
    iget-object p0, p0, La0/d;->e:Ljava/lang/Object;

    .line 730
    .line 731
    check-cast p0, La0/e;

    .line 732
    .line 733
    iget-object v0, p0, La0/e;->g:Ly4/h;

    .line 734
    .line 735
    if-eqz v0, :cond_18

    .line 736
    .line 737
    invoke-virtual {v0, v4}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 738
    .line 739
    .line 740
    iput-object v4, p0, La0/e;->g:Ly4/h;

    .line 741
    .line 742
    :cond_18
    return-void

    .line 743
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
