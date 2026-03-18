.class public final Lcq/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lcq/s1;->a:I

    iput-object p2, p0, Lcq/s1;->b:Ljava/lang/Object;

    iput-object p3, p0, Lcq/s1;->c:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lvp/m1;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p3, p0, Lcq/s1;->a:I

    iput-object p2, p0, Lcq/s1;->b:Ljava/lang/Object;

    iput-object p1, p0, Lcq/s1;->c:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lvp/z3;Lvp/f4;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lcq/s1;->a:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lcq/s1;->b:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcq/s1;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lcq/s1;->a:I

    .line 2
    .line 3
    iget-object v1, p0, Lcq/s1;->c:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object p0, p0, Lcq/s1;->b:Ljava/lang/Object;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p0, Lvp/f4;

    .line 11
    .line 12
    iget-object v0, p0, Lvp/f4;->d:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    check-cast v1, Lvp/z3;

    .line 18
    .line 19
    invoke-virtual {v1, v0}, Lvp/z3;->a(Ljava/lang/String;)Lvp/s1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sget-object v2, Lvp/r1;->f:Lvp/r1;

    .line 24
    .line 25
    invoke-virtual {v0, v2}, Lvp/s1;->i(Lvp/r1;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    iget-object v0, p0, Lvp/f4;->v:Ljava/lang/String;

    .line 32
    .line 33
    const/16 v3, 0x64

    .line 34
    .line 35
    invoke-static {v3, v0}, Lvp/s1;->c(ILjava/lang/String;)Lvp/s1;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {v0, v2}, Lvp/s1;->i(Lvp/r1;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_0

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {v1, p0}, Lvp/z3;->b0(Lvp/f4;)Lvp/t0;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {p0}, Lvp/t0;->E()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    :goto_0
    invoke-virtual {v1}, Lvp/z3;->d()Lvp/p0;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 60
    .line 61
    const-string v0, "Analytics storage consent denied. Returning null app instance id"

    .line 62
    .line 63
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    const/4 p0, 0x0

    .line 67
    :goto_1
    return-object p0

    .line 68
    :pswitch_0
    check-cast v1, Lvp/m1;

    .line 69
    .line 70
    iget-object v0, v1, Lvp/m1;->c:Lvp/z3;

    .line 71
    .line 72
    invoke-virtual {v0}, Lvp/z3;->B()V

    .line 73
    .line 74
    .line 75
    check-cast p0, Lvp/f4;

    .line 76
    .line 77
    new-instance v0, Lvp/j;

    .line 78
    .line 79
    iget-object v1, v1, Lvp/m1;->c:Lvp/z3;

    .line 80
    .line 81
    iget-object p0, p0, Lvp/f4;->d:Ljava/lang/String;

    .line 82
    .line 83
    invoke-virtual {v1, p0}, Lvp/z3;->o0(Ljava/lang/String;)Landroid/os/Bundle;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-direct {v0, p0}, Lvp/j;-><init>(Landroid/os/Bundle;)V

    .line 88
    .line 89
    .line 90
    return-object v0

    .line 91
    :pswitch_1
    check-cast v1, Lvp/m1;

    .line 92
    .line 93
    iget-object v0, v1, Lvp/m1;->c:Lvp/z3;

    .line 94
    .line 95
    invoke-virtual {v0}, Lvp/z3;->B()V

    .line 96
    .line 97
    .line 98
    iget-object v0, v1, Lvp/m1;->c:Lvp/z3;

    .line 99
    .line 100
    iget-object v0, v0, Lvp/z3;->f:Lvp/n;

    .line 101
    .line 102
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 103
    .line 104
    .line 105
    check-cast p0, Ljava/lang/String;

    .line 106
    .line 107
    invoke-virtual {v0, p0}, Lvp/n;->V0(Ljava/lang/String;)Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :pswitch_2
    check-cast v1, Lvy0/l;

    .line 113
    .line 114
    check-cast p0, La4/b;

    .line 115
    .line 116
    :try_start_0
    invoke-virtual {p0}, La4/b;->invoke()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 120
    goto :goto_2

    .line 121
    :catchall_0
    move-exception p0

    .line 122
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    if-eqz v0, :cond_2

    .line 131
    .line 132
    invoke-virtual {v1}, Lvy0/l;->v()Z

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    if-eqz v2, :cond_2

    .line 137
    .line 138
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-virtual {v1, v0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    :cond_2
    instance-of v0, p0, Llx0/n;

    .line 146
    .line 147
    if-nez v0, :cond_3

    .line 148
    .line 149
    invoke-virtual {v1}, Lvy0/l;->v()Z

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    if-eqz v0, :cond_3

    .line 154
    .line 155
    invoke-virtual {v1, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_3
    new-instance v0, Llx0/o;

    .line 159
    .line 160
    invoke-direct {v0, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    return-object v0

    .line 164
    :pswitch_3
    check-cast p0, Lnv/b;

    .line 165
    .line 166
    check-cast v1, Lmv/a;

    .line 167
    .line 168
    const-class v0, Ljava/lang/Throwable;

    .line 169
    .line 170
    sget-object v2, Lkp/ha;->i:Ljava/util/HashMap;

    .line 171
    .line 172
    invoke-static {}, Lkp/pa;->b()V

    .line 173
    .line 174
    .line 175
    sget v2, Lkp/oa;->a:I

    .line 176
    .line 177
    invoke-static {}, Lkp/pa;->b()V

    .line 178
    .line 179
    .line 180
    const-string v2, ""

    .line 181
    .line 182
    invoke-static {v2}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    if-nez v2, :cond_4

    .line 187
    .line 188
    sget-object v2, Lkp/ga;->j:Lkp/ga;

    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_4
    sget-object v2, Lkp/ha;->i:Ljava/util/HashMap;

    .line 192
    .line 193
    const-string v3, "detectorTaskWithResource#run"

    .line 194
    .line 195
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    if-nez v4, :cond_5

    .line 200
    .line 201
    new-instance v4, Lkp/ha;

    .line 202
    .line 203
    invoke-direct {v4, v3}, Lkp/ha;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v2, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    :cond_5
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v2

    .line 213
    check-cast v2, Lkp/ha;

    .line 214
    .line 215
    :goto_3
    invoke-virtual {v2}, Lkp/ha;->a()V

    .line 216
    .line 217
    .line 218
    :try_start_1
    iget-object p0, p0, Lnv/b;->e:Leb/j0;

    .line 219
    .line 220
    invoke-virtual {p0, v1}, Leb/j0;->E(Lmv/a;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 224
    invoke-virtual {v2}, Lkp/ha;->close()V

    .line 225
    .line 226
    .line 227
    return-object p0

    .line 228
    :catchall_1
    move-exception p0

    .line 229
    :try_start_2
    invoke-virtual {v2}, Lkp/ha;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 230
    .line 231
    .line 232
    goto :goto_4

    .line 233
    :catchall_2
    move-exception v1

    .line 234
    :try_start_3
    const-string v2, "addSuppressed"

    .line 235
    .line 236
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    move-result-object v3

    .line 240
    invoke-virtual {v0, v2, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v1

    .line 248
    invoke-virtual {v0, p0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 249
    .line 250
    .line 251
    :catch_0
    :goto_4
    throw p0

    .line 252
    :pswitch_4
    check-cast p0, Landroid/os/ParcelFileDescriptor;

    .line 253
    .line 254
    const-string v0, "processAssets: closing: "

    .line 255
    .line 256
    const-string v2, "processAssets: writing data failed: "

    .line 257
    .line 258
    const-string v3, "processAssets: wrote data: "

    .line 259
    .line 260
    const-string v4, "WearableClient"

    .line 261
    .line 262
    const/4 v5, 0x3

    .line 263
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 264
    .line 265
    .line 266
    move-result v6

    .line 267
    if-eqz v6, :cond_6

    .line 268
    .line 269
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 270
    .line 271
    .line 272
    move-result-object v6

    .line 273
    const-string v7, "processAssets: writing data to FD : "

    .line 274
    .line 275
    invoke-virtual {v7, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v6

    .line 279
    invoke-static {v4, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 280
    .line 281
    .line 282
    :cond_6
    new-instance v6, Landroid/os/ParcelFileDescriptor$AutoCloseOutputStream;

    .line 283
    .line 284
    invoke-direct {v6, p0}, Landroid/os/ParcelFileDescriptor$AutoCloseOutputStream;-><init>(Landroid/os/ParcelFileDescriptor;)V

    .line 285
    .line 286
    .line 287
    :try_start_4
    check-cast v1, [B

    .line 288
    .line 289
    invoke-virtual {v6, v1}, Ljava/io/OutputStream;->write([B)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {v6}, Ljava/io/OutputStream;->flush()V

    .line 293
    .line 294
    .line 295
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    if-eqz v1, :cond_7

    .line 300
    .line 301
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-static {v4, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 310
    .line 311
    .line 312
    goto :goto_5

    .line 313
    :catchall_3
    move-exception v1

    .line 314
    goto :goto_7

    .line 315
    :cond_7
    :goto_5
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 316
    .line 317
    :try_start_5
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 318
    .line 319
    .line 320
    move-result v2

    .line 321
    if-eqz v2, :cond_8

    .line 322
    .line 323
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object p0

    .line 327
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object p0

    .line 331
    invoke-static {v4, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 332
    .line 333
    .line 334
    :cond_8
    invoke-virtual {v6}, Landroid/os/ParcelFileDescriptor$AutoCloseOutputStream;->close()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_3

    .line 335
    .line 336
    .line 337
    goto :goto_6

    .line 338
    :catch_1
    :try_start_6
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v1

    .line 342
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v1

    .line 346
    invoke-static {v4, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 347
    .line 348
    .line 349
    :try_start_7
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 350
    .line 351
    .line 352
    move-result v1

    .line 353
    if-eqz v1, :cond_9

    .line 354
    .line 355
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object p0

    .line 359
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    invoke-static {v4, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 364
    .line 365
    .line 366
    :cond_9
    invoke-virtual {v6}, Landroid/os/ParcelFileDescriptor$AutoCloseOutputStream;->close()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_2

    .line 367
    .line 368
    .line 369
    :catch_2
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 370
    .line 371
    :catch_3
    :goto_6
    return-object v1

    .line 372
    :goto_7
    :try_start_8
    invoke-static {v4, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    if-eqz v2, :cond_a

    .line 377
    .line 378
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object p0

    .line 382
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object p0

    .line 386
    invoke-static {v4, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 387
    .line 388
    .line 389
    :cond_a
    invoke-virtual {v6}, Landroid/os/ParcelFileDescriptor$AutoCloseOutputStream;->close()V
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_4

    .line 390
    .line 391
    .line 392
    :catch_4
    throw v1

    .line 393
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
