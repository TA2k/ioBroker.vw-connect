.class public final Lo10/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lo10/l;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lo10/l;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lo10/l;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lo10/l;

    .line 7
    .line 8
    iget-object v0, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v0

    .line 11
    check-cast v2, Lzp0/e;

    .line 12
    .line 13
    iget-object v0, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v0

    .line 16
    check-cast v4, Ljava/lang/String;

    .line 17
    .line 18
    const/16 v6, 0x13

    .line 19
    .line 20
    iget-object v3, p0, Lo10/l;->g:Ljava/lang/String;

    .line 21
    .line 22
    move-object v5, p1

    .line 23
    invoke-direct/range {v1 .. v6}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    return-object v1

    .line 27
    :pswitch_0
    move-object v6, p1

    .line 28
    new-instance v2, Lo10/l;

    .line 29
    .line 30
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v3, p1

    .line 33
    check-cast v3, Ly80/b;

    .line 34
    .line 35
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 36
    .line 37
    move-object v5, p1

    .line 38
    check-cast v5, Lgg0/a;

    .line 39
    .line 40
    const/16 v7, 0x12

    .line 41
    .line 42
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 43
    .line 44
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    return-object v2

    .line 48
    :pswitch_1
    move-object v6, p1

    .line 49
    new-instance v2, Lo10/l;

    .line 50
    .line 51
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 52
    .line 53
    move-object v3, p1

    .line 54
    check-cast v3, Lx90/b;

    .line 55
    .line 56
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v5, p1

    .line 59
    check-cast v5, Ljava/lang/String;

    .line 60
    .line 61
    const/16 v7, 0x11

    .line 62
    .line 63
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 64
    .line 65
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object v2

    .line 69
    :pswitch_2
    move-object v6, p1

    .line 70
    new-instance v2, Lo10/l;

    .line 71
    .line 72
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 73
    .line 74
    move-object v3, p1

    .line 75
    check-cast v3, Lwo0/f;

    .line 76
    .line 77
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v5, p1

    .line 80
    check-cast v5, Lcz/myskoda/api/bff/v1/NotificationSubscriptionDto;

    .line 81
    .line 82
    const/16 v7, 0x10

    .line 83
    .line 84
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 85
    .line 86
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 87
    .line 88
    .line 89
    return-object v2

    .line 90
    :pswitch_3
    move-object v6, p1

    .line 91
    new-instance v2, Lo10/l;

    .line 92
    .line 93
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 94
    .line 95
    move-object v3, p1

    .line 96
    check-cast v3, Lwo0/e;

    .line 97
    .line 98
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 99
    .line 100
    move-object v5, p1

    .line 101
    check-cast v5, Ljava/lang/String;

    .line 102
    .line 103
    const/16 v7, 0xf

    .line 104
    .line 105
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 106
    .line 107
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 108
    .line 109
    .line 110
    return-object v2

    .line 111
    :pswitch_4
    move-object v6, p1

    .line 112
    new-instance v2, Lo10/l;

    .line 113
    .line 114
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 115
    .line 116
    move-object v3, p1

    .line 117
    check-cast v3, Lus0/b;

    .line 118
    .line 119
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 120
    .line 121
    move-object v5, p1

    .line 122
    check-cast v5, Ljava/lang/String;

    .line 123
    .line 124
    const/16 v7, 0xe

    .line 125
    .line 126
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 127
    .line 128
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 129
    .line 130
    .line 131
    return-object v2

    .line 132
    :pswitch_5
    move-object v6, p1

    .line 133
    new-instance v2, Lo10/l;

    .line 134
    .line 135
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 136
    .line 137
    move-object v3, p1

    .line 138
    check-cast v3, Lu70/c;

    .line 139
    .line 140
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 141
    .line 142
    move-object v5, p1

    .line 143
    check-cast v5, Lcq0/i;

    .line 144
    .line 145
    const/16 v7, 0xd

    .line 146
    .line 147
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 148
    .line 149
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 150
    .line 151
    .line 152
    return-object v2

    .line 153
    :pswitch_6
    move-object v6, p1

    .line 154
    new-instance v2, Lo10/l;

    .line 155
    .line 156
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 157
    .line 158
    move-object v3, p1

    .line 159
    check-cast v3, Lu70/c;

    .line 160
    .line 161
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 162
    .line 163
    move-object v5, p1

    .line 164
    check-cast v5, Lgg0/a;

    .line 165
    .line 166
    const/16 v7, 0xc

    .line 167
    .line 168
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 169
    .line 170
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 171
    .line 172
    .line 173
    return-object v2

    .line 174
    :pswitch_7
    move-object v6, p1

    .line 175
    new-instance v2, Lo10/l;

    .line 176
    .line 177
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 178
    .line 179
    move-object v3, p1

    .line 180
    check-cast v3, Ltq0/k;

    .line 181
    .line 182
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 183
    .line 184
    move-object v5, p1

    .line 185
    check-cast v5, Ljava/lang/String;

    .line 186
    .line 187
    const/16 v7, 0xb

    .line 188
    .line 189
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 190
    .line 191
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 192
    .line 193
    .line 194
    return-object v2

    .line 195
    :pswitch_8
    move-object v6, p1

    .line 196
    new-instance v2, Lo10/l;

    .line 197
    .line 198
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 199
    .line 200
    move-object v3, p1

    .line 201
    check-cast v3, Lsk0/d;

    .line 202
    .line 203
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 204
    .line 205
    move-object v5, p1

    .line 206
    check-cast v5, Ljava/util/UUID;

    .line 207
    .line 208
    const/16 v7, 0xa

    .line 209
    .line 210
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 211
    .line 212
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 213
    .line 214
    .line 215
    return-object v2

    .line 216
    :pswitch_9
    move-object v6, p1

    .line 217
    new-instance v2, Lo10/l;

    .line 218
    .line 219
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 220
    .line 221
    move-object v3, p1

    .line 222
    check-cast v3, Lry/k;

    .line 223
    .line 224
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 225
    .line 226
    move-object v5, p1

    .line 227
    check-cast v5, Ljava/util/List;

    .line 228
    .line 229
    const/16 v7, 0x9

    .line 230
    .line 231
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 232
    .line 233
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 234
    .line 235
    .line 236
    return-object v2

    .line 237
    :pswitch_a
    move-object v6, p1

    .line 238
    new-instance v2, Lo10/l;

    .line 239
    .line 240
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 241
    .line 242
    move-object v3, p1

    .line 243
    check-cast v3, Lod0/b0;

    .line 244
    .line 245
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 246
    .line 247
    move-object v5, p1

    .line 248
    check-cast v5, Lrd0/r;

    .line 249
    .line 250
    const/16 v7, 0x8

    .line 251
    .line 252
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 253
    .line 254
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 255
    .line 256
    .line 257
    return-object v2

    .line 258
    :pswitch_b
    move-object v6, p1

    .line 259
    new-instance v2, Lo10/l;

    .line 260
    .line 261
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 262
    .line 263
    move-object v3, p1

    .line 264
    check-cast v3, Lod0/b0;

    .line 265
    .line 266
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 267
    .line 268
    move-object v5, p1

    .line 269
    check-cast v5, Lrd0/h;

    .line 270
    .line 271
    const/4 v7, 0x7

    .line 272
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 273
    .line 274
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 275
    .line 276
    .line 277
    return-object v2

    .line 278
    :pswitch_c
    move-object v6, p1

    .line 279
    new-instance v2, Lo10/l;

    .line 280
    .line 281
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 282
    .line 283
    move-object v3, p1

    .line 284
    check-cast v3, Lod0/b0;

    .line 285
    .line 286
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 287
    .line 288
    move-object v5, p1

    .line 289
    check-cast v5, Lqr0/l;

    .line 290
    .line 291
    const/4 v7, 0x6

    .line 292
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 293
    .line 294
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 295
    .line 296
    .line 297
    return-object v2

    .line 298
    :pswitch_d
    move-object v6, p1

    .line 299
    new-instance v2, Lo10/l;

    .line 300
    .line 301
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 302
    .line 303
    move-object v3, p1

    .line 304
    check-cast v3, Lod0/b0;

    .line 305
    .line 306
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 307
    .line 308
    move-object v5, p1

    .line 309
    check-cast v5, Lrd0/g;

    .line 310
    .line 311
    const/4 v7, 0x5

    .line 312
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 313
    .line 314
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 315
    .line 316
    .line 317
    return-object v2

    .line 318
    :pswitch_e
    move-object v6, p1

    .line 319
    new-instance v2, Lo10/l;

    .line 320
    .line 321
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 322
    .line 323
    move-object v3, p1

    .line 324
    check-cast v3, Lod0/b0;

    .line 325
    .line 326
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 327
    .line 328
    move-object v5, p1

    .line 329
    check-cast v5, Lrd0/g0;

    .line 330
    .line 331
    const/4 v7, 0x4

    .line 332
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 333
    .line 334
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 335
    .line 336
    .line 337
    return-object v2

    .line 338
    :pswitch_f
    move-object v6, p1

    .line 339
    new-instance v2, Lo10/l;

    .line 340
    .line 341
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 342
    .line 343
    move-object v3, p1

    .line 344
    check-cast v3, Lod0/b0;

    .line 345
    .line 346
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 347
    .line 348
    move-object v5, p1

    .line 349
    check-cast v5, Lrd0/a;

    .line 350
    .line 351
    const/4 v7, 0x3

    .line 352
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 353
    .line 354
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 355
    .line 356
    .line 357
    return-object v2

    .line 358
    :pswitch_10
    move-object v6, p1

    .line 359
    new-instance v2, Lo10/l;

    .line 360
    .line 361
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 362
    .line 363
    move-object v3, p1

    .line 364
    check-cast v3, Lod0/b0;

    .line 365
    .line 366
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 367
    .line 368
    move-object v5, p1

    .line 369
    check-cast v5, Lrd0/e0;

    .line 370
    .line 371
    const/4 v7, 0x2

    .line 372
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 373
    .line 374
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 375
    .line 376
    .line 377
    return-object v2

    .line 378
    :pswitch_11
    move-object v6, p1

    .line 379
    new-instance v2, Lo10/l;

    .line 380
    .line 381
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 382
    .line 383
    move-object v3, p1

    .line 384
    check-cast v3, Lo10/m;

    .line 385
    .line 386
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 387
    .line 388
    move-object v5, p1

    .line 389
    check-cast v5, Lqr0/l;

    .line 390
    .line 391
    const/4 v7, 0x1

    .line 392
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 393
    .line 394
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 395
    .line 396
    .line 397
    return-object v2

    .line 398
    :pswitch_12
    move-object v6, p1

    .line 399
    new-instance v2, Lo10/l;

    .line 400
    .line 401
    iget-object p1, p0, Lo10/l;->f:Ljava/lang/Object;

    .line 402
    .line 403
    move-object v3, p1

    .line 404
    check-cast v3, Lo10/m;

    .line 405
    .line 406
    iget-object p1, p0, Lo10/l;->h:Ljava/lang/Object;

    .line 407
    .line 408
    move-object v5, p1

    .line 409
    check-cast v5, Lr10/b;

    .line 410
    .line 411
    const/4 v7, 0x0

    .line 412
    iget-object v4, p0, Lo10/l;->g:Ljava/lang/String;

    .line 413
    .line 414
    invoke-direct/range {v2 .. v7}, Lo10/l;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 415
    .line 416
    .line 417
    return-object v2

    .line 418
    nop

    .line 419
    :pswitch_data_0
    .packed-switch 0x0
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

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lo10/l;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lo10/l;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lo10/l;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lo10/l;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lo10/l;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_3
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Lo10/l;

    .line 65
    .line 66
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_4
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    check-cast p0, Lo10/l;

    .line 78
    .line 79
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_5
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, Lo10/l;

    .line 91
    .line 92
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :pswitch_6
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    check-cast p0, Lo10/l;

    .line 104
    .line 105
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :pswitch_7
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    check-cast p0, Lo10/l;

    .line 117
    .line 118
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_8
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    check-cast p0, Lo10/l;

    .line 130
    .line 131
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0

    .line 138
    :pswitch_9
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    check-cast p0, Lo10/l;

    .line 143
    .line 144
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0

    .line 151
    :pswitch_a
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    check-cast p0, Lo10/l;

    .line 156
    .line 157
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_b
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    check-cast p0, Lo10/l;

    .line 169
    .line 170
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0

    .line 177
    :pswitch_c
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    check-cast p0, Lo10/l;

    .line 182
    .line 183
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    return-object p0

    .line 190
    :pswitch_d
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    check-cast p0, Lo10/l;

    .line 195
    .line 196
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    return-object p0

    .line 203
    :pswitch_e
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    check-cast p0, Lo10/l;

    .line 208
    .line 209
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    return-object p0

    .line 216
    :pswitch_f
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    check-cast p0, Lo10/l;

    .line 221
    .line 222
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 223
    .line 224
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    return-object p0

    .line 229
    :pswitch_10
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    check-cast p0, Lo10/l;

    .line 234
    .line 235
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 236
    .line 237
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    return-object p0

    .line 242
    :pswitch_11
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    check-cast p0, Lo10/l;

    .line 247
    .line 248
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 249
    .line 250
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    return-object p0

    .line 255
    :pswitch_12
    invoke-virtual {p0, p1}, Lo10/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    check-cast p0, Lo10/l;

    .line 260
    .line 261
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    invoke-virtual {p0, p1}, Lo10/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object p0

    .line 267
    return-object p0

    .line 268
    nop

    .line 269
    :pswitch_data_0
    .packed-switch 0x0
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

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 39

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget v0, v5, Lo10/l;->d:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v1, v5, Lo10/l;->e:I

    .line 11
    .line 12
    const/4 v2, 0x2

    .line 13
    const/4 v3, 0x1

    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-eq v1, v3, :cond_1

    .line 17
    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    move-object/from16 v0, p1

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0

    .line 34
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    move-object/from16 v1, p1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Lzp0/e;

    .line 46
    .line 47
    iget-object v1, v1, Lzp0/e;->b:Lti0/a;

    .line 48
    .line 49
    iput v3, v5, Lo10/l;->e:I

    .line 50
    .line 51
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    if-ne v1, v0, :cond_3

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    :goto_0
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 59
    .line 60
    new-instance v3, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;

    .line 61
    .line 62
    iget-object v4, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v4, Ljava/lang/String;

    .line 65
    .line 66
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iput v2, v5, Lo10/l;->e:I

    .line 70
    .line 71
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 72
    .line 73
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->setVehicleServicePartner(Ljava/lang/String;Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    if-ne v1, v0, :cond_4

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_4
    move-object v0, v1

    .line 81
    :goto_1
    return-object v0

    .line 82
    :pswitch_0
    iget-object v0, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lgg0/a;

    .line 85
    .line 86
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 87
    .line 88
    iget v1, v5, Lo10/l;->e:I

    .line 89
    .line 90
    const/4 v2, 0x2

    .line 91
    const/4 v3, 0x1

    .line 92
    if-eqz v1, :cond_7

    .line 93
    .line 94
    if-eq v1, v3, :cond_6

    .line 95
    .line 96
    if-ne v1, v2, :cond_5

    .line 97
    .line 98
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    move-object/from16 v0, p1

    .line 102
    .line 103
    goto :goto_5

    .line 104
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 105
    .line 106
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 107
    .line 108
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw v0

    .line 112
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    move-object/from16 v1, p1

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v1, Ly80/b;

    .line 124
    .line 125
    iget-object v1, v1, Ly80/b;->b:Lti0/a;

    .line 126
    .line 127
    iput v3, v5, Lo10/l;->e:I

    .line 128
    .line 129
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    if-ne v1, v8, :cond_8

    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_8
    :goto_2
    check-cast v1, Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;

    .line 137
    .line 138
    const/4 v3, 0x0

    .line 139
    if-eqz v0, :cond_9

    .line 140
    .line 141
    iget-wide v6, v0, Lgg0/a;->a:D

    .line 142
    .line 143
    new-instance v4, Ljava/lang/Double;

    .line 144
    .line 145
    invoke-direct {v4, v6, v7}, Ljava/lang/Double;-><init>(D)V

    .line 146
    .line 147
    .line 148
    goto :goto_3

    .line 149
    :cond_9
    move-object v4, v3

    .line 150
    :goto_3
    if-eqz v0, :cond_a

    .line 151
    .line 152
    iget-wide v6, v0, Lgg0/a;->b:D

    .line 153
    .line 154
    new-instance v3, Ljava/lang/Double;

    .line 155
    .line 156
    invoke-direct {v3, v6, v7}, Ljava/lang/Double;-><init>(D)V

    .line 157
    .line 158
    .line 159
    :cond_a
    iput v2, v5, Lo10/l;->e:I

    .line 160
    .line 161
    move-object v0, v1

    .line 162
    iget-object v1, v5, Lo10/l;->g:Ljava/lang/String;

    .line 163
    .line 164
    move-object v2, v4

    .line 165
    const/4 v4, 0x0

    .line 166
    const/16 v6, 0x8

    .line 167
    .line 168
    const/4 v7, 0x0

    .line 169
    invoke-static/range {v0 .. v7}, Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;->getDealers$default(Lcz/myskoda/api/bff_test_drive/v2/TestDriveApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    if-ne v0, v8, :cond_b

    .line 174
    .line 175
    :goto_4
    move-object v0, v8

    .line 176
    :cond_b
    :goto_5
    return-object v0

    .line 177
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 178
    .line 179
    iget v1, v5, Lo10/l;->e:I

    .line 180
    .line 181
    const/4 v2, 0x2

    .line 182
    const/4 v3, 0x1

    .line 183
    if-eqz v1, :cond_e

    .line 184
    .line 185
    if-eq v1, v3, :cond_d

    .line 186
    .line 187
    if-ne v1, v2, :cond_c

    .line 188
    .line 189
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    move-object/from16 v0, p1

    .line 193
    .line 194
    goto :goto_7

    .line 195
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 196
    .line 197
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 198
    .line 199
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    throw v0

    .line 203
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    move-object/from16 v1, p1

    .line 207
    .line 208
    goto :goto_6

    .line 209
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v1, Lx90/b;

    .line 215
    .line 216
    iget-object v1, v1, Lx90/b;->b:Lti0/a;

    .line 217
    .line 218
    iput v3, v5, Lo10/l;->e:I

    .line 219
    .line 220
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v1

    .line 224
    if-ne v1, v0, :cond_f

    .line 225
    .line 226
    goto :goto_7

    .line 227
    :cond_f
    :goto_6
    check-cast v1, Lcz/myskoda/api/bff/v1/VehicleServicesBackupApi;

    .line 228
    .line 229
    new-instance v3, Lcz/myskoda/api/bff/v1/ApplyVehicleServicesBackupRequestDto;

    .line 230
    .line 231
    iget-object v4, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast v4, Ljava/lang/String;

    .line 234
    .line 235
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ApplyVehicleServicesBackupRequestDto;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    iput v2, v5, Lo10/l;->e:I

    .line 239
    .line 240
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 241
    .line 242
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/VehicleServicesBackupApi;->applyVehicleServicesBackup(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ApplyVehicleServicesBackupRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    if-ne v1, v0, :cond_10

    .line 247
    .line 248
    goto :goto_7

    .line 249
    :cond_10
    move-object v0, v1

    .line 250
    :goto_7
    return-object v0

    .line 251
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 252
    .line 253
    iget v1, v5, Lo10/l;->e:I

    .line 254
    .line 255
    const/4 v2, 0x2

    .line 256
    const/4 v3, 0x1

    .line 257
    if-eqz v1, :cond_13

    .line 258
    .line 259
    if-eq v1, v3, :cond_12

    .line 260
    .line 261
    if-ne v1, v2, :cond_11

    .line 262
    .line 263
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    move-object/from16 v0, p1

    .line 267
    .line 268
    goto :goto_9

    .line 269
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 270
    .line 271
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 272
    .line 273
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :cond_12
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    move-object/from16 v1, p1

    .line 281
    .line 282
    goto :goto_8

    .line 283
    :cond_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v1, Lwo0/f;

    .line 289
    .line 290
    iget-object v1, v1, Lwo0/f;->b:Lti0/a;

    .line 291
    .line 292
    iput v3, v5, Lo10/l;->e:I

    .line 293
    .line 294
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    if-ne v1, v0, :cond_14

    .line 299
    .line 300
    goto :goto_9

    .line 301
    :cond_14
    :goto_8
    check-cast v1, Lcz/myskoda/api/bff/v1/NotificationSubscriptionApi;

    .line 302
    .line 303
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v3, Lcz/myskoda/api/bff/v1/NotificationSubscriptionDto;

    .line 306
    .line 307
    iput v2, v5, Lo10/l;->e:I

    .line 308
    .line 309
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 310
    .line 311
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/NotificationSubscriptionApi;->createNotificationSubscription(Ljava/lang/String;Lcz/myskoda/api/bff/v1/NotificationSubscriptionDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    if-ne v1, v0, :cond_15

    .line 316
    .line 317
    goto :goto_9

    .line 318
    :cond_15
    move-object v0, v1

    .line 319
    :goto_9
    return-object v0

    .line 320
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 321
    .line 322
    iget v1, v5, Lo10/l;->e:I

    .line 323
    .line 324
    const/4 v2, 0x2

    .line 325
    const/4 v3, 0x1

    .line 326
    if-eqz v1, :cond_18

    .line 327
    .line 328
    if-eq v1, v3, :cond_17

    .line 329
    .line 330
    if-ne v1, v2, :cond_16

    .line 331
    .line 332
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    move-object/from16 v0, p1

    .line 336
    .line 337
    goto :goto_b

    .line 338
    :cond_16
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 339
    .line 340
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 341
    .line 342
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 343
    .line 344
    .line 345
    throw v0

    .line 346
    :cond_17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    move-object/from16 v1, p1

    .line 350
    .line 351
    goto :goto_a

    .line 352
    :cond_18
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 353
    .line 354
    .line 355
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v1, Lwo0/e;

    .line 358
    .line 359
    iget-object v1, v1, Lwo0/e;->b:Lti0/a;

    .line 360
    .line 361
    iput v3, v5, Lo10/l;->e:I

    .line 362
    .line 363
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v1

    .line 367
    if-ne v1, v0, :cond_19

    .line 368
    .line 369
    goto :goto_b

    .line 370
    :cond_19
    :goto_a
    check-cast v1, Lcz/myskoda/api/bff/v1/NotificationSubscriptionApi;

    .line 371
    .line 372
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 373
    .line 374
    check-cast v3, Ljava/lang/String;

    .line 375
    .line 376
    iput v2, v5, Lo10/l;->e:I

    .line 377
    .line 378
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 379
    .line 380
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/NotificationSubscriptionApi;->getNotificationSettings(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v1

    .line 384
    if-ne v1, v0, :cond_1a

    .line 385
    .line 386
    goto :goto_b

    .line 387
    :cond_1a
    move-object v0, v1

    .line 388
    :goto_b
    return-object v0

    .line 389
    :pswitch_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 390
    .line 391
    iget v1, v5, Lo10/l;->e:I

    .line 392
    .line 393
    const/4 v2, 0x2

    .line 394
    const/4 v3, 0x1

    .line 395
    if-eqz v1, :cond_1d

    .line 396
    .line 397
    if-eq v1, v3, :cond_1c

    .line 398
    .line 399
    if-ne v1, v2, :cond_1b

    .line 400
    .line 401
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 402
    .line 403
    .line 404
    move-object/from16 v0, p1

    .line 405
    .line 406
    goto :goto_d

    .line 407
    :cond_1b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 408
    .line 409
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 410
    .line 411
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    throw v0

    .line 415
    :cond_1c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 416
    .line 417
    .line 418
    move-object/from16 v1, p1

    .line 419
    .line 420
    goto :goto_c

    .line 421
    :cond_1d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 422
    .line 423
    .line 424
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 425
    .line 426
    check-cast v1, Lus0/b;

    .line 427
    .line 428
    iget-object v1, v1, Lus0/b;->b:Lti0/a;

    .line 429
    .line 430
    iput v3, v5, Lo10/l;->e:I

    .line 431
    .line 432
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    if-ne v1, v0, :cond_1e

    .line 437
    .line 438
    goto :goto_d

    .line 439
    :cond_1e
    :goto_c
    check-cast v1, Lcz/myskoda/api/bff/v1/VehicleServicesBackupApi;

    .line 440
    .line 441
    new-instance v3, Lcz/myskoda/api/bff/v1/VehicleServicesBackupCreationRequestDto;

    .line 442
    .line 443
    iget-object v4, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast v4, Ljava/lang/String;

    .line 446
    .line 447
    iget-object v6, v5, Lo10/l;->g:Ljava/lang/String;

    .line 448
    .line 449
    invoke-direct {v3, v6, v4}, Lcz/myskoda/api/bff/v1/VehicleServicesBackupCreationRequestDto;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    iput v2, v5, Lo10/l;->e:I

    .line 453
    .line 454
    invoke-interface {v1, v3, v5}, Lcz/myskoda/api/bff/v1/VehicleServicesBackupApi;->createVehicleServicesBackup(Lcz/myskoda/api/bff/v1/VehicleServicesBackupCreationRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    if-ne v1, v0, :cond_1f

    .line 459
    .line 460
    goto :goto_d

    .line 461
    :cond_1f
    move-object v0, v1

    .line 462
    :goto_d
    return-object v0

    .line 463
    :pswitch_5
    iget-object v0, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 464
    .line 465
    check-cast v0, Lu70/c;

    .line 466
    .line 467
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 468
    .line 469
    iget v2, v5, Lo10/l;->e:I

    .line 470
    .line 471
    const/4 v3, 0x2

    .line 472
    const/4 v4, 0x1

    .line 473
    if-eqz v2, :cond_22

    .line 474
    .line 475
    if-eq v2, v4, :cond_21

    .line 476
    .line 477
    if-ne v2, v3, :cond_20

    .line 478
    .line 479
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 480
    .line 481
    .line 482
    move-object/from16 v0, p1

    .line 483
    .line 484
    goto/16 :goto_12

    .line 485
    .line 486
    :cond_20
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 487
    .line 488
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 489
    .line 490
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    throw v0

    .line 494
    :cond_21
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 495
    .line 496
    .line 497
    move-object/from16 v0, p1

    .line 498
    .line 499
    goto :goto_e

    .line 500
    :cond_22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 501
    .line 502
    .line 503
    iget-object v0, v0, Lu70/c;->b:Lti0/a;

    .line 504
    .line 505
    iput v4, v5, Lo10/l;->e:I

    .line 506
    .line 507
    invoke-interface {v0, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v0

    .line 511
    if-ne v0, v1, :cond_23

    .line 512
    .line 513
    goto :goto_11

    .line 514
    :cond_23
    :goto_e
    check-cast v0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 515
    .line 516
    iget-object v2, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast v2, Lcq0/i;

    .line 519
    .line 520
    iget-object v4, v2, Lcq0/i;->a:Lqr0/d;

    .line 521
    .line 522
    if-eqz v4, :cond_24

    .line 523
    .line 524
    iget-wide v6, v4, Lqr0/d;->a:D

    .line 525
    .line 526
    const-wide v8, 0x408f400000000000L    # 1000.0

    .line 527
    .line 528
    .line 529
    .line 530
    .line 531
    div-double/2addr v6, v8

    .line 532
    double-to-int v4, v6

    .line 533
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 534
    .line 535
    .line 536
    move-result-object v4

    .line 537
    goto :goto_f

    .line 538
    :cond_24
    const/4 v4, 0x0

    .line 539
    :goto_f
    iget-object v6, v2, Lcq0/i;->b:Ljava/util/ArrayList;

    .line 540
    .line 541
    new-instance v7, Ljava/util/ArrayList;

    .line 542
    .line 543
    const/16 v8, 0xa

    .line 544
    .line 545
    invoke-static {v6, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 546
    .line 547
    .line 548
    move-result v8

    .line 549
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 550
    .line 551
    .line 552
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 553
    .line 554
    .line 555
    move-result-object v6

    .line 556
    :goto_10
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 557
    .line 558
    .line 559
    move-result v8

    .line 560
    if-eqz v8, :cond_25

    .line 561
    .line 562
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v8

    .line 566
    check-cast v8, Lcq0/w;

    .line 567
    .line 568
    new-instance v9, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;

    .line 569
    .line 570
    iget-object v10, v8, Lcq0/w;->d:Ljava/lang/String;

    .line 571
    .line 572
    invoke-virtual {v8}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 573
    .line 574
    .line 575
    move-result-object v8

    .line 576
    invoke-direct {v9, v10, v8}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingExtrasDto;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 577
    .line 578
    .line 579
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 580
    .line 581
    .line 582
    goto :goto_10

    .line 583
    :cond_25
    new-instance v6, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;

    .line 584
    .line 585
    iget-object v8, v2, Lcq0/i;->c:Ljava/time/OffsetDateTime;

    .line 586
    .line 587
    iget-object v9, v2, Lcq0/i;->d:Ljava/time/OffsetDateTime;

    .line 588
    .line 589
    iget-object v10, v2, Lcq0/i;->e:Ljava/lang/String;

    .line 590
    .line 591
    iget-boolean v2, v2, Lcq0/i;->f:Z

    .line 592
    .line 593
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 594
    .line 595
    .line 596
    move-result-object v2

    .line 597
    invoke-direct {v6, v8, v9, v10, v2}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;-><init>(Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/Boolean;)V

    .line 598
    .line 599
    .line 600
    new-instance v2, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;

    .line 601
    .line 602
    invoke-direct {v2, v4, v6, v7}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;-><init>(Ljava/lang/Integer;Lcz/myskoda/api/bff_vehicle_maintenance/v3/BookingAddOnsDto;Ljava/util/List;)V

    .line 603
    .line 604
    .line 605
    iput v3, v5, Lo10/l;->e:I

    .line 606
    .line 607
    iget-object v3, v5, Lo10/l;->g:Ljava/lang/String;

    .line 608
    .line 609
    invoke-interface {v0, v3, v2, v5}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->createServiceBooking(Ljava/lang/String;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 610
    .line 611
    .line 612
    move-result-object v0

    .line 613
    if-ne v0, v1, :cond_26

    .line 614
    .line 615
    :goto_11
    move-object v0, v1

    .line 616
    :cond_26
    :goto_12
    return-object v0

    .line 617
    :pswitch_6
    iget-object v0, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 618
    .line 619
    check-cast v0, Lgg0/a;

    .line 620
    .line 621
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 622
    .line 623
    iget v1, v5, Lo10/l;->e:I

    .line 624
    .line 625
    const/4 v2, 0x2

    .line 626
    const/4 v3, 0x1

    .line 627
    if-eqz v1, :cond_29

    .line 628
    .line 629
    if-eq v1, v3, :cond_28

    .line 630
    .line 631
    if-ne v1, v2, :cond_27

    .line 632
    .line 633
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 634
    .line 635
    .line 636
    move-object/from16 v0, p1

    .line 637
    .line 638
    goto :goto_16

    .line 639
    :cond_27
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 640
    .line 641
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 642
    .line 643
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 644
    .line 645
    .line 646
    throw v0

    .line 647
    :cond_28
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 648
    .line 649
    .line 650
    move-object/from16 v1, p1

    .line 651
    .line 652
    goto :goto_13

    .line 653
    :cond_29
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 654
    .line 655
    .line 656
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 657
    .line 658
    check-cast v1, Lu70/c;

    .line 659
    .line 660
    iget-object v1, v1, Lu70/c;->b:Lti0/a;

    .line 661
    .line 662
    iput v3, v5, Lo10/l;->e:I

    .line 663
    .line 664
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 665
    .line 666
    .line 667
    move-result-object v1

    .line 668
    if-ne v1, v9, :cond_2a

    .line 669
    .line 670
    goto :goto_15

    .line 671
    :cond_2a
    :goto_13
    check-cast v1, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;

    .line 672
    .line 673
    const/4 v3, 0x0

    .line 674
    if-eqz v0, :cond_2b

    .line 675
    .line 676
    iget-wide v6, v0, Lgg0/a;->a:D

    .line 677
    .line 678
    new-instance v4, Ljava/lang/Double;

    .line 679
    .line 680
    invoke-direct {v4, v6, v7}, Ljava/lang/Double;-><init>(D)V

    .line 681
    .line 682
    .line 683
    goto :goto_14

    .line 684
    :cond_2b
    move-object v4, v3

    .line 685
    :goto_14
    if-eqz v0, :cond_2c

    .line 686
    .line 687
    iget-wide v6, v0, Lgg0/a;->b:D

    .line 688
    .line 689
    new-instance v3, Ljava/lang/Double;

    .line 690
    .line 691
    invoke-direct {v3, v6, v7}, Ljava/lang/Double;-><init>(D)V

    .line 692
    .line 693
    .line 694
    :cond_2c
    iput v2, v5, Lo10/l;->e:I

    .line 695
    .line 696
    move-object v0, v1

    .line 697
    iget-object v1, v5, Lo10/l;->g:Ljava/lang/String;

    .line 698
    .line 699
    move-object v2, v4

    .line 700
    const/4 v4, 0x0

    .line 701
    const/4 v5, 0x0

    .line 702
    const/16 v7, 0x18

    .line 703
    .line 704
    const/4 v8, 0x0

    .line 705
    move-object/from16 v6, p0

    .line 706
    .line 707
    invoke-static/range {v0 .. v8}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->getServicePartners$default(Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Float;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v0

    .line 711
    if-ne v0, v9, :cond_2d

    .line 712
    .line 713
    :goto_15
    move-object v0, v9

    .line 714
    :cond_2d
    :goto_16
    return-object v0

    .line 715
    :pswitch_7
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 716
    .line 717
    iget v1, v5, Lo10/l;->e:I

    .line 718
    .line 719
    const/4 v2, 0x2

    .line 720
    const/4 v3, 0x1

    .line 721
    if-eqz v1, :cond_30

    .line 722
    .line 723
    if-eq v1, v3, :cond_2f

    .line 724
    .line 725
    if-ne v1, v2, :cond_2e

    .line 726
    .line 727
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 728
    .line 729
    .line 730
    move-object/from16 v0, p1

    .line 731
    .line 732
    goto :goto_18

    .line 733
    :cond_2e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 734
    .line 735
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 736
    .line 737
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 738
    .line 739
    .line 740
    throw v0

    .line 741
    :cond_2f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 742
    .line 743
    .line 744
    move-object/from16 v1, p1

    .line 745
    .line 746
    goto :goto_17

    .line 747
    :cond_30
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 748
    .line 749
    .line 750
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 751
    .line 752
    check-cast v1, Ltq0/k;

    .line 753
    .line 754
    iget-object v1, v1, Ltq0/k;->b:Lti0/a;

    .line 755
    .line 756
    iput v3, v5, Lo10/l;->e:I

    .line 757
    .line 758
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 759
    .line 760
    .line 761
    move-result-object v1

    .line 762
    if-ne v1, v0, :cond_31

    .line 763
    .line 764
    goto :goto_18

    .line 765
    :cond_31
    :goto_17
    check-cast v1, Lcz/myskoda/api/bff/v1/SpinApi;

    .line 766
    .line 767
    new-instance v3, Lcz/myskoda/api/bff/v1/SpinUpdateDto;

    .line 768
    .line 769
    iget-object v4, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 770
    .line 771
    check-cast v4, Ljava/lang/String;

    .line 772
    .line 773
    iget-object v6, v5, Lo10/l;->g:Ljava/lang/String;

    .line 774
    .line 775
    invoke-direct {v3, v6, v4}, Lcz/myskoda/api/bff/v1/SpinUpdateDto;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 776
    .line 777
    .line 778
    iput v2, v5, Lo10/l;->e:I

    .line 779
    .line 780
    invoke-interface {v1, v3, v5}, Lcz/myskoda/api/bff/v1/SpinApi;->updateSpin(Lcz/myskoda/api/bff/v1/SpinUpdateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 781
    .line 782
    .line 783
    move-result-object v1

    .line 784
    if-ne v1, v0, :cond_32

    .line 785
    .line 786
    goto :goto_18

    .line 787
    :cond_32
    move-object v0, v1

    .line 788
    :goto_18
    return-object v0

    .line 789
    :pswitch_8
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 790
    .line 791
    iget v1, v5, Lo10/l;->e:I

    .line 792
    .line 793
    const/4 v2, 0x2

    .line 794
    const/4 v3, 0x1

    .line 795
    if-eqz v1, :cond_35

    .line 796
    .line 797
    if-eq v1, v3, :cond_34

    .line 798
    .line 799
    if-ne v1, v2, :cond_33

    .line 800
    .line 801
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 802
    .line 803
    .line 804
    move-object/from16 v0, p1

    .line 805
    .line 806
    goto :goto_1a

    .line 807
    :cond_33
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 808
    .line 809
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 810
    .line 811
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 812
    .line 813
    .line 814
    throw v0

    .line 815
    :cond_34
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 816
    .line 817
    .line 818
    move-object/from16 v1, p1

    .line 819
    .line 820
    goto :goto_19

    .line 821
    :cond_35
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 822
    .line 823
    .line 824
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 825
    .line 826
    check-cast v1, Lsk0/d;

    .line 827
    .line 828
    iget-object v1, v1, Lsk0/d;->b:Lti0/a;

    .line 829
    .line 830
    iput v3, v5, Lo10/l;->e:I

    .line 831
    .line 832
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 833
    .line 834
    .line 835
    move-result-object v1

    .line 836
    if-ne v1, v0, :cond_36

    .line 837
    .line 838
    goto :goto_1a

    .line 839
    :cond_36
    :goto_19
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 840
    .line 841
    new-instance v3, Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;

    .line 842
    .line 843
    iget-object v4, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 844
    .line 845
    check-cast v4, Ljava/util/UUID;

    .line 846
    .line 847
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;-><init>(Ljava/util/UUID;)V

    .line 848
    .line 849
    .line 850
    iput v2, v5, Lo10/l;->e:I

    .line 851
    .line 852
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 853
    .line 854
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->redeemOffer(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 855
    .line 856
    .line 857
    move-result-object v1

    .line 858
    if-ne v1, v0, :cond_37

    .line 859
    .line 860
    goto :goto_1a

    .line 861
    :cond_37
    move-object v0, v1

    .line 862
    :goto_1a
    return-object v0

    .line 863
    :pswitch_9
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 864
    .line 865
    iget v1, v5, Lo10/l;->e:I

    .line 866
    .line 867
    const/4 v2, 0x2

    .line 868
    const/4 v3, 0x1

    .line 869
    if-eqz v1, :cond_3a

    .line 870
    .line 871
    if-eq v1, v3, :cond_39

    .line 872
    .line 873
    if-ne v1, v2, :cond_38

    .line 874
    .line 875
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 876
    .line 877
    .line 878
    move-object/from16 v0, p1

    .line 879
    .line 880
    goto :goto_1d

    .line 881
    :cond_38
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 882
    .line 883
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 884
    .line 885
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 886
    .line 887
    .line 888
    throw v0

    .line 889
    :cond_39
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 890
    .line 891
    .line 892
    move-object/from16 v1, p1

    .line 893
    .line 894
    goto :goto_1b

    .line 895
    :cond_3a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 896
    .line 897
    .line 898
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 899
    .line 900
    check-cast v1, Lry/k;

    .line 901
    .line 902
    iget-object v1, v1, Lry/k;->b:Lti0/a;

    .line 903
    .line 904
    iput v3, v5, Lo10/l;->e:I

    .line 905
    .line 906
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 907
    .line 908
    .line 909
    move-result-object v1

    .line 910
    if-ne v1, v0, :cond_3b

    .line 911
    .line 912
    goto :goto_1d

    .line 913
    :cond_3b
    :goto_1b
    check-cast v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 914
    .line 915
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 916
    .line 917
    check-cast v3, Ljava/util/List;

    .line 918
    .line 919
    const-string v4, "<this>"

    .line 920
    .line 921
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 922
    .line 923
    .line 924
    check-cast v3, Ljava/lang/Iterable;

    .line 925
    .line 926
    new-instance v4, Ljava/util/ArrayList;

    .line 927
    .line 928
    const/16 v6, 0xa

    .line 929
    .line 930
    invoke-static {v3, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 931
    .line 932
    .line 933
    move-result v6

    .line 934
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 935
    .line 936
    .line 937
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 938
    .line 939
    .line 940
    move-result-object v3

    .line 941
    :goto_1c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 942
    .line 943
    .line 944
    move-result v6

    .line 945
    if-eqz v6, :cond_3c

    .line 946
    .line 947
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 948
    .line 949
    .line 950
    move-result-object v6

    .line 951
    check-cast v6, Lao0/c;

    .line 952
    .line 953
    invoke-static {v6}, Lwn0/c;->a(Lao0/c;)Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 954
    .line 955
    .line 956
    move-result-object v6

    .line 957
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 958
    .line 959
    .line 960
    goto :goto_1c

    .line 961
    :cond_3c
    new-instance v3, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;

    .line 962
    .line 963
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;-><init>(Ljava/util/List;)V

    .line 964
    .line 965
    .line 966
    iput v2, v5, Lo10/l;->e:I

    .line 967
    .line 968
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 969
    .line 970
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setActiveVentilationTimers(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 971
    .line 972
    .line 973
    move-result-object v1

    .line 974
    if-ne v1, v0, :cond_3d

    .line 975
    .line 976
    goto :goto_1d

    .line 977
    :cond_3d
    move-object v0, v1

    .line 978
    :goto_1d
    return-object v0

    .line 979
    :pswitch_a
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 980
    .line 981
    iget v0, v5, Lo10/l;->e:I

    .line 982
    .line 983
    const/4 v1, 0x2

    .line 984
    const/4 v2, 0x1

    .line 985
    if-eqz v0, :cond_40

    .line 986
    .line 987
    if-eq v0, v2, :cond_3f

    .line 988
    .line 989
    if-ne v0, v1, :cond_3e

    .line 990
    .line 991
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 992
    .line 993
    .line 994
    move-object/from16 v0, p1

    .line 995
    .line 996
    goto/16 :goto_2c

    .line 997
    .line 998
    :cond_3e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 999
    .line 1000
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1001
    .line 1002
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1003
    .line 1004
    .line 1005
    throw v0

    .line 1006
    :cond_3f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1007
    .line 1008
    .line 1009
    move-object/from16 v0, p1

    .line 1010
    .line 1011
    goto :goto_1e

    .line 1012
    :cond_40
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1013
    .line 1014
    .line 1015
    iget-object v0, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1016
    .line 1017
    check-cast v0, Lod0/b0;

    .line 1018
    .line 1019
    iget-object v0, v0, Lod0/b0;->b:Lti0/a;

    .line 1020
    .line 1021
    iput v2, v5, Lo10/l;->e:I

    .line 1022
    .line 1023
    invoke-interface {v0, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v0

    .line 1027
    if-ne v0, v6, :cond_41

    .line 1028
    .line 1029
    goto/16 :goto_2b

    .line 1030
    .line 1031
    :cond_41
    :goto_1e
    check-cast v0, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1032
    .line 1033
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1034
    .line 1035
    check-cast v3, Lrd0/r;

    .line 1036
    .line 1037
    iget-wide v8, v3, Lrd0/r;->a:J

    .line 1038
    .line 1039
    iget-object v10, v3, Lrd0/r;->b:Ljava/lang/String;

    .line 1040
    .line 1041
    iget-object v4, v3, Lrd0/r;->d:Ljava/util/List;

    .line 1042
    .line 1043
    check-cast v4, Ljava/lang/Iterable;

    .line 1044
    .line 1045
    new-instance v13, Ljava/util/ArrayList;

    .line 1046
    .line 1047
    const/16 v7, 0xa

    .line 1048
    .line 1049
    invoke-static {v4, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1050
    .line 1051
    .line 1052
    move-result v11

    .line 1053
    invoke-direct {v13, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 1054
    .line 1055
    .line 1056
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v4

    .line 1060
    :goto_1f
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1061
    .line 1062
    .line 1063
    move-result v11

    .line 1064
    if-eqz v11, :cond_47

    .line 1065
    .line 1066
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v11

    .line 1070
    check-cast v11, Lao0/c;

    .line 1071
    .line 1072
    iget-wide v14, v11, Lao0/c;->a:J

    .line 1073
    .line 1074
    iget-object v12, v11, Lao0/c;->e:Ljava/util/Set;

    .line 1075
    .line 1076
    iget-boolean v1, v11, Lao0/c;->b:Z

    .line 1077
    .line 1078
    iget-object v7, v11, Lao0/c;->d:Lao0/f;

    .line 1079
    .line 1080
    const-string v2, "<this>"

    .line 1081
    .line 1082
    invoke-static {v7, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1083
    .line 1084
    .line 1085
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 1086
    .line 1087
    .line 1088
    move-result v2

    .line 1089
    if-eqz v2, :cond_43

    .line 1090
    .line 1091
    move-object/from16 v27, v0

    .line 1092
    .line 1093
    const/4 v0, 0x1

    .line 1094
    if-ne v2, v0, :cond_42

    .line 1095
    .line 1096
    const-string v0, "RECURRING"

    .line 1097
    .line 1098
    :goto_20
    move-object/from16 v18, v0

    .line 1099
    .line 1100
    goto :goto_21

    .line 1101
    :cond_42
    new-instance v0, La8/r0;

    .line 1102
    .line 1103
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1104
    .line 1105
    .line 1106
    throw v0

    .line 1107
    :cond_43
    move-object/from16 v27, v0

    .line 1108
    .line 1109
    const-string v0, "ONE_OFF"

    .line 1110
    .line 1111
    goto :goto_20

    .line 1112
    :goto_21
    iget-object v0, v11, Lao0/c;->c:Ljava/time/LocalTime;

    .line 1113
    .line 1114
    invoke-virtual {v0}, Ljava/time/LocalTime;->toString()Ljava/lang/String;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v20

    .line 1118
    iget-boolean v0, v11, Lao0/c;->f:Z

    .line 1119
    .line 1120
    new-instance v28, Lcz/myskoda/api/bff/v1/TimerDto;

    .line 1121
    .line 1122
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v19

    .line 1126
    const/16 v23, 0x60

    .line 1127
    .line 1128
    const/16 v24, 0x0

    .line 1129
    .line 1130
    const/16 v21, 0x0

    .line 1131
    .line 1132
    const/16 v22, 0x0

    .line 1133
    .line 1134
    move/from16 v17, v1

    .line 1135
    .line 1136
    move-wide v15, v14

    .line 1137
    move-object/from16 v14, v28

    .line 1138
    .line 1139
    invoke-direct/range {v14 .. v24}, Lcz/myskoda/api/bff/v1/TimerDto;-><init>(JZLjava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    .line 1140
    .line 1141
    .line 1142
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 1143
    .line 1144
    .line 1145
    move-result v0

    .line 1146
    if-eqz v0, :cond_46

    .line 1147
    .line 1148
    const/4 v1, 0x1

    .line 1149
    if-ne v0, v1, :cond_45

    .line 1150
    .line 1151
    check-cast v12, Ljava/lang/Iterable;

    .line 1152
    .line 1153
    new-instance v0, Ljava/util/ArrayList;

    .line 1154
    .line 1155
    const/16 v2, 0xa

    .line 1156
    .line 1157
    invoke-static {v12, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1158
    .line 1159
    .line 1160
    move-result v7

    .line 1161
    invoke-direct {v0, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 1162
    .line 1163
    .line 1164
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1165
    .line 1166
    .line 1167
    move-result-object v2

    .line 1168
    :goto_22
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1169
    .line 1170
    .line 1171
    move-result v7

    .line 1172
    if-eqz v7, :cond_44

    .line 1173
    .line 1174
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v7

    .line 1178
    check-cast v7, Ljava/time/DayOfWeek;

    .line 1179
    .line 1180
    invoke-virtual {v7}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v7

    .line 1184
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1185
    .line 1186
    .line 1187
    goto :goto_22

    .line 1188
    :cond_44
    const/16 v37, 0x3f

    .line 1189
    .line 1190
    const/16 v38, 0x0

    .line 1191
    .line 1192
    const-wide/16 v29, 0x0

    .line 1193
    .line 1194
    const/16 v31, 0x0

    .line 1195
    .line 1196
    const/16 v32, 0x0

    .line 1197
    .line 1198
    const/16 v33, 0x0

    .line 1199
    .line 1200
    const/16 v34, 0x0

    .line 1201
    .line 1202
    const/16 v35, 0x0

    .line 1203
    .line 1204
    move-object/from16 v36, v0

    .line 1205
    .line 1206
    invoke-static/range {v28 .. v38}, Lcz/myskoda/api/bff/v1/TimerDto;->copy$default(Lcz/myskoda/api/bff/v1/TimerDto;JZLjava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/TimerDto;

    .line 1207
    .line 1208
    .line 1209
    move-result-object v0

    .line 1210
    goto :goto_23

    .line 1211
    :cond_45
    new-instance v0, La8/r0;

    .line 1212
    .line 1213
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1214
    .line 1215
    .line 1216
    throw v0

    .line 1217
    :cond_46
    const/4 v1, 0x1

    .line 1218
    check-cast v12, Ljava/lang/Iterable;

    .line 1219
    .line 1220
    invoke-static {v12}, Lmx0/q;->I(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 1221
    .line 1222
    .line 1223
    move-result-object v0

    .line 1224
    check-cast v0, Ljava/time/DayOfWeek;

    .line 1225
    .line 1226
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v35

    .line 1230
    const/16 v37, 0x5f

    .line 1231
    .line 1232
    const/16 v38, 0x0

    .line 1233
    .line 1234
    const-wide/16 v29, 0x0

    .line 1235
    .line 1236
    const/16 v31, 0x0

    .line 1237
    .line 1238
    const/16 v32, 0x0

    .line 1239
    .line 1240
    const/16 v33, 0x0

    .line 1241
    .line 1242
    const/16 v34, 0x0

    .line 1243
    .line 1244
    const/16 v36, 0x0

    .line 1245
    .line 1246
    invoke-static/range {v28 .. v38}, Lcz/myskoda/api/bff/v1/TimerDto;->copy$default(Lcz/myskoda/api/bff/v1/TimerDto;JZLjava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/TimerDto;

    .line 1247
    .line 1248
    .line 1249
    move-result-object v0

    .line 1250
    :goto_23
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1251
    .line 1252
    .line 1253
    move v2, v1

    .line 1254
    move-object/from16 v0, v27

    .line 1255
    .line 1256
    const/4 v1, 0x2

    .line 1257
    const/16 v7, 0xa

    .line 1258
    .line 1259
    goto/16 :goto_1f

    .line 1260
    .line 1261
    :cond_47
    move-object/from16 v27, v0

    .line 1262
    .line 1263
    move v1, v2

    .line 1264
    iget-object v0, v3, Lrd0/r;->e:Ljava/util/List;

    .line 1265
    .line 1266
    check-cast v0, Ljava/lang/Iterable;

    .line 1267
    .line 1268
    new-instance v12, Ljava/util/ArrayList;

    .line 1269
    .line 1270
    const/16 v2, 0xa

    .line 1271
    .line 1272
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1273
    .line 1274
    .line 1275
    move-result v2

    .line 1276
    invoke-direct {v12, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1277
    .line 1278
    .line 1279
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1280
    .line 1281
    .line 1282
    move-result-object v0

    .line 1283
    :goto_24
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1284
    .line 1285
    .line 1286
    move-result v2

    .line 1287
    if-eqz v2, :cond_48

    .line 1288
    .line 1289
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1290
    .line 1291
    .line 1292
    move-result-object v2

    .line 1293
    check-cast v2, Lao0/a;

    .line 1294
    .line 1295
    invoke-static {v2}, Llp/md;->b(Lao0/a;)Lcz/myskoda/api/bff/v1/ChargingTimeDto;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v2

    .line 1299
    invoke-virtual {v12, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1300
    .line 1301
    .line 1302
    goto :goto_24

    .line 1303
    :cond_48
    iget-object v0, v3, Lrd0/r;->f:Lrd0/s;

    .line 1304
    .line 1305
    iget-object v2, v0, Lrd0/s;->c:Ljava/lang/Boolean;

    .line 1306
    .line 1307
    const/4 v3, 0x0

    .line 1308
    if-eqz v2, :cond_4a

    .line 1309
    .line 1310
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1311
    .line 1312
    .line 1313
    move-result v2

    .line 1314
    if-eqz v2, :cond_49

    .line 1315
    .line 1316
    sget-object v2, Lrd0/g;->e:Lrd0/g;

    .line 1317
    .line 1318
    goto :goto_25

    .line 1319
    :cond_49
    sget-object v2, Lrd0/g;->d:Lrd0/g;

    .line 1320
    .line 1321
    :goto_25
    invoke-static {v2}, Ljp/qb;->e(Lrd0/g;)Lcz/myskoda/api/bff/v1/ChargingCurrentDto;

    .line 1322
    .line 1323
    .line 1324
    move-result-object v2

    .line 1325
    invoke-virtual {v2}, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;->getChargingCurrent()Ljava/lang/String;

    .line 1326
    .line 1327
    .line 1328
    move-result-object v2

    .line 1329
    goto :goto_26

    .line 1330
    :cond_4a
    move-object v2, v3

    .line 1331
    :goto_26
    iget-object v4, v0, Lrd0/s;->a:Lqr0/l;

    .line 1332
    .line 1333
    if-eqz v4, :cond_4c

    .line 1334
    .line 1335
    new-instance v7, Lcz/myskoda/api/bff/v1/MinBatteryStateOfChargeDto;

    .line 1336
    .line 1337
    iget v4, v4, Lqr0/l;->d:I

    .line 1338
    .line 1339
    if-lez v4, :cond_4b

    .line 1340
    .line 1341
    goto :goto_27

    .line 1342
    :cond_4b
    const/4 v1, 0x0

    .line 1343
    :goto_27
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v1

    .line 1347
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v4

    .line 1351
    invoke-direct {v7, v1, v4}, Lcz/myskoda/api/bff/v1/MinBatteryStateOfChargeDto;-><init>(Ljava/lang/Boolean;Ljava/lang/Integer;)V

    .line 1352
    .line 1353
    .line 1354
    goto :goto_28

    .line 1355
    :cond_4c
    move-object v7, v3

    .line 1356
    :goto_28
    iget-object v1, v0, Lrd0/s;->b:Lqr0/l;

    .line 1357
    .line 1358
    if-eqz v1, :cond_4d

    .line 1359
    .line 1360
    iget v1, v1, Lqr0/l;->d:I

    .line 1361
    .line 1362
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1363
    .line 1364
    .line 1365
    move-result-object v1

    .line 1366
    goto :goto_29

    .line 1367
    :cond_4d
    move-object v1, v3

    .line 1368
    :goto_29
    iget-object v0, v0, Lrd0/s;->d:Ljava/lang/Boolean;

    .line 1369
    .line 1370
    if-eqz v0, :cond_4f

    .line 1371
    .line 1372
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1373
    .line 1374
    .line 1375
    move-result v0

    .line 1376
    if-eqz v0, :cond_4e

    .line 1377
    .line 1378
    sget-object v0, Lrd0/g0;->d:Lrd0/g0;

    .line 1379
    .line 1380
    goto :goto_2a

    .line 1381
    :cond_4e
    sget-object v0, Lrd0/g0;->e:Lrd0/g0;

    .line 1382
    .line 1383
    :goto_2a
    invoke-static {v0}, Ljp/qb;->d(Lrd0/g0;)Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;

    .line 1384
    .line 1385
    .line 1386
    move-result-object v0

    .line 1387
    invoke-virtual {v0}, Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;->getAutoUnlockPlug()Ljava/lang/String;

    .line 1388
    .line 1389
    .line 1390
    move-result-object v3

    .line 1391
    :cond_4f
    new-instance v11, Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;

    .line 1392
    .line 1393
    invoke-direct {v11, v2, v7, v1, v3}, Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff/v1/MinBatteryStateOfChargeDto;Ljava/lang/Integer;Ljava/lang/String;)V

    .line 1394
    .line 1395
    .line 1396
    new-instance v4, Lcz/myskoda/api/bff/v1/ChargingProfileDto;

    .line 1397
    .line 1398
    const/16 v15, 0x20

    .line 1399
    .line 1400
    const/16 v16, 0x0

    .line 1401
    .line 1402
    const/4 v14, 0x0

    .line 1403
    move-object v7, v4

    .line 1404
    invoke-direct/range {v7 .. v16}, Lcz/myskoda/api/bff/v1/ChargingProfileDto;-><init>(JLjava/lang/String;Lcz/myskoda/api/bff/v1/ChargingProfileSettingsDto;Ljava/util/List;Ljava/util/List;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;ILkotlin/jvm/internal/g;)V

    .line 1405
    .line 1406
    .line 1407
    move-wide v2, v8

    .line 1408
    const/4 v0, 0x2

    .line 1409
    iput v0, v5, Lo10/l;->e:I

    .line 1410
    .line 1411
    iget-object v1, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1412
    .line 1413
    move-object/from16 v0, v27

    .line 1414
    .line 1415
    invoke-interface/range {v0 .. v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateChargingProfile(Ljava/lang/String;JLcz/myskoda/api/bff/v1/ChargingProfileDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1416
    .line 1417
    .line 1418
    move-result-object v0

    .line 1419
    if-ne v0, v6, :cond_50

    .line 1420
    .line 1421
    :goto_2b
    move-object v0, v6

    .line 1422
    :cond_50
    :goto_2c
    return-object v0

    .line 1423
    :pswitch_b
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1424
    .line 1425
    iget v1, v5, Lo10/l;->e:I

    .line 1426
    .line 1427
    const/4 v2, 0x2

    .line 1428
    const/4 v3, 0x1

    .line 1429
    if-eqz v1, :cond_53

    .line 1430
    .line 1431
    if-eq v1, v3, :cond_52

    .line 1432
    .line 1433
    if-ne v1, v2, :cond_51

    .line 1434
    .line 1435
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1436
    .line 1437
    .line 1438
    move-object/from16 v0, p1

    .line 1439
    .line 1440
    goto/16 :goto_2f

    .line 1441
    .line 1442
    :cond_51
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1443
    .line 1444
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1445
    .line 1446
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1447
    .line 1448
    .line 1449
    throw v0

    .line 1450
    :cond_52
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1451
    .line 1452
    .line 1453
    move-object/from16 v1, p1

    .line 1454
    .line 1455
    goto :goto_2d

    .line 1456
    :cond_53
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1457
    .line 1458
    .line 1459
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1460
    .line 1461
    check-cast v1, Lod0/b0;

    .line 1462
    .line 1463
    iget-object v1, v1, Lod0/b0;->b:Lti0/a;

    .line 1464
    .line 1465
    iput v3, v5, Lo10/l;->e:I

    .line 1466
    .line 1467
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1468
    .line 1469
    .line 1470
    move-result-object v1

    .line 1471
    if-ne v1, v0, :cond_54

    .line 1472
    .line 1473
    goto :goto_2f

    .line 1474
    :cond_54
    :goto_2d
    check-cast v1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1475
    .line 1476
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1477
    .line 1478
    check-cast v3, Lrd0/h;

    .line 1479
    .line 1480
    const-string v4, "<this>"

    .line 1481
    .line 1482
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1483
    .line 1484
    .line 1485
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 1486
    .line 1487
    .line 1488
    move-result v3

    .line 1489
    packed-switch v3, :pswitch_data_1

    .line 1490
    .line 1491
    .line 1492
    new-instance v0, La8/r0;

    .line 1493
    .line 1494
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1495
    .line 1496
    .line 1497
    throw v0

    .line 1498
    :pswitch_c
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1499
    .line 1500
    const-string v4, "HOME_STORAGE_CHARGING"

    .line 1501
    .line 1502
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1503
    .line 1504
    .line 1505
    goto :goto_2e

    .line 1506
    :pswitch_d
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1507
    .line 1508
    const-string v4, "IMMEDIATE_DISCHARGING"

    .line 1509
    .line 1510
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1511
    .line 1512
    .line 1513
    goto :goto_2e

    .line 1514
    :pswitch_e
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1515
    .line 1516
    const-string v4, "ONLY_OWN_CURRENT"

    .line 1517
    .line 1518
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1519
    .line 1520
    .line 1521
    goto :goto_2e

    .line 1522
    :pswitch_f
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1523
    .line 1524
    const-string v4, "PREFERRED_CHARGING_TIMES"

    .line 1525
    .line 1526
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1527
    .line 1528
    .line 1529
    goto :goto_2e

    .line 1530
    :pswitch_10
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1531
    .line 1532
    const-string v4, "TIMER_CHARGING_WITH_CLIMATISATION"

    .line 1533
    .line 1534
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1535
    .line 1536
    .line 1537
    goto :goto_2e

    .line 1538
    :pswitch_11
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1539
    .line 1540
    const-string v4, "TIMER"

    .line 1541
    .line 1542
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1543
    .line 1544
    .line 1545
    goto :goto_2e

    .line 1546
    :pswitch_12
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargeModeDto;

    .line 1547
    .line 1548
    const-string v4, "MANUAL"

    .line 1549
    .line 1550
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargeModeDto;-><init>(Ljava/lang/String;)V

    .line 1551
    .line 1552
    .line 1553
    :goto_2e
    iput v2, v5, Lo10/l;->e:I

    .line 1554
    .line 1555
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1556
    .line 1557
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateChargeMode(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ChargeModeDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1558
    .line 1559
    .line 1560
    move-result-object v1

    .line 1561
    if-ne v1, v0, :cond_55

    .line 1562
    .line 1563
    goto :goto_2f

    .line 1564
    :cond_55
    move-object v0, v1

    .line 1565
    :goto_2f
    return-object v0

    .line 1566
    :pswitch_13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1567
    .line 1568
    iget v1, v5, Lo10/l;->e:I

    .line 1569
    .line 1570
    const/4 v2, 0x2

    .line 1571
    const/4 v3, 0x1

    .line 1572
    if-eqz v1, :cond_58

    .line 1573
    .line 1574
    if-eq v1, v3, :cond_57

    .line 1575
    .line 1576
    if-ne v1, v2, :cond_56

    .line 1577
    .line 1578
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1579
    .line 1580
    .line 1581
    move-object/from16 v0, p1

    .line 1582
    .line 1583
    goto :goto_31

    .line 1584
    :cond_56
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1585
    .line 1586
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1587
    .line 1588
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1589
    .line 1590
    .line 1591
    throw v0

    .line 1592
    :cond_57
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1593
    .line 1594
    .line 1595
    move-object/from16 v1, p1

    .line 1596
    .line 1597
    goto :goto_30

    .line 1598
    :cond_58
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1599
    .line 1600
    .line 1601
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1602
    .line 1603
    check-cast v1, Lod0/b0;

    .line 1604
    .line 1605
    iget-object v1, v1, Lod0/b0;->b:Lti0/a;

    .line 1606
    .line 1607
    iput v3, v5, Lo10/l;->e:I

    .line 1608
    .line 1609
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1610
    .line 1611
    .line 1612
    move-result-object v1

    .line 1613
    if-ne v1, v0, :cond_59

    .line 1614
    .line 1615
    goto :goto_31

    .line 1616
    :cond_59
    :goto_30
    check-cast v1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1617
    .line 1618
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1619
    .line 1620
    check-cast v3, Lqr0/l;

    .line 1621
    .line 1622
    new-instance v4, Lcz/myskoda/api/bff/v1/ChargeLimitDto;

    .line 1623
    .line 1624
    iget v3, v3, Lqr0/l;->d:I

    .line 1625
    .line 1626
    invoke-direct {v4, v3}, Lcz/myskoda/api/bff/v1/ChargeLimitDto;-><init>(I)V

    .line 1627
    .line 1628
    .line 1629
    iput v2, v5, Lo10/l;->e:I

    .line 1630
    .line 1631
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1632
    .line 1633
    invoke-interface {v1, v2, v4, v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateChargeLimit(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ChargeLimitDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1634
    .line 1635
    .line 1636
    move-result-object v1

    .line 1637
    if-ne v1, v0, :cond_5a

    .line 1638
    .line 1639
    goto :goto_31

    .line 1640
    :cond_5a
    move-object v0, v1

    .line 1641
    :goto_31
    return-object v0

    .line 1642
    :pswitch_14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1643
    .line 1644
    iget v1, v5, Lo10/l;->e:I

    .line 1645
    .line 1646
    const/4 v2, 0x2

    .line 1647
    const/4 v3, 0x1

    .line 1648
    if-eqz v1, :cond_5d

    .line 1649
    .line 1650
    if-eq v1, v3, :cond_5c

    .line 1651
    .line 1652
    if-ne v1, v2, :cond_5b

    .line 1653
    .line 1654
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1655
    .line 1656
    .line 1657
    move-object/from16 v0, p1

    .line 1658
    .line 1659
    goto :goto_33

    .line 1660
    :cond_5b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1661
    .line 1662
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1663
    .line 1664
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1665
    .line 1666
    .line 1667
    throw v0

    .line 1668
    :cond_5c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1669
    .line 1670
    .line 1671
    move-object/from16 v1, p1

    .line 1672
    .line 1673
    goto :goto_32

    .line 1674
    :cond_5d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1675
    .line 1676
    .line 1677
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1678
    .line 1679
    check-cast v1, Lod0/b0;

    .line 1680
    .line 1681
    iget-object v1, v1, Lod0/b0;->b:Lti0/a;

    .line 1682
    .line 1683
    iput v3, v5, Lo10/l;->e:I

    .line 1684
    .line 1685
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1686
    .line 1687
    .line 1688
    move-result-object v1

    .line 1689
    if-ne v1, v0, :cond_5e

    .line 1690
    .line 1691
    goto :goto_33

    .line 1692
    :cond_5e
    :goto_32
    check-cast v1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1693
    .line 1694
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1695
    .line 1696
    check-cast v3, Lrd0/g;

    .line 1697
    .line 1698
    invoke-static {v3}, Ljp/qb;->e(Lrd0/g;)Lcz/myskoda/api/bff/v1/ChargingCurrentDto;

    .line 1699
    .line 1700
    .line 1701
    move-result-object v3

    .line 1702
    iput v2, v5, Lo10/l;->e:I

    .line 1703
    .line 1704
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1705
    .line 1706
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateChargingCurrent(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ChargingCurrentDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1707
    .line 1708
    .line 1709
    move-result-object v1

    .line 1710
    if-ne v1, v0, :cond_5f

    .line 1711
    .line 1712
    goto :goto_33

    .line 1713
    :cond_5f
    move-object v0, v1

    .line 1714
    :goto_33
    return-object v0

    .line 1715
    :pswitch_15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1716
    .line 1717
    iget v1, v5, Lo10/l;->e:I

    .line 1718
    .line 1719
    const/4 v2, 0x2

    .line 1720
    const/4 v3, 0x1

    .line 1721
    if-eqz v1, :cond_62

    .line 1722
    .line 1723
    if-eq v1, v3, :cond_61

    .line 1724
    .line 1725
    if-ne v1, v2, :cond_60

    .line 1726
    .line 1727
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1728
    .line 1729
    .line 1730
    move-object/from16 v0, p1

    .line 1731
    .line 1732
    goto :goto_35

    .line 1733
    :cond_60
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1734
    .line 1735
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1736
    .line 1737
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1738
    .line 1739
    .line 1740
    throw v0

    .line 1741
    :cond_61
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1742
    .line 1743
    .line 1744
    move-object/from16 v1, p1

    .line 1745
    .line 1746
    goto :goto_34

    .line 1747
    :cond_62
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1748
    .line 1749
    .line 1750
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1751
    .line 1752
    check-cast v1, Lod0/b0;

    .line 1753
    .line 1754
    iget-object v1, v1, Lod0/b0;->b:Lti0/a;

    .line 1755
    .line 1756
    iput v3, v5, Lo10/l;->e:I

    .line 1757
    .line 1758
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1759
    .line 1760
    .line 1761
    move-result-object v1

    .line 1762
    if-ne v1, v0, :cond_63

    .line 1763
    .line 1764
    goto :goto_35

    .line 1765
    :cond_63
    :goto_34
    check-cast v1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1766
    .line 1767
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1768
    .line 1769
    check-cast v3, Lrd0/g0;

    .line 1770
    .line 1771
    invoke-static {v3}, Ljp/qb;->d(Lrd0/g0;)Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;

    .line 1772
    .line 1773
    .line 1774
    move-result-object v3

    .line 1775
    iput v2, v5, Lo10/l;->e:I

    .line 1776
    .line 1777
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1778
    .line 1779
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateAutoUnlockPlug(Ljava/lang/String;Lcz/myskoda/api/bff/v1/AutoUnlockPlugDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1780
    .line 1781
    .line 1782
    move-result-object v1

    .line 1783
    if-ne v1, v0, :cond_64

    .line 1784
    .line 1785
    goto :goto_35

    .line 1786
    :cond_64
    move-object v0, v1

    .line 1787
    :goto_35
    return-object v0

    .line 1788
    :pswitch_16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1789
    .line 1790
    iget v1, v5, Lo10/l;->e:I

    .line 1791
    .line 1792
    const/4 v2, 0x2

    .line 1793
    const/4 v3, 0x1

    .line 1794
    if-eqz v1, :cond_67

    .line 1795
    .line 1796
    if-eq v1, v3, :cond_66

    .line 1797
    .line 1798
    if-ne v1, v2, :cond_65

    .line 1799
    .line 1800
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1801
    .line 1802
    .line 1803
    move-object/from16 v0, p1

    .line 1804
    .line 1805
    goto :goto_38

    .line 1806
    :cond_65
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1807
    .line 1808
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1809
    .line 1810
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1811
    .line 1812
    .line 1813
    throw v0

    .line 1814
    :cond_66
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1815
    .line 1816
    .line 1817
    move-object/from16 v1, p1

    .line 1818
    .line 1819
    goto :goto_36

    .line 1820
    :cond_67
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1821
    .line 1822
    .line 1823
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1824
    .line 1825
    check-cast v1, Lod0/b0;

    .line 1826
    .line 1827
    iget-object v1, v1, Lod0/b0;->b:Lti0/a;

    .line 1828
    .line 1829
    iput v3, v5, Lo10/l;->e:I

    .line 1830
    .line 1831
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1832
    .line 1833
    .line 1834
    move-result-object v1

    .line 1835
    if-ne v1, v0, :cond_68

    .line 1836
    .line 1837
    goto :goto_38

    .line 1838
    :cond_68
    :goto_36
    check-cast v1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1839
    .line 1840
    iget-object v4, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1841
    .line 1842
    check-cast v4, Lrd0/a;

    .line 1843
    .line 1844
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 1845
    .line 1846
    .line 1847
    move-result v4

    .line 1848
    if-eqz v4, :cond_6a

    .line 1849
    .line 1850
    if-ne v4, v3, :cond_69

    .line 1851
    .line 1852
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargingCareModeDto;

    .line 1853
    .line 1854
    const-string v4, "DEACTIVATED"

    .line 1855
    .line 1856
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargingCareModeDto;-><init>(Ljava/lang/String;)V

    .line 1857
    .line 1858
    .line 1859
    goto :goto_37

    .line 1860
    :cond_69
    new-instance v0, La8/r0;

    .line 1861
    .line 1862
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1863
    .line 1864
    .line 1865
    throw v0

    .line 1866
    :cond_6a
    new-instance v3, Lcz/myskoda/api/bff/v1/ChargingCareModeDto;

    .line 1867
    .line 1868
    const-string v4, "ACTIVATED"

    .line 1869
    .line 1870
    invoke-direct {v3, v4}, Lcz/myskoda/api/bff/v1/ChargingCareModeDto;-><init>(Ljava/lang/String;)V

    .line 1871
    .line 1872
    .line 1873
    :goto_37
    iput v2, v5, Lo10/l;->e:I

    .line 1874
    .line 1875
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1876
    .line 1877
    invoke-interface {v1, v2, v3, v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateCareMode(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ChargingCareModeDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1878
    .line 1879
    .line 1880
    move-result-object v1

    .line 1881
    if-ne v1, v0, :cond_6b

    .line 1882
    .line 1883
    goto :goto_38

    .line 1884
    :cond_6b
    move-object v0, v1

    .line 1885
    :goto_38
    return-object v0

    .line 1886
    :pswitch_17
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1887
    .line 1888
    iget v1, v5, Lo10/l;->e:I

    .line 1889
    .line 1890
    const/4 v2, 0x2

    .line 1891
    const/4 v3, 0x1

    .line 1892
    if-eqz v1, :cond_6e

    .line 1893
    .line 1894
    if-eq v1, v3, :cond_6d

    .line 1895
    .line 1896
    if-ne v1, v2, :cond_6c

    .line 1897
    .line 1898
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1899
    .line 1900
    .line 1901
    move-object/from16 v0, p1

    .line 1902
    .line 1903
    goto :goto_3a

    .line 1904
    :cond_6c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1905
    .line 1906
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1907
    .line 1908
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1909
    .line 1910
    .line 1911
    throw v0

    .line 1912
    :cond_6d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1913
    .line 1914
    .line 1915
    move-object/from16 v1, p1

    .line 1916
    .line 1917
    goto :goto_39

    .line 1918
    :cond_6e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1919
    .line 1920
    .line 1921
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 1922
    .line 1923
    check-cast v1, Lod0/b0;

    .line 1924
    .line 1925
    iget-object v1, v1, Lod0/b0;->b:Lti0/a;

    .line 1926
    .line 1927
    iput v3, v5, Lo10/l;->e:I

    .line 1928
    .line 1929
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1930
    .line 1931
    .line 1932
    move-result-object v1

    .line 1933
    if-ne v1, v0, :cond_6f

    .line 1934
    .line 1935
    goto :goto_3a

    .line 1936
    :cond_6f
    :goto_39
    check-cast v1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 1937
    .line 1938
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 1939
    .line 1940
    check-cast v3, Lrd0/e0;

    .line 1941
    .line 1942
    new-instance v4, Lcz/myskoda/api/bff/v1/CreateChargingProfileRequestDto;

    .line 1943
    .line 1944
    iget-object v6, v3, Lrd0/e0;->a:Ljava/lang/String;

    .line 1945
    .line 1946
    new-instance v7, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 1947
    .line 1948
    iget-wide v8, v3, Lrd0/e0;->b:D

    .line 1949
    .line 1950
    iget-wide v10, v3, Lrd0/e0;->c:D

    .line 1951
    .line 1952
    invoke-direct {v7, v8, v9, v10, v11}, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;-><init>(DD)V

    .line 1953
    .line 1954
    .line 1955
    invoke-direct {v4, v6, v7}, Lcz/myskoda/api/bff/v1/CreateChargingProfileRequestDto;-><init>(Ljava/lang/String;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)V

    .line 1956
    .line 1957
    .line 1958
    iput v2, v5, Lo10/l;->e:I

    .line 1959
    .line 1960
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 1961
    .line 1962
    invoke-interface {v1, v2, v4, v5}, Lcz/myskoda/api/bff/v1/ChargingApi;->createChargingProfile(Ljava/lang/String;Lcz/myskoda/api/bff/v1/CreateChargingProfileRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1963
    .line 1964
    .line 1965
    move-result-object v1

    .line 1966
    if-ne v1, v0, :cond_70

    .line 1967
    .line 1968
    goto :goto_3a

    .line 1969
    :cond_70
    move-object v0, v1

    .line 1970
    :goto_3a
    return-object v0

    .line 1971
    :pswitch_18
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1972
    .line 1973
    iget v1, v5, Lo10/l;->e:I

    .line 1974
    .line 1975
    const/4 v2, 0x2

    .line 1976
    const/4 v3, 0x1

    .line 1977
    if-eqz v1, :cond_73

    .line 1978
    .line 1979
    if-eq v1, v3, :cond_72

    .line 1980
    .line 1981
    if-ne v1, v2, :cond_71

    .line 1982
    .line 1983
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1984
    .line 1985
    .line 1986
    move-object/from16 v0, p1

    .line 1987
    .line 1988
    goto :goto_3c

    .line 1989
    :cond_71
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1990
    .line 1991
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 1992
    .line 1993
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1994
    .line 1995
    .line 1996
    throw v0

    .line 1997
    :cond_72
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1998
    .line 1999
    .line 2000
    move-object/from16 v1, p1

    .line 2001
    .line 2002
    goto :goto_3b

    .line 2003
    :cond_73
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2004
    .line 2005
    .line 2006
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 2007
    .line 2008
    check-cast v1, Lo10/m;

    .line 2009
    .line 2010
    iget-object v1, v1, Lo10/m;->b:Lti0/a;

    .line 2011
    .line 2012
    iput v3, v5, Lo10/l;->e:I

    .line 2013
    .line 2014
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2015
    .line 2016
    .line 2017
    move-result-object v1

    .line 2018
    if-ne v1, v0, :cond_74

    .line 2019
    .line 2020
    goto :goto_3c

    .line 2021
    :cond_74
    :goto_3b
    check-cast v1, Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;

    .line 2022
    .line 2023
    iget-object v3, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 2024
    .line 2025
    check-cast v3, Lqr0/l;

    .line 2026
    .line 2027
    new-instance v4, Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;

    .line 2028
    .line 2029
    iget v3, v3, Lqr0/l;->d:I

    .line 2030
    .line 2031
    invoke-direct {v4, v3}, Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;-><init>(I)V

    .line 2032
    .line 2033
    .line 2034
    iput v2, v5, Lo10/l;->e:I

    .line 2035
    .line 2036
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 2037
    .line 2038
    invoke-interface {v1, v2, v4, v5}, Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;->updateDepartureTimersSettings(Ljava/lang/String;Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2039
    .line 2040
    .line 2041
    move-result-object v1

    .line 2042
    if-ne v1, v0, :cond_75

    .line 2043
    .line 2044
    goto :goto_3c

    .line 2045
    :cond_75
    move-object v0, v1

    .line 2046
    :goto_3c
    return-object v0

    .line 2047
    :pswitch_19
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2048
    .line 2049
    iget v1, v5, Lo10/l;->e:I

    .line 2050
    .line 2051
    const/4 v2, 0x2

    .line 2052
    const/4 v3, 0x1

    .line 2053
    if-eqz v1, :cond_78

    .line 2054
    .line 2055
    if-eq v1, v3, :cond_77

    .line 2056
    .line 2057
    if-ne v1, v2, :cond_76

    .line 2058
    .line 2059
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2060
    .line 2061
    .line 2062
    move-object/from16 v0, p1

    .line 2063
    .line 2064
    goto/16 :goto_44

    .line 2065
    .line 2066
    :cond_76
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2067
    .line 2068
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 2069
    .line 2070
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2071
    .line 2072
    .line 2073
    throw v0

    .line 2074
    :cond_77
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2075
    .line 2076
    .line 2077
    move-object/from16 v1, p1

    .line 2078
    .line 2079
    goto :goto_3d

    .line 2080
    :cond_78
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2081
    .line 2082
    .line 2083
    iget-object v1, v5, Lo10/l;->f:Ljava/lang/Object;

    .line 2084
    .line 2085
    check-cast v1, Lo10/m;

    .line 2086
    .line 2087
    iget-object v1, v1, Lo10/m;->b:Lti0/a;

    .line 2088
    .line 2089
    iput v3, v5, Lo10/l;->e:I

    .line 2090
    .line 2091
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2092
    .line 2093
    .line 2094
    move-result-object v1

    .line 2095
    if-ne v1, v0, :cond_79

    .line 2096
    .line 2097
    goto/16 :goto_44

    .line 2098
    .line 2099
    :cond_79
    :goto_3d
    check-cast v1, Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;

    .line 2100
    .line 2101
    new-instance v4, Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;

    .line 2102
    .line 2103
    iget-object v6, v5, Lo10/l;->h:Ljava/lang/Object;

    .line 2104
    .line 2105
    check-cast v6, Lr10/b;

    .line 2106
    .line 2107
    iget-object v7, v6, Lr10/b;->g:Lao0/c;

    .line 2108
    .line 2109
    iget-wide v9, v6, Lr10/b;->h:J

    .line 2110
    .line 2111
    iget-boolean v8, v6, Lr10/b;->c:Z

    .line 2112
    .line 2113
    iget-boolean v11, v6, Lr10/b;->d:Z

    .line 2114
    .line 2115
    iget-boolean v12, v6, Lr10/b;->b:Z

    .line 2116
    .line 2117
    iget-object v13, v6, Lr10/b;->e:Lqr0/l;

    .line 2118
    .line 2119
    const/16 v22, 0x0

    .line 2120
    .line 2121
    if-eqz v13, :cond_7a

    .line 2122
    .line 2123
    iget v13, v13, Lqr0/l;->d:I

    .line 2124
    .line 2125
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2126
    .line 2127
    .line 2128
    move-result-object v13

    .line 2129
    move-object/from16 v16, v13

    .line 2130
    .line 2131
    goto :goto_3e

    .line 2132
    :cond_7a
    move-object/from16 v16, v22

    .line 2133
    .line 2134
    :goto_3e
    iget-object v6, v6, Lr10/b;->f:Ljava/util/List;

    .line 2135
    .line 2136
    const/16 v13, 0xa

    .line 2137
    .line 2138
    if-eqz v6, :cond_7c

    .line 2139
    .line 2140
    check-cast v6, Ljava/lang/Iterable;

    .line 2141
    .line 2142
    new-instance v14, Ljava/util/ArrayList;

    .line 2143
    .line 2144
    invoke-static {v6, v13}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2145
    .line 2146
    .line 2147
    move-result v15

    .line 2148
    invoke-direct {v14, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 2149
    .line 2150
    .line 2151
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2152
    .line 2153
    .line 2154
    move-result-object v6

    .line 2155
    :goto_3f
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 2156
    .line 2157
    .line 2158
    move-result v15

    .line 2159
    if-eqz v15, :cond_7b

    .line 2160
    .line 2161
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2162
    .line 2163
    .line 2164
    move-result-object v15

    .line 2165
    check-cast v15, Lao0/a;

    .line 2166
    .line 2167
    invoke-static {v15}, Llp/md;->b(Lao0/a;)Lcz/myskoda/api/bff/v1/ChargingTimeDto;

    .line 2168
    .line 2169
    .line 2170
    move-result-object v15

    .line 2171
    invoke-virtual {v14, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2172
    .line 2173
    .line 2174
    goto :goto_3f

    .line 2175
    :cond_7b
    move-object/from16 v17, v14

    .line 2176
    .line 2177
    goto :goto_40

    .line 2178
    :cond_7c
    move-object/from16 v17, v22

    .line 2179
    .line 2180
    :goto_40
    iget-object v6, v7, Lao0/c;->c:Ljava/time/LocalTime;

    .line 2181
    .line 2182
    iget-object v14, v7, Lao0/c;->e:Ljava/util/Set;

    .line 2183
    .line 2184
    iget-object v7, v7, Lao0/c;->d:Lao0/f;

    .line 2185
    .line 2186
    invoke-virtual {v6}, Ljava/time/LocalTime;->toString()Ljava/lang/String;

    .line 2187
    .line 2188
    .line 2189
    move-result-object v6

    .line 2190
    const-string v15, "toString(...)"

    .line 2191
    .line 2192
    invoke-static {v6, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2193
    .line 2194
    .line 2195
    const-string v13, "<this>"

    .line 2196
    .line 2197
    invoke-static {v7, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2198
    .line 2199
    .line 2200
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 2201
    .line 2202
    .line 2203
    move-result v13

    .line 2204
    if-eqz v13, :cond_7e

    .line 2205
    .line 2206
    if-ne v13, v3, :cond_7d

    .line 2207
    .line 2208
    const-string v13, "RECURRING"

    .line 2209
    .line 2210
    goto :goto_41

    .line 2211
    :cond_7d
    new-instance v0, La8/r0;

    .line 2212
    .line 2213
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2214
    .line 2215
    .line 2216
    throw v0

    .line 2217
    :cond_7e
    const-string v13, "ONE_OFF"

    .line 2218
    .line 2219
    :goto_41
    new-instance v23, Lcz/myskoda/api/bff/v1/DepartureTimerDto;

    .line 2220
    .line 2221
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2222
    .line 2223
    .line 2224
    move-result-object v8

    .line 2225
    invoke-static {v11}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2226
    .line 2227
    .line 2228
    move-result-object v11

    .line 2229
    invoke-static {v12}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 2230
    .line 2231
    .line 2232
    move-result-object v12

    .line 2233
    const/16 v20, 0x300

    .line 2234
    .line 2235
    const/16 v21, 0x0

    .line 2236
    .line 2237
    const/16 v18, 0x0

    .line 2238
    .line 2239
    const/16 v19, 0x0

    .line 2240
    .line 2241
    move-object v2, v11

    .line 2242
    move-object v11, v6

    .line 2243
    move-object v6, v14

    .line 2244
    move-object v14, v2

    .line 2245
    move-object v2, v15

    .line 2246
    move-object v15, v12

    .line 2247
    move-object v12, v13

    .line 2248
    move-object v13, v8

    .line 2249
    move-object/from16 v8, v23

    .line 2250
    .line 2251
    invoke-direct/range {v8 .. v21}, Lcz/myskoda/api/bff/v1/DepartureTimerDto;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/String;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    .line 2252
    .line 2253
    .line 2254
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 2255
    .line 2256
    .line 2257
    move-result v7

    .line 2258
    if-eqz v7, :cond_81

    .line 2259
    .line 2260
    if-ne v7, v3, :cond_80

    .line 2261
    .line 2262
    move-object v14, v6

    .line 2263
    check-cast v14, Ljava/lang/Iterable;

    .line 2264
    .line 2265
    new-instance v3, Ljava/util/ArrayList;

    .line 2266
    .line 2267
    const/16 v6, 0xa

    .line 2268
    .line 2269
    invoke-static {v14, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2270
    .line 2271
    .line 2272
    move-result v6

    .line 2273
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 2274
    .line 2275
    .line 2276
    invoke-interface {v14}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2277
    .line 2278
    .line 2279
    move-result-object v6

    .line 2280
    :goto_42
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 2281
    .line 2282
    .line 2283
    move-result v7

    .line 2284
    if-eqz v7, :cond_7f

    .line 2285
    .line 2286
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2287
    .line 2288
    .line 2289
    move-result-object v7

    .line 2290
    check-cast v7, Ljava/time/DayOfWeek;

    .line 2291
    .line 2292
    invoke-virtual {v7}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 2293
    .line 2294
    .line 2295
    move-result-object v7

    .line 2296
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2297
    .line 2298
    .line 2299
    goto :goto_42

    .line 2300
    :cond_7f
    const/16 v35, 0x1ff

    .line 2301
    .line 2302
    const/16 v36, 0x0

    .line 2303
    .line 2304
    const-wide/16 v24, 0x0

    .line 2305
    .line 2306
    const/16 v26, 0x0

    .line 2307
    .line 2308
    const/16 v27, 0x0

    .line 2309
    .line 2310
    const/16 v28, 0x0

    .line 2311
    .line 2312
    const/16 v29, 0x0

    .line 2313
    .line 2314
    const/16 v30, 0x0

    .line 2315
    .line 2316
    const/16 v31, 0x0

    .line 2317
    .line 2318
    const/16 v32, 0x0

    .line 2319
    .line 2320
    const/16 v33, 0x0

    .line 2321
    .line 2322
    move-object/from16 v34, v3

    .line 2323
    .line 2324
    invoke-static/range {v23 .. v36}, Lcz/myskoda/api/bff/v1/DepartureTimerDto;->copy$default(Lcz/myskoda/api/bff/v1/DepartureTimerDto;JLjava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/String;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/DepartureTimerDto;

    .line 2325
    .line 2326
    .line 2327
    move-result-object v3

    .line 2328
    goto :goto_43

    .line 2329
    :cond_80
    new-instance v0, La8/r0;

    .line 2330
    .line 2331
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2332
    .line 2333
    .line 2334
    throw v0

    .line 2335
    :cond_81
    move-object v14, v6

    .line 2336
    check-cast v14, Ljava/lang/Iterable;

    .line 2337
    .line 2338
    invoke-static {v14}, Lmx0/q;->K(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 2339
    .line 2340
    .line 2341
    move-result-object v3

    .line 2342
    check-cast v3, Ljava/time/DayOfWeek;

    .line 2343
    .line 2344
    if-eqz v3, :cond_82

    .line 2345
    .line 2346
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 2347
    .line 2348
    .line 2349
    move-result-object v22

    .line 2350
    :cond_82
    move-object/from16 v33, v22

    .line 2351
    .line 2352
    const/16 v35, 0x2ff

    .line 2353
    .line 2354
    const/16 v36, 0x0

    .line 2355
    .line 2356
    const-wide/16 v24, 0x0

    .line 2357
    .line 2358
    const/16 v26, 0x0

    .line 2359
    .line 2360
    const/16 v27, 0x0

    .line 2361
    .line 2362
    const/16 v28, 0x0

    .line 2363
    .line 2364
    const/16 v29, 0x0

    .line 2365
    .line 2366
    const/16 v30, 0x0

    .line 2367
    .line 2368
    const/16 v31, 0x0

    .line 2369
    .line 2370
    const/16 v32, 0x0

    .line 2371
    .line 2372
    const/16 v34, 0x0

    .line 2373
    .line 2374
    invoke-static/range {v23 .. v36}, Lcz/myskoda/api/bff/v1/DepartureTimerDto;->copy$default(Lcz/myskoda/api/bff/v1/DepartureTimerDto;JLjava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Integer;Ljava/util/List;Ljava/lang/String;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/DepartureTimerDto;

    .line 2375
    .line 2376
    .line 2377
    move-result-object v3

    .line 2378
    :goto_43
    invoke-static {v3}, Ljp/k1;->k(Ljava/lang/Object;)Ljava/util/List;

    .line 2379
    .line 2380
    .line 2381
    move-result-object v3

    .line 2382
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 2383
    .line 2384
    .line 2385
    move-result-object v6

    .line 2386
    invoke-virtual {v6}, Ljava/time/OffsetDateTime;->toString()Ljava/lang/String;

    .line 2387
    .line 2388
    .line 2389
    move-result-object v6

    .line 2390
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2391
    .line 2392
    .line 2393
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2394
    .line 2395
    .line 2396
    move-result-object v2

    .line 2397
    invoke-virtual {v2}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 2398
    .line 2399
    .line 2400
    move-result-object v2

    .line 2401
    invoke-direct {v4, v3, v6, v2}, Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;-><init>(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 2402
    .line 2403
    .line 2404
    const/4 v2, 0x2

    .line 2405
    iput v2, v5, Lo10/l;->e:I

    .line 2406
    .line 2407
    iget-object v2, v5, Lo10/l;->g:Ljava/lang/String;

    .line 2408
    .line 2409
    invoke-interface {v1, v2, v4, v5}, Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;->updateDepartureTimers(Ljava/lang/String;Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2410
    .line 2411
    .line 2412
    move-result-object v1

    .line 2413
    if-ne v1, v0, :cond_83

    .line 2414
    .line 2415
    goto :goto_44

    .line 2416
    :cond_83
    move-object v0, v1

    .line 2417
    :goto_44
    return-object v0

    .line 2418
    nop

    .line 2419
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
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
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
    .end packed-switch
.end method
