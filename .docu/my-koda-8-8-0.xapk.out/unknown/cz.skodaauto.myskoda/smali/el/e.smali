.class public final synthetic Lel/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ldi/l;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ldi/l;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lel/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lel/e;->e:Ldi/l;

    .line 4
    .line 5
    iput-object p2, p0, Lel/e;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lel/e;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v3

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    move-object v9, p1

    .line 26
    check-cast v9, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_6

    .line 33
    .line 34
    const p1, 0x7f120bea

    .line 35
    .line 36
    .line 37
    invoke-static {v9, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    iget-object p1, p0, Lel/e;->e:Ldi/l;

    .line 42
    .line 43
    iget-boolean p2, p1, Ldi/l;->g:Z

    .line 44
    .line 45
    iget-boolean v0, p1, Ldi/l;->e:Z

    .line 46
    .line 47
    iget-object v1, p1, Ldi/l;->f:Ljava/lang/String;

    .line 48
    .line 49
    const-string v2, " "

    .line 50
    .line 51
    if-eqz p2, :cond_1

    .line 52
    .line 53
    const p1, -0xe931da1

    .line 54
    .line 55
    .line 56
    invoke-virtual {v9, p1}, Ll2/t;->Y(I)V

    .line 57
    .line 58
    .line 59
    const p1, 0x7f120c11

    .line 60
    .line 61
    .line 62
    invoke-static {v9, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    new-instance p2, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-virtual {v9, v3}, Ll2/t;->q(Z)V

    .line 85
    .line 86
    .line 87
    :goto_1
    move-object v5, p1

    .line 88
    goto :goto_2

    .line 89
    :cond_1
    if-eqz v0, :cond_2

    .line 90
    .line 91
    const p1, -0xe8fe748

    .line 92
    .line 93
    .line 94
    invoke-virtual {v9, p1}, Ll2/t;->Y(I)V

    .line 95
    .line 96
    .line 97
    const p1, 0x7f120c10

    .line 98
    .line 99
    .line 100
    invoke-static {v9, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    new-instance p2, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    invoke-virtual {v9, v3}, Ll2/t;->q(Z)V

    .line 123
    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_2
    const p2, -0xe8d34af

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, p2}, Ll2/t;->Y(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v9, v3}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    iget-object p1, p1, Ldi/l;->d:Ljava/lang/String;

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :goto_2
    if-eqz v0, :cond_3

    .line 139
    .line 140
    const p1, 0x7f080348

    .line 141
    .line 142
    .line 143
    :goto_3
    move v7, p1

    .line 144
    goto :goto_4

    .line 145
    :cond_3
    const p1, 0x7f08033b

    .line 146
    .line 147
    .line 148
    goto :goto_3

    .line 149
    :goto_4
    iget-object p0, p0, Lel/e;->f:Lay0/k;

    .line 150
    .line 151
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result p1

    .line 155
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p2

    .line 159
    if-nez p1, :cond_4

    .line 160
    .line 161
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 162
    .line 163
    if-ne p2, p1, :cond_5

    .line 164
    .line 165
    :cond_4
    new-instance p2, Le41/b;

    .line 166
    .line 167
    const/4 p1, 0x4

    .line 168
    invoke-direct {p2, p1, p0}, Le41/b;-><init>(ILay0/k;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v9, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    :cond_5
    move-object v8, p2

    .line 175
    check-cast v8, Lay0/a;

    .line 176
    .line 177
    const/16 v10, 0x180

    .line 178
    .line 179
    const/4 v11, 0x0

    .line 180
    const-string v6, "wallbox_software_update"

    .line 181
    .line 182
    invoke-static/range {v4 .. v11}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 183
    .line 184
    .line 185
    goto :goto_5

    .line 186
    :cond_6
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 187
    .line 188
    .line 189
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object p0

    .line 192
    :pswitch_0
    and-int/lit8 v0, p2, 0x3

    .line 193
    .line 194
    const/4 v1, 0x2

    .line 195
    const/4 v2, 0x1

    .line 196
    const/4 v3, 0x0

    .line 197
    if-eq v0, v1, :cond_7

    .line 198
    .line 199
    move v0, v2

    .line 200
    goto :goto_6

    .line 201
    :cond_7
    move v0, v3

    .line 202
    :goto_6
    and-int/2addr p2, v2

    .line 203
    move-object v9, p1

    .line 204
    check-cast v9, Ll2/t;

    .line 205
    .line 206
    invoke-virtual {v9, p2, v0}, Ll2/t;->O(IZ)Z

    .line 207
    .line 208
    .line 209
    move-result p1

    .line 210
    if-eqz p1, :cond_b

    .line 211
    .line 212
    const p1, 0x7f120be4

    .line 213
    .line 214
    .line 215
    invoke-static {v9, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v4

    .line 219
    iget-object p1, p0, Lel/e;->e:Ldi/l;

    .line 220
    .line 221
    iget-boolean p1, p1, Ldi/l;->a:Z

    .line 222
    .line 223
    if-eqz p1, :cond_8

    .line 224
    .line 225
    const p1, -0x353626b6    # -6614181.0f

    .line 226
    .line 227
    .line 228
    const p2, 0x7f120be3

    .line 229
    .line 230
    .line 231
    :goto_7
    invoke-static {p1, p2, v9, v9, v3}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    move-object v5, p1

    .line 236
    goto :goto_8

    .line 237
    :cond_8
    const p1, -0x35342af7    # -6679172.5f

    .line 238
    .line 239
    .line 240
    const p2, 0x7f120be2

    .line 241
    .line 242
    .line 243
    goto :goto_7

    .line 244
    :goto_8
    iget-object p0, p0, Lel/e;->f:Lay0/k;

    .line 245
    .line 246
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result p1

    .line 250
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p2

    .line 254
    if-nez p1, :cond_9

    .line 255
    .line 256
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 257
    .line 258
    if-ne p2, p1, :cond_a

    .line 259
    .line 260
    :cond_9
    new-instance p2, Le41/b;

    .line 261
    .line 262
    const/4 p1, 0x1

    .line 263
    invoke-direct {p2, p1, p0}, Le41/b;-><init>(ILay0/k;)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v9, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    :cond_a
    move-object v8, p2

    .line 270
    check-cast v8, Lay0/a;

    .line 271
    .line 272
    const/16 v10, 0x180

    .line 273
    .line 274
    const/16 v11, 0x8

    .line 275
    .line 276
    const-string v6, "wallbox_auth_mode_status"

    .line 277
    .line 278
    const/4 v7, 0x0

    .line 279
    invoke-static/range {v4 .. v11}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 280
    .line 281
    .line 282
    goto :goto_9

    .line 283
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 284
    .line 285
    .line 286
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    return-object p0

    .line 289
    :pswitch_1
    and-int/lit8 v0, p2, 0x3

    .line 290
    .line 291
    const/4 v1, 0x2

    .line 292
    const/4 v2, 0x1

    .line 293
    if-eq v0, v1, :cond_c

    .line 294
    .line 295
    move v0, v2

    .line 296
    goto :goto_a

    .line 297
    :cond_c
    const/4 v0, 0x0

    .line 298
    :goto_a
    and-int/2addr p2, v2

    .line 299
    move-object v6, p1

    .line 300
    check-cast v6, Ll2/t;

    .line 301
    .line 302
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 303
    .line 304
    .line 305
    move-result p1

    .line 306
    if-eqz p1, :cond_10

    .line 307
    .line 308
    const p1, 0x7f120bee

    .line 309
    .line 310
    .line 311
    invoke-static {v6, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    iget-object p1, p0, Lel/e;->e:Ldi/l;

    .line 316
    .line 317
    iget-object p1, p1, Ldi/l;->h:Ljava/lang/String;

    .line 318
    .line 319
    if-nez p1, :cond_d

    .line 320
    .line 321
    const-string p1, ""

    .line 322
    .line 323
    :cond_d
    move-object v2, p1

    .line 324
    iget-object p0, p0, Lel/e;->f:Lay0/k;

    .line 325
    .line 326
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result p1

    .line 330
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object p2

    .line 334
    if-nez p1, :cond_e

    .line 335
    .line 336
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 337
    .line 338
    if-ne p2, p1, :cond_f

    .line 339
    .line 340
    :cond_e
    new-instance p2, Le41/b;

    .line 341
    .line 342
    const/4 p1, 0x5

    .line 343
    invoke-direct {p2, p1, p0}, Le41/b;-><init>(ILay0/k;)V

    .line 344
    .line 345
    .line 346
    invoke-virtual {v6, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    :cond_f
    move-object v5, p2

    .line 350
    check-cast v5, Lay0/a;

    .line 351
    .line 352
    const/16 v7, 0x180

    .line 353
    .line 354
    const/16 v8, 0x8

    .line 355
    .line 356
    const-string v3, "wallbox_location"

    .line 357
    .line 358
    const/4 v4, 0x0

    .line 359
    invoke-static/range {v1 .. v8}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 360
    .line 361
    .line 362
    goto :goto_b

    .line 363
    :cond_10
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 364
    .line 365
    .line 366
    :goto_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 367
    .line 368
    return-object p0

    .line 369
    :pswitch_2
    and-int/lit8 v0, p2, 0x3

    .line 370
    .line 371
    const/4 v1, 0x2

    .line 372
    const/4 v2, 0x1

    .line 373
    if-eq v0, v1, :cond_11

    .line 374
    .line 375
    move v0, v2

    .line 376
    goto :goto_c

    .line 377
    :cond_11
    const/4 v0, 0x0

    .line 378
    :goto_c
    and-int/2addr p2, v2

    .line 379
    move-object v6, p1

    .line 380
    check-cast v6, Ll2/t;

    .line 381
    .line 382
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 383
    .line 384
    .line 385
    move-result p1

    .line 386
    if-eqz p1, :cond_14

    .line 387
    .line 388
    const p1, 0x7f120c3f

    .line 389
    .line 390
    .line 391
    invoke-static {v6, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 392
    .line 393
    .line 394
    move-result-object v1

    .line 395
    iget-object p1, p0, Lel/e;->e:Ldi/l;

    .line 396
    .line 397
    iget-object v2, p1, Ldi/l;->c:Ljava/lang/String;

    .line 398
    .line 399
    iget-object p0, p0, Lel/e;->f:Lay0/k;

    .line 400
    .line 401
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 402
    .line 403
    .line 404
    move-result p1

    .line 405
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    move-result-object p2

    .line 409
    if-nez p1, :cond_12

    .line 410
    .line 411
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 412
    .line 413
    if-ne p2, p1, :cond_13

    .line 414
    .line 415
    :cond_12
    new-instance p2, Le41/b;

    .line 416
    .line 417
    const/4 p1, 0x3

    .line 418
    invoke-direct {p2, p1, p0}, Le41/b;-><init>(ILay0/k;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v6, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 422
    .line 423
    .line 424
    :cond_13
    move-object v5, p2

    .line 425
    check-cast v5, Lay0/a;

    .line 426
    .line 427
    const/16 v7, 0x180

    .line 428
    .line 429
    const/16 v8, 0x8

    .line 430
    .line 431
    const-string v3, "wallbox_name"

    .line 432
    .line 433
    const/4 v4, 0x0

    .line 434
    invoke-static/range {v1 .. v8}, Lel/b;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILay0/a;Ll2/o;II)V

    .line 435
    .line 436
    .line 437
    goto :goto_d

    .line 438
    :cond_14
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 439
    .line 440
    .line 441
    :goto_d
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 442
    .line 443
    return-object p0

    .line 444
    nop

    .line 445
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
