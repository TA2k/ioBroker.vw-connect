.class public final synthetic Ltt/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lcom/google/firebase/perf/metrics/AppStartTrace;


# direct methods
.method public synthetic constructor <init>(Lcom/google/firebase/perf/metrics/AppStartTrace;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltt/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltt/a;->e:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    .line 1
    iget v0, p0, Ltt/a;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltt/a;->e:Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->z:Lzt/h;

    .line 9
    .line 10
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "_as"

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lau/x;->o(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iget-wide v1, v1, Lzt/h;->d:J

    .line 24
    .line 25
    invoke-virtual {v0, v1, v2}, Lau/x;->m(J)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    iget-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->o:Lzt/h;

    .line 33
    .line 34
    invoke-virtual {v1, v2}, Lzt/h;->k(Lzt/h;)J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    invoke-virtual {v0, v1, v2}, Lau/x;->n(J)V

    .line 39
    .line 40
    .line 41
    new-instance v1, Ljava/util/ArrayList;

    .line 42
    .line 43
    const/4 v2, 0x3

    .line 44
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 45
    .line 46
    .line 47
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    const-string v3, "_astui"

    .line 52
    .line 53
    invoke-virtual {v2, v3}, Lau/x;->o(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    iget-wide v3, v3, Lzt/h;->d:J

    .line 61
    .line 62
    invoke-virtual {v2, v3, v4}, Lau/x;->m(J)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    iget-object v4, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 70
    .line 71
    invoke-virtual {v3, v4}, Lzt/h;->k(Lzt/h;)J

    .line 72
    .line 73
    .line 74
    move-result-wide v3

    .line 75
    invoke-virtual {v2, v3, v4}, Lau/x;->n(J)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    check-cast v2, Lau/a0;

    .line 83
    .line 84
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    iget-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;

    .line 88
    .line 89
    if-eqz v2, :cond_0

    .line 90
    .line 91
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    const-string v3, "_astfd"

    .line 96
    .line 97
    invoke-virtual {v2, v3}, Lau/x;->o(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    iget-object v3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 101
    .line 102
    iget-wide v3, v3, Lzt/h;->d:J

    .line 103
    .line 104
    invoke-virtual {v2, v3, v4}, Lau/x;->m(J)V

    .line 105
    .line 106
    .line 107
    iget-object v3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->l:Lzt/h;

    .line 108
    .line 109
    iget-object v4, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;

    .line 110
    .line 111
    invoke-virtual {v3, v4}, Lzt/h;->k(Lzt/h;)J

    .line 112
    .line 113
    .line 114
    move-result-wide v3

    .line 115
    invoke-virtual {v2, v3, v4}, Lau/x;->n(J)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v2}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    check-cast v2, Lau/a0;

    .line 123
    .line 124
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    const-string v3, "_asti"

    .line 132
    .line 133
    invoke-virtual {v2, v3}, Lau/x;->o(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    iget-object v3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;

    .line 137
    .line 138
    iget-wide v3, v3, Lzt/h;->d:J

    .line 139
    .line 140
    invoke-virtual {v2, v3, v4}, Lau/x;->m(J)V

    .line 141
    .line 142
    .line 143
    iget-object v3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->n:Lzt/h;

    .line 144
    .line 145
    iget-object v4, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->o:Lzt/h;

    .line 146
    .line 147
    invoke-virtual {v3, v4}, Lzt/h;->k(Lzt/h;)J

    .line 148
    .line 149
    .line 150
    move-result-wide v3

    .line 151
    invoke-virtual {v2, v3, v4}, Lau/x;->n(J)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v2}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    check-cast v2, Lau/a0;

    .line 159
    .line 160
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    :cond_0
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 164
    .line 165
    .line 166
    iget-object v2, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 167
    .line 168
    check-cast v2, Lau/a0;

    .line 169
    .line 170
    invoke-static {v2, v1}, Lau/a0;->v(Lau/a0;Ljava/util/ArrayList;)V

    .line 171
    .line 172
    .line 173
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->u:Lwt/a;

    .line 174
    .line 175
    invoke-virtual {v1}, Lwt/a;->h()Lau/w;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 180
    .line 181
    .line 182
    iget-object v2, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 183
    .line 184
    check-cast v2, Lau/a0;

    .line 185
    .line 186
    invoke-static {v2, v1}, Lau/a0;->x(Lau/a0;Lau/w;)V

    .line 187
    .line 188
    .line 189
    iget-object p0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->e:Lyt/h;

    .line 190
    .line 191
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    check-cast v0, Lau/a0;

    .line 196
    .line 197
    sget-object v1, Lau/i;->h:Lau/i;

    .line 198
    .line 199
    invoke-virtual {p0, v0, v1}, Lyt/h;->c(Lau/a0;Lau/i;)V

    .line 200
    .line 201
    .line 202
    return-void

    .line 203
    :pswitch_0
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->g:Lau/x;

    .line 204
    .line 205
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->s:Lzt/h;

    .line 206
    .line 207
    if-eqz v1, :cond_1

    .line 208
    .line 209
    goto :goto_0

    .line 210
    :cond_1
    new-instance v1, Lzt/h;

    .line 211
    .line 212
    invoke-direct {v1}, Lzt/h;-><init>()V

    .line 213
    .line 214
    .line 215
    iput-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->s:Lzt/h;

    .line 216
    .line 217
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    const-string v2, "_experiment_preDrawFoQ"

    .line 222
    .line 223
    invoke-virtual {v1, v2}, Lau/x;->o(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 227
    .line 228
    .line 229
    move-result-object v2

    .line 230
    iget-wide v2, v2, Lzt/h;->d:J

    .line 231
    .line 232
    invoke-virtual {v1, v2, v3}, Lau/x;->m(J)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    iget-object v3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->s:Lzt/h;

    .line 240
    .line 241
    invoke-virtual {v2, v3}, Lzt/h;->k(Lzt/h;)J

    .line 242
    .line 243
    .line 244
    move-result-wide v2

    .line 245
    invoke-virtual {v1, v2, v3}, Lau/x;->n(J)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v1}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    check-cast v1, Lau/a0;

    .line 253
    .line 254
    invoke-virtual {v0, v1}, Lau/x;->k(Lau/a0;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {p0, v0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->d(Lau/x;)V

    .line 258
    .line 259
    .line 260
    :goto_0
    return-void

    .line 261
    :pswitch_1
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->g:Lau/x;

    .line 262
    .line 263
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->r:Lzt/h;

    .line 264
    .line 265
    if-eqz v1, :cond_2

    .line 266
    .line 267
    goto :goto_1

    .line 268
    :cond_2
    new-instance v1, Lzt/h;

    .line 269
    .line 270
    invoke-direct {v1}, Lzt/h;-><init>()V

    .line 271
    .line 272
    .line 273
    iput-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->r:Lzt/h;

    .line 274
    .line 275
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    iget-wide v1, v1, Lzt/h;->d:J

    .line 280
    .line 281
    invoke-virtual {v0, v1, v2}, Lau/x;->m(J)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    iget-object v2, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->r:Lzt/h;

    .line 289
    .line 290
    invoke-virtual {v1, v2}, Lzt/h;->k(Lzt/h;)J

    .line 291
    .line 292
    .line 293
    move-result-wide v1

    .line 294
    invoke-virtual {v0, v1, v2}, Lau/x;->n(J)V

    .line 295
    .line 296
    .line 297
    invoke-virtual {p0, v0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->d(Lau/x;)V

    .line 298
    .line 299
    .line 300
    :goto_1
    return-void

    .line 301
    :pswitch_2
    iget-object v0, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->g:Lau/x;

    .line 302
    .line 303
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->t:Lzt/h;

    .line 304
    .line 305
    if-eqz v1, :cond_3

    .line 306
    .line 307
    goto/16 :goto_3

    .line 308
    .line 309
    :cond_3
    new-instance v1, Lzt/h;

    .line 310
    .line 311
    invoke-direct {v1}, Lzt/h;-><init>()V

    .line 312
    .line 313
    .line 314
    iput-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->t:Lzt/h;

    .line 315
    .line 316
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 317
    .line 318
    .line 319
    move-result-object v1

    .line 320
    const-string v2, "_experiment_onDrawFoQ"

    .line 321
    .line 322
    invoke-virtual {v1, v2}, Lau/x;->o(Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    iget-wide v2, v2, Lzt/h;->d:J

    .line 330
    .line 331
    invoke-virtual {v1, v2, v3}, Lau/x;->m(J)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 335
    .line 336
    .line 337
    move-result-object v2

    .line 338
    iget-object v3, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->t:Lzt/h;

    .line 339
    .line 340
    invoke-virtual {v2, v3}, Lzt/h;->k(Lzt/h;)J

    .line 341
    .line 342
    .line 343
    move-result-wide v2

    .line 344
    invoke-virtual {v1, v2, v3}, Lau/x;->n(J)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v1}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 348
    .line 349
    .line 350
    move-result-object v1

    .line 351
    check-cast v1, Lau/a0;

    .line 352
    .line 353
    invoke-virtual {v0, v1}, Lau/x;->k(Lau/a0;)V

    .line 354
    .line 355
    .line 356
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->j:Lzt/h;

    .line 357
    .line 358
    if-eqz v1, :cond_4

    .line 359
    .line 360
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 361
    .line 362
    .line 363
    move-result-object v1

    .line 364
    const-string v2, "_experiment_procStart_to_classLoad"

    .line 365
    .line 366
    invoke-virtual {v1, v2}, Lau/x;->o(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 370
    .line 371
    .line 372
    move-result-object v2

    .line 373
    iget-wide v2, v2, Lzt/h;->d:J

    .line 374
    .line 375
    invoke-virtual {v1, v2, v3}, Lau/x;->m(J)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->b()Lzt/h;

    .line 379
    .line 380
    .line 381
    move-result-object v2

    .line 382
    invoke-virtual {p0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->a()Lzt/h;

    .line 383
    .line 384
    .line 385
    move-result-object v3

    .line 386
    invoke-virtual {v2, v3}, Lzt/h;->k(Lzt/h;)J

    .line 387
    .line 388
    .line 389
    move-result-wide v2

    .line 390
    invoke-virtual {v1, v2, v3}, Lau/x;->n(J)V

    .line 391
    .line 392
    .line 393
    invoke-virtual {v1}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    check-cast v1, Lau/a0;

    .line 398
    .line 399
    invoke-virtual {v0, v1}, Lau/x;->k(Lau/a0;)V

    .line 400
    .line 401
    .line 402
    :cond_4
    iget-boolean v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->y:Z

    .line 403
    .line 404
    if-eqz v1, :cond_5

    .line 405
    .line 406
    const-string v1, "true"

    .line 407
    .line 408
    goto :goto_2

    .line 409
    :cond_5
    const-string v1, "false"

    .line 410
    .line 411
    :goto_2
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 412
    .line 413
    .line 414
    iget-object v2, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 415
    .line 416
    check-cast v2, Lau/a0;

    .line 417
    .line 418
    invoke-static {v2}, Lau/a0;->w(Lau/a0;)Lcom/google/protobuf/i0;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    const-string v3, "systemDeterminedForeground"

    .line 423
    .line 424
    invoke-virtual {v2, v3, v1}, Lcom/google/protobuf/i0;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    iget v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->w:I

    .line 428
    .line 429
    int-to-long v1, v1

    .line 430
    const-string v3, "onDrawCount"

    .line 431
    .line 432
    invoke-virtual {v0, v1, v2, v3}, Lau/x;->l(JLjava/lang/String;)V

    .line 433
    .line 434
    .line 435
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/AppStartTrace;->u:Lwt/a;

    .line 436
    .line 437
    invoke-virtual {v1}, Lwt/a;->h()Lau/w;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 442
    .line 443
    .line 444
    iget-object v2, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 445
    .line 446
    check-cast v2, Lau/a0;

    .line 447
    .line 448
    invoke-static {v2, v1}, Lau/a0;->x(Lau/a0;Lau/w;)V

    .line 449
    .line 450
    .line 451
    invoke-virtual {p0, v0}, Lcom/google/firebase/perf/metrics/AppStartTrace;->d(Lau/x;)V

    .line 452
    .line 453
    .line 454
    :goto_3
    return-void

    .line 455
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
