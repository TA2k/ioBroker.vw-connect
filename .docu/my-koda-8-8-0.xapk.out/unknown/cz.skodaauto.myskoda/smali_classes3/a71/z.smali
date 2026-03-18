.class public final synthetic La71/z;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, La71/z;->d:I

    .line 2
    .line 3
    move-object v0, p4

    .line 4
    move-object p4, p2

    .line 5
    move p2, p6

    .line 6
    move-object p6, p5

    .line 7
    move-object p5, v0

    .line 8
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, La71/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lc20/c;

    .line 9
    .line 10
    check-cast p0, La20/a;

    .line 11
    .line 12
    iget-object p0, p0, La20/a;->a:Lwe0/a;

    .line 13
    .line 14
    check-cast p0, Lwe0/c;

    .line 15
    .line 16
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lc00/k1;

    .line 28
    .line 29
    iget-object p0, p0, Lc00/k1;->B:Llb0/c0;

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    invoke-virtual {p0, v0}, Llb0/c0;->a(Lmb0/h;)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lc00/h;

    .line 41
    .line 42
    iget-object p0, p0, Lc00/h;->z:Llb0/c0;

    .line 43
    .line 44
    const/4 v0, 0x0

    .line 45
    invoke-virtual {p0, v0}, Llb0/c0;->a(Lmb0/h;)V

    .line 46
    .line 47
    .line 48
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 54
    .line 55
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->stopCloseWindows()V

    .line 56
    .line 57
    .line 58
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 64
    .line 65
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->startCloseWindows()V

    .line 66
    .line 67
    .line 68
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    return-object p0

    .line 71
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 74
    .line 75
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->closeRPAModule()V

    .line 76
    .line 77
    .line 78
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 84
    .line 85
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->closeRPAModule()V

    .line 86
    .line 87
    .line 88
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    return-object p0

    .line 91
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 94
    .line 95
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->closeRPAModule()V

    .line 96
    .line 97
    .line 98
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 104
    .line 105
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->closeRPAModule()V

    .line 106
    .line 107
    .line 108
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast p0, La60/j;

    .line 114
    .line 115
    iget-object p0, p0, La60/j;->h:Ltr0/b;

    .line 116
    .line 117
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, La60/e;

    .line 126
    .line 127
    iget-object p0, p0, La60/e;->l:Ltr0/b;

    .line 128
    .line 129
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p0, La60/e;

    .line 138
    .line 139
    iget-object p0, p0, La60/e;->l:Ltr0/b;

    .line 140
    .line 141
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    return-object p0

    .line 147
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast p0, La50/j;

    .line 150
    .line 151
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    new-instance v1, La50/e;

    .line 159
    .line 160
    const/4 v2, 0x2

    .line 161
    const/4 v3, 0x0

    .line 162
    invoke-direct {v1, p0, v3, v2}, La50/e;-><init>(La50/j;Lkotlin/coroutines/Continuation;I)V

    .line 163
    .line 164
    .line 165
    const/4 p0, 0x3

    .line 166
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 167
    .line 168
    .line 169
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    return-object p0

    .line 172
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast p0, La10/d;

    .line 175
    .line 176
    iget-object p0, p0, La10/d;->k:Lcf0/h;

    .line 177
    .line 178
    const/4 v0, 0x1

    .line 179
    iget-object p0, p0, Lcf0/h;->a:Laf0/a;

    .line 180
    .line 181
    iput-boolean v0, p0, Laf0/a;->a:Z

    .line 182
    .line 183
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    return-object p0

    .line 186
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 187
    .line 188
    check-cast p0, La10/d;

    .line 189
    .line 190
    iget-object p0, p0, La10/d;->k:Lcf0/h;

    .line 191
    .line 192
    const/4 v0, 0x0

    .line 193
    iget-object p0, p0, Lcf0/h;->a:Laf0/a;

    .line 194
    .line 195
    iput-boolean v0, p0, Laf0/a;->a:Z

    .line 196
    .line 197
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 198
    .line 199
    return-object p0

    .line 200
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast p0, La10/d;

    .line 203
    .line 204
    iget-object p0, p0, La10/d;->j:Ltr0/b;

    .line 205
    .line 206
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    return-object p0

    .line 212
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast p0, La10/d;

    .line 215
    .line 216
    iget-object p0, p0, La10/d;->i:Lz00/h;

    .line 217
    .line 218
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 222
    .line 223
    return-object p0

    .line 224
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast p0, La10/d;

    .line 227
    .line 228
    iget-object p0, p0, La10/d;->h:Lz00/e;

    .line 229
    .line 230
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 234
    .line 235
    return-object p0

    .line 236
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 237
    .line 238
    check-cast p0, Lb/h0;

    .line 239
    .line 240
    invoke-virtual {p0}, Lb/h0;->e()V

    .line 241
    .line 242
    .line 243
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 244
    .line 245
    return-object p0

    .line 246
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast p0, Lb/h0;

    .line 249
    .line 250
    invoke-virtual {p0}, Lb/h0;->e()V

    .line 251
    .line 252
    .line 253
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 254
    .line 255
    return-object p0

    .line 256
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p0, Lzi0/f;

    .line 259
    .line 260
    iget-object p0, p0, Lzi0/f;->i:Lwi0/q;

    .line 261
    .line 262
    sget-object v0, Lyi0/d;->f:Lyi0/d;

    .line 263
    .line 264
    invoke-virtual {p0, v0}, Lwi0/q;->a(Lyi0/d;)V

    .line 265
    .line 266
    .line 267
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    return-object p0

    .line 270
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 271
    .line 272
    check-cast p0, Lzi0/f;

    .line 273
    .line 274
    iget-object p0, p0, Lzi0/f;->i:Lwi0/q;

    .line 275
    .line 276
    sget-object v0, Lyi0/d;->e:Lyi0/d;

    .line 277
    .line 278
    invoke-virtual {p0, v0}, Lwi0/q;->a(Lyi0/d;)V

    .line 279
    .line 280
    .line 281
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 282
    .line 283
    return-object p0

    .line 284
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast p0, Lzi0/f;

    .line 287
    .line 288
    iget-object p0, p0, Lzi0/f;->i:Lwi0/q;

    .line 289
    .line 290
    sget-object v0, Lyi0/d;->d:Lyi0/d;

    .line 291
    .line 292
    invoke-virtual {p0, v0}, Lwi0/q;->a(Lyi0/d;)V

    .line 293
    .line 294
    .line 295
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    return-object p0

    .line 298
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast p0, Lzi0/d;

    .line 301
    .line 302
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 303
    .line 304
    .line 305
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    new-instance v1, Lzi0/a;

    .line 310
    .line 311
    const/4 v2, 0x3

    .line 312
    const/4 v3, 0x0

    .line 313
    invoke-direct {v1, p0, v3, v2}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 314
    .line 315
    .line 316
    const/4 p0, 0x3

    .line 317
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 318
    .line 319
    .line 320
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 321
    .line 322
    return-object p0

    .line 323
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 324
    .line 325
    check-cast p0, Lzi0/d;

    .line 326
    .line 327
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 328
    .line 329
    .line 330
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    new-instance v1, Lzi0/a;

    .line 335
    .line 336
    const/4 v2, 0x2

    .line 337
    const/4 v3, 0x0

    .line 338
    invoke-direct {v1, p0, v3, v2}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 339
    .line 340
    .line 341
    const/4 p0, 0x3

    .line 342
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 343
    .line 344
    .line 345
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 346
    .line 347
    return-object p0

    .line 348
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 351
    .line 352
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;->stopCorrectionMoveForward()V

    .line 353
    .line 354
    .line 355
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 356
    .line 357
    return-object p0

    .line 358
    :pswitch_19
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 359
    .line 360
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 361
    .line 362
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;->startCorrectionMoveForward()V

    .line 363
    .line 364
    .line 365
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    return-object p0

    .line 368
    :pswitch_1a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 369
    .line 370
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 371
    .line 372
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;->stopCorrectionMoveBackward()V

    .line 373
    .line 374
    .line 375
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 376
    .line 377
    return-object p0

    .line 378
    :pswitch_1b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 379
    .line 380
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 381
    .line 382
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;->startCorrectionMoveBackward()V

    .line 383
    .line 384
    .line 385
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 386
    .line 387
    return-object p0

    .line 388
    :pswitch_1c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 391
    .line 392
    invoke-interface {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;->stopParking()V

    .line 393
    .line 394
    .line 395
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 396
    .line 397
    return-object p0

    .line 398
    nop

    .line 399
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
