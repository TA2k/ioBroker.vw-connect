.class public final synthetic Lxk0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lxk0/g0;->d:I

    iput-object p3, p0, Lxk0/g0;->f:Ljava/lang/Object;

    iput-object p4, p0, Lxk0/g0;->g:Ljava/lang/Object;

    iput-object p5, p0, Lxk0/g0;->h:Ljava/lang/Object;

    iput p1, p0, Lxk0/g0;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;II)V
    .locals 0

    .line 2
    iput p5, p0, Lxk0/g0;->d:I

    iput-object p1, p0, Lxk0/g0;->f:Ljava/lang/Object;

    iput-object p2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    iput-object p3, p0, Lxk0/g0;->g:Ljava/lang/Object;

    iput p4, p0, Lxk0/g0;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lza0/q;Ly6/q;Ljava/lang/String;I)V
    .locals 1

    .line 3
    const/16 v0, 0xd

    iput v0, p0, Lxk0/g0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/g0;->g:Ljava/lang/Object;

    iput-object p2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    iput-object p3, p0, Lxk0/g0;->f:Ljava/lang/Object;

    iput p4, p0, Lxk0/g0;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lxk0/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Landroid/content/Intent;

    .line 9
    .line 10
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lx2/s;

    .line 13
    .line 14
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lt2/b;

    .line 17
    .line 18
    check-cast p1, Ll2/o;

    .line 19
    .line 20
    check-cast p2, Ljava/lang/Integer;

    .line 21
    .line 22
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    iget p0, p0, Lxk0/g0;->e:I

    .line 26
    .line 27
    or-int/lit8 p0, p0, 0x1

    .line 28
    .line 29
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-static {v0, v1, v2, p1, p0}, Lzb/b;->k(Landroid/content/Intent;Lx2/s;Lt2/b;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    iget-object v0, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lza0/q;

    .line 42
    .line 43
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v1, Ly6/q;

    .line 46
    .line 47
    iget-object v2, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v2, Ljava/lang/String;

    .line 50
    .line 51
    check-cast p1, Ll2/o;

    .line 52
    .line 53
    check-cast p2, Ljava/lang/Integer;

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 56
    .line 57
    .line 58
    iget p0, p0, Lxk0/g0;->e:I

    .line 59
    .line 60
    or-int/lit8 p0, p0, 0x1

    .line 61
    .line 62
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    invoke-virtual {v0, v1, v2, p1, p0}, Lza0/q;->n(Ly6/q;Ljava/lang/String;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :pswitch_1
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Ly70/w1;

    .line 73
    .line 74
    iget-object v1, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v1, Lay0/a;

    .line 77
    .line 78
    iget-object v2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v2, Lay0/a;

    .line 81
    .line 82
    check-cast p1, Ll2/o;

    .line 83
    .line 84
    check-cast p2, Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 87
    .line 88
    .line 89
    iget p0, p0, Lxk0/g0;->e:I

    .line 90
    .line 91
    or-int/lit8 p0, p0, 0x1

    .line 92
    .line 93
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    invoke-static {v0, v1, v2, p1, p0}, Lz70/l;->B(Ly70/w1;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 98
    .line 99
    .line 100
    goto :goto_0

    .line 101
    :pswitch_2
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v0, Ly70/h0;

    .line 104
    .line 105
    iget-object v1, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v1, Lay0/k;

    .line 108
    .line 109
    iget-object v2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v2, Lay0/k;

    .line 112
    .line 113
    check-cast p1, Ll2/o;

    .line 114
    .line 115
    check-cast p2, Ljava/lang/Integer;

    .line 116
    .line 117
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    iget p0, p0, Lxk0/g0;->e:I

    .line 121
    .line 122
    or-int/lit8 p0, p0, 0x1

    .line 123
    .line 124
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    invoke-static {v0, v1, v2, p1, p0}, Lz70/s;->a(Ly70/h0;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 129
    .line 130
    .line 131
    goto :goto_0

    .line 132
    :pswitch_3
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v0, Ly70/f0;

    .line 135
    .line 136
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v1, Lx2/s;

    .line 139
    .line 140
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v2, Lay0/k;

    .line 143
    .line 144
    check-cast p1, Ll2/o;

    .line 145
    .line 146
    check-cast p2, Ljava/lang/Integer;

    .line 147
    .line 148
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    iget p0, p0, Lxk0/g0;->e:I

    .line 152
    .line 153
    or-int/lit8 p0, p0, 0x1

    .line 154
    .line 155
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    invoke-static {v0, v1, v2, p1, p0}, Lz70/l;->C(Ly70/f0;Lx2/s;Lay0/k;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    goto :goto_0

    .line 163
    :pswitch_4
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v0, Ly61/g;

    .line 166
    .line 167
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v1, Lx2/s;

    .line 170
    .line 171
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 174
    .line 175
    check-cast p1, Ll2/o;

    .line 176
    .line 177
    check-cast p2, Ljava/lang/Integer;

    .line 178
    .line 179
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 180
    .line 181
    .line 182
    iget p0, p0, Lxk0/g0;->e:I

    .line 183
    .line 184
    or-int/lit8 p0, p0, 0x1

    .line 185
    .line 186
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 187
    .line 188
    .line 189
    move-result p0

    .line 190
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->e(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;Ll2/o;I)V

    .line 191
    .line 192
    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :pswitch_5
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v0, Ly61/g;

    .line 198
    .line 199
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v1, Lx2/s;

    .line 202
    .line 203
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;

    .line 206
    .line 207
    check-cast p1, Ll2/o;

    .line 208
    .line 209
    check-cast p2, Ljava/lang/Integer;

    .line 210
    .line 211
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 212
    .line 213
    .line 214
    iget p0, p0, Lxk0/g0;->e:I

    .line 215
    .line 216
    or-int/lit8 p0, p0, 0x1

    .line 217
    .line 218
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 219
    .line 220
    .line 221
    move-result p0

    .line 222
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->b(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveActivationViewModel;Ll2/o;I)V

    .line 223
    .line 224
    .line 225
    goto/16 :goto_0

    .line 226
    .line 227
    :pswitch_6
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v0, Ly61/g;

    .line 230
    .line 231
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast v1, Lx2/s;

    .line 234
    .line 235
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;

    .line 238
    .line 239
    check-cast p1, Ll2/o;

    .line 240
    .line 241
    check-cast p2, Ljava/lang/Integer;

    .line 242
    .line 243
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 244
    .line 245
    .line 246
    iget p0, p0, Lxk0/g0;->e:I

    .line 247
    .line 248
    or-int/lit8 p0, p0, 0x1

    .line 249
    .line 250
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 251
    .line 252
    .line 253
    move-result p0

    .line 254
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->c(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/DriveCorrectionViewModel;Ll2/o;I)V

    .line 255
    .line 256
    .line 257
    goto/16 :goto_0

    .line 258
    .line 259
    :pswitch_7
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 260
    .line 261
    check-cast v0, Ly61/g;

    .line 262
    .line 263
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 264
    .line 265
    check-cast v1, Lx2/s;

    .line 266
    .line 267
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 268
    .line 269
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;

    .line 270
    .line 271
    check-cast p1, Ll2/o;

    .line 272
    .line 273
    check-cast p2, Ljava/lang/Integer;

    .line 274
    .line 275
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 276
    .line 277
    .line 278
    iget p0, p0, Lxk0/g0;->e:I

    .line 279
    .line 280
    or-int/lit8 p0, p0, 0x1

    .line 281
    .line 282
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 283
    .line 284
    .line 285
    move-result p0

    .line 286
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->g(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;Ll2/o;I)V

    .line 287
    .line 288
    .line 289
    goto/16 :goto_0

    .line 290
    .line 291
    :pswitch_8
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 292
    .line 293
    check-cast v0, Ly61/g;

    .line 294
    .line 295
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v1, Lx2/s;

    .line 298
    .line 299
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 300
    .line 301
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;

    .line 302
    .line 303
    check-cast p1, Ll2/o;

    .line 304
    .line 305
    check-cast p2, Ljava/lang/Integer;

    .line 306
    .line 307
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 308
    .line 309
    .line 310
    iget p0, p0, Lxk0/g0;->e:I

    .line 311
    .line 312
    or-int/lit8 p0, p0, 0x1

    .line 313
    .line 314
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 315
    .line 316
    .line 317
    move-result p0

    .line 318
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->h(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/TouchDiagnosisViewModel;Ll2/o;I)V

    .line 319
    .line 320
    .line 321
    goto/16 :goto_0

    .line 322
    .line 323
    :pswitch_9
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 324
    .line 325
    check-cast v0, Ly61/g;

    .line 326
    .line 327
    iget-object v1, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 328
    .line 329
    check-cast v1, Lh70/o;

    .line 330
    .line 331
    iget-object v2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 332
    .line 333
    check-cast v2, Lt2/b;

    .line 334
    .line 335
    check-cast p1, Ll2/o;

    .line 336
    .line 337
    check-cast p2, Ljava/lang/Integer;

    .line 338
    .line 339
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 340
    .line 341
    .line 342
    iget p0, p0, Lxk0/g0;->e:I

    .line 343
    .line 344
    or-int/lit8 p0, p0, 0x1

    .line 345
    .line 346
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 347
    .line 348
    .line 349
    move-result p0

    .line 350
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->f(Lh70/o;Lt2/b;Ll2/o;I)V

    .line 351
    .line 352
    .line 353
    goto/16 :goto_0

    .line 354
    .line 355
    :pswitch_a
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v0, Ly61/g;

    .line 358
    .line 359
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 360
    .line 361
    check-cast v1, Lx2/s;

    .line 362
    .line 363
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;

    .line 366
    .line 367
    check-cast p1, Ll2/o;

    .line 368
    .line 369
    check-cast p2, Ljava/lang/Integer;

    .line 370
    .line 371
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 372
    .line 373
    .line 374
    iget p0, p0, Lxk0/g0;->e:I

    .line 375
    .line 376
    or-int/lit8 p0, p0, 0x1

    .line 377
    .line 378
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 379
    .line 380
    .line 381
    move-result p0

    .line 382
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->d(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;Ll2/o;I)V

    .line 383
    .line 384
    .line 385
    goto/16 :goto_0

    .line 386
    .line 387
    :pswitch_b
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 388
    .line 389
    check-cast v0, Ly61/g;

    .line 390
    .line 391
    iget-object v1, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 392
    .line 393
    check-cast v1, Lx2/s;

    .line 394
    .line 395
    iget-object v2, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 396
    .line 397
    check-cast v2, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;

    .line 398
    .line 399
    check-cast p1, Ll2/o;

    .line 400
    .line 401
    check-cast p2, Ljava/lang/Integer;

    .line 402
    .line 403
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 404
    .line 405
    .line 406
    iget p0, p0, Lxk0/g0;->e:I

    .line 407
    .line 408
    or-int/lit8 p0, p0, 0x1

    .line 409
    .line 410
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 411
    .line 412
    .line 413
    move-result p0

    .line 414
    invoke-virtual {v0, v1, v2, p1, p0}, Ly61/g;->a(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;Ll2/o;I)V

    .line 415
    .line 416
    .line 417
    goto/16 :goto_0

    .line 418
    .line 419
    :pswitch_c
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 420
    .line 421
    check-cast v0, Lw1/g;

    .line 422
    .line 423
    iget-object v1, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 424
    .line 425
    check-cast v1, La2/k;

    .line 426
    .line 427
    iget-object v2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 428
    .line 429
    check-cast v2, Lay0/a;

    .line 430
    .line 431
    check-cast p1, Ll2/o;

    .line 432
    .line 433
    check-cast p2, Ljava/lang/Integer;

    .line 434
    .line 435
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 436
    .line 437
    .line 438
    iget p0, p0, Lxk0/g0;->e:I

    .line 439
    .line 440
    or-int/lit8 p0, p0, 0x1

    .line 441
    .line 442
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 443
    .line 444
    .line 445
    move-result p0

    .line 446
    invoke-static {v0, v1, v2, p1, p0}, Ly1/k;->c(Lw1/g;La2/k;Lay0/a;Ll2/o;I)V

    .line 447
    .line 448
    .line 449
    goto/16 :goto_0

    .line 450
    .line 451
    :pswitch_d
    iget-object v0, p0, Lxk0/g0;->f:Ljava/lang/Object;

    .line 452
    .line 453
    check-cast v0, Ljava/lang/String;

    .line 454
    .line 455
    iget-object v1, p0, Lxk0/g0;->g:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast v1, Li91/s2;

    .line 458
    .line 459
    iget-object v2, p0, Lxk0/g0;->h:Ljava/lang/Object;

    .line 460
    .line 461
    check-cast v2, Lx2/s;

    .line 462
    .line 463
    check-cast p1, Ll2/o;

    .line 464
    .line 465
    check-cast p2, Ljava/lang/Integer;

    .line 466
    .line 467
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 468
    .line 469
    .line 470
    iget p0, p0, Lxk0/g0;->e:I

    .line 471
    .line 472
    or-int/lit8 p0, p0, 0x1

    .line 473
    .line 474
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 475
    .line 476
    .line 477
    move-result p0

    .line 478
    invoke-static {v0, v1, v2, p1, p0}, Lxk0/i0;->a(Ljava/lang/String;Li91/s2;Lx2/s;Ll2/o;I)V

    .line 479
    .line 480
    .line 481
    goto/16 :goto_0

    .line 482
    .line 483
    :pswitch_data_0
    .packed-switch 0x0
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
