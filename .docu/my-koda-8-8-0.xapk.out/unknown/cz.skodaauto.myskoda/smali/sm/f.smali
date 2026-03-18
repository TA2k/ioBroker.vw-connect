.class public abstract Lsm/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lnx0/f;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lnx0/f;

    .line 2
    .line 3
    invoke-direct {v0}, Lnx0/f;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "bin"

    .line 7
    .line 8
    const-string v2, "application/octet-stream"

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    const-string v1, "gz"

    .line 14
    .line 15
    const-string v2, "application/gzip"

    .line 16
    .line 17
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    const-string v1, "json"

    .line 21
    .line 22
    const-string v2, "application/json"

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    const-string v1, "pdf"

    .line 28
    .line 29
    const-string v2, "application/pdf"

    .line 30
    .line 31
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    const-string v1, "yaml"

    .line 35
    .line 36
    const-string v2, "application/yaml"

    .line 37
    .line 38
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    const-string v1, "avif"

    .line 42
    .line 43
    const-string v2, "image/avif"

    .line 44
    .line 45
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    const-string v1, "avifs"

    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    const-string v1, "bmp"

    .line 54
    .line 55
    const-string v2, "image/bmp"

    .line 56
    .line 57
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    const-string v1, "cgm"

    .line 61
    .line 62
    const-string v2, "image/cgm"

    .line 63
    .line 64
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    const-string v1, "g3"

    .line 68
    .line 69
    const-string v2, "image/g3fax"

    .line 70
    .line 71
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    const-string v1, "gif"

    .line 75
    .line 76
    const-string v2, "image/gif"

    .line 77
    .line 78
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    const-string v1, "heif"

    .line 82
    .line 83
    const-string v2, "image/heic"

    .line 84
    .line 85
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    const-string v1, "heic"

    .line 89
    .line 90
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    const-string v1, "ief"

    .line 94
    .line 95
    const-string v2, "image/ief"

    .line 96
    .line 97
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    const-string v1, "jpe"

    .line 101
    .line 102
    const-string v2, "image/jpeg"

    .line 103
    .line 104
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    const-string v1, "jpeg"

    .line 108
    .line 109
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    const-string v1, "jpg"

    .line 113
    .line 114
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    const-string v1, "pjpg"

    .line 118
    .line 119
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    const-string v1, "jfif"

    .line 123
    .line 124
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    const-string v1, "jfif-tbnl"

    .line 128
    .line 129
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    const-string v1, "jif"

    .line 133
    .line 134
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    const-string v1, "png"

    .line 138
    .line 139
    const-string v2, "image/png"

    .line 140
    .line 141
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    const-string v1, "btif"

    .line 145
    .line 146
    const-string v2, "image/prs.btif"

    .line 147
    .line 148
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    const-string v1, "svg"

    .line 152
    .line 153
    const-string v2, "image/svg+xml"

    .line 154
    .line 155
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    const-string v1, "svgz"

    .line 159
    .line 160
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    const-string v1, "tif"

    .line 164
    .line 165
    const-string v2, "image/tiff"

    .line 166
    .line 167
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    const-string v1, "tiff"

    .line 171
    .line 172
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    const-string v1, "psd"

    .line 176
    .line 177
    const-string v2, "image/vnd.adobe.photoshop"

    .line 178
    .line 179
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    const-string v1, "djv"

    .line 183
    .line 184
    const-string v2, "image/vnd.djvu"

    .line 185
    .line 186
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    const-string v1, "djvu"

    .line 190
    .line 191
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    const-string v1, "dwg"

    .line 195
    .line 196
    const-string v2, "image/vnd.dwg"

    .line 197
    .line 198
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    const-string v1, "dxf"

    .line 202
    .line 203
    const-string v2, "image/vnd.dxf"

    .line 204
    .line 205
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    const-string v1, "fbs"

    .line 209
    .line 210
    const-string v2, "image/vnd.fastbidsheet"

    .line 211
    .line 212
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    const-string v1, "fpx"

    .line 216
    .line 217
    const-string v2, "image/vnd.fpx"

    .line 218
    .line 219
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    const-string v1, "fst"

    .line 223
    .line 224
    const-string v2, "image/vnd.fst"

    .line 225
    .line 226
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    const-string v1, "mmr"

    .line 230
    .line 231
    const-string v2, "image/vnd.fujixerox.edmics-mmr"

    .line 232
    .line 233
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    const-string v1, "rlc"

    .line 237
    .line 238
    const-string v2, "image/vnd.fujixerox.edmics-rlc"

    .line 239
    .line 240
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    const-string v1, "mdi"

    .line 244
    .line 245
    const-string v2, "image/vnd.ms-modi"

    .line 246
    .line 247
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    const-string v1, "npx"

    .line 251
    .line 252
    const-string v2, "image/vnd.net-fpx"

    .line 253
    .line 254
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    const-string v1, "wbmp"

    .line 258
    .line 259
    const-string v2, "image/vnd.wap.wbmp"

    .line 260
    .line 261
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    const-string v1, "xif"

    .line 265
    .line 266
    const-string v2, "image/vnd.xiff"

    .line 267
    .line 268
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    const-string v1, "webp"

    .line 272
    .line 273
    const-string v2, "image/webp"

    .line 274
    .line 275
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    const-string v1, "dng"

    .line 279
    .line 280
    const-string v2, "image/x-adobe-dng"

    .line 281
    .line 282
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    const-string v1, "cr2"

    .line 286
    .line 287
    const-string v2, "image/x-canon-cr2"

    .line 288
    .line 289
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    const-string v1, "crw"

    .line 293
    .line 294
    const-string v2, "image/x-canon-crw"

    .line 295
    .line 296
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    const-string v1, "ras"

    .line 300
    .line 301
    const-string v2, "image/x-cmu-raster"

    .line 302
    .line 303
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    const-string v1, "cmx"

    .line 307
    .line 308
    const-string v2, "image/x-cmx"

    .line 309
    .line 310
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    const-string v1, "erf"

    .line 314
    .line 315
    const-string v2, "image/x-epson-erf"

    .line 316
    .line 317
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    const-string v1, "fh"

    .line 321
    .line 322
    const-string v2, "image/x-freehand"

    .line 323
    .line 324
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    const-string v1, "fh4"

    .line 328
    .line 329
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    const-string v1, "fh5"

    .line 333
    .line 334
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    const-string v1, "fh7"

    .line 338
    .line 339
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    const-string v1, "fhc"

    .line 343
    .line 344
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    const-string v1, "raf"

    .line 348
    .line 349
    const-string v2, "image/x-fuji-raf"

    .line 350
    .line 351
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    const-string v1, "icns"

    .line 355
    .line 356
    const-string v2, "image/x-icns"

    .line 357
    .line 358
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    const-string v1, "ico"

    .line 362
    .line 363
    const-string v2, "image/x-icon"

    .line 364
    .line 365
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    const-string v1, "dcr"

    .line 369
    .line 370
    const-string v2, "image/x-kodak-dcr"

    .line 371
    .line 372
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    const-string v1, "k25"

    .line 376
    .line 377
    const-string v2, "image/x-kodak-k25"

    .line 378
    .line 379
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    const-string v1, "kdc"

    .line 383
    .line 384
    const-string v2, "image/x-kodak-kdc"

    .line 385
    .line 386
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    const-string v1, "mrw"

    .line 390
    .line 391
    const-string v2, "image/x-minolta-mrw"

    .line 392
    .line 393
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    const-string v1, "nef"

    .line 397
    .line 398
    const-string v2, "image/x-nikon-nef"

    .line 399
    .line 400
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    const-string v1, "orf"

    .line 404
    .line 405
    const-string v2, "image/x-olympus-orf"

    .line 406
    .line 407
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    const-string v1, "raw"

    .line 411
    .line 412
    const-string v2, "image/x-panasonic-raw"

    .line 413
    .line 414
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    const-string v1, "rw2"

    .line 418
    .line 419
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    const-string v1, "rwl"

    .line 423
    .line 424
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    const-string v1, "pcx"

    .line 428
    .line 429
    const-string v2, "image/x-pcx"

    .line 430
    .line 431
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    const-string v1, "pef"

    .line 435
    .line 436
    const-string v2, "image/x-pentax-pef"

    .line 437
    .line 438
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    const-string v1, "ptx"

    .line 442
    .line 443
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 444
    .line 445
    .line 446
    const-string v1, "pct"

    .line 447
    .line 448
    const-string v2, "image/x-pict"

    .line 449
    .line 450
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    const-string v1, "pic"

    .line 454
    .line 455
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    const-string v1, "pnm"

    .line 459
    .line 460
    const-string v2, "image/x-portable-anymap"

    .line 461
    .line 462
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    const-string v1, "pbm"

    .line 466
    .line 467
    const-string v2, "image/x-portable-bitmap"

    .line 468
    .line 469
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    const-string v1, "pgm"

    .line 473
    .line 474
    const-string v2, "image/x-portable-graymap"

    .line 475
    .line 476
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    const-string v1, "ppm"

    .line 480
    .line 481
    const-string v2, "image/x-portable-pixmap"

    .line 482
    .line 483
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    const-string v1, "rgb"

    .line 487
    .line 488
    const-string v2, "image/x-rgb"

    .line 489
    .line 490
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    const-string v1, "x3f"

    .line 494
    .line 495
    const-string v2, "image/x-sigma-x3f"

    .line 496
    .line 497
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    const-string v1, "arw"

    .line 501
    .line 502
    const-string v2, "image/x-sony-arw"

    .line 503
    .line 504
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    const-string v1, "sr2"

    .line 508
    .line 509
    const-string v2, "image/x-sony-sr2"

    .line 510
    .line 511
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    const-string v1, "srf"

    .line 515
    .line 516
    const-string v2, "image/x-sony-srf"

    .line 517
    .line 518
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    const-string v1, "xbm"

    .line 522
    .line 523
    const-string v2, "image/x-xbitmap"

    .line 524
    .line 525
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    const-string v1, "xpm"

    .line 529
    .line 530
    const-string v2, "image/x-xpixmap"

    .line 531
    .line 532
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    const-string v1, "xwd"

    .line 536
    .line 537
    const-string v2, "image/x-xwindowdump"

    .line 538
    .line 539
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    const-string v1, "css"

    .line 543
    .line 544
    const-string v2, "text/css"

    .line 545
    .line 546
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    const-string v1, "csv"

    .line 550
    .line 551
    const-string v2, "text/csv"

    .line 552
    .line 553
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    const-string v1, "htm"

    .line 557
    .line 558
    const-string v2, "text/html"

    .line 559
    .line 560
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 561
    .line 562
    .line 563
    const-string v1, "html"

    .line 564
    .line 565
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 566
    .line 567
    .line 568
    const-string v1, "ics"

    .line 569
    .line 570
    const-string v2, "text/calendar"

    .line 571
    .line 572
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    const-string v1, "js"

    .line 576
    .line 577
    const-string v2, "text/javascript"

    .line 578
    .line 579
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    const-string v1, "mjs"

    .line 583
    .line 584
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 585
    .line 586
    .line 587
    const-string v1, "md"

    .line 588
    .line 589
    const-string v2, "text/markdown"

    .line 590
    .line 591
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    const-string v1, "txt"

    .line 595
    .line 596
    const-string v2, "text/plain"

    .line 597
    .line 598
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 599
    .line 600
    .line 601
    const-string v1, "xml"

    .line 602
    .line 603
    const-string v2, "text/xml"

    .line 604
    .line 605
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    const-string v1, "3gp"

    .line 609
    .line 610
    const-string v2, "video/3gpp"

    .line 611
    .line 612
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 613
    .line 614
    .line 615
    const-string v1, "3g2"

    .line 616
    .line 617
    const-string v2, "video/3gpp2"

    .line 618
    .line 619
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    const-string v1, "h261"

    .line 623
    .line 624
    const-string v2, "video/h261"

    .line 625
    .line 626
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 627
    .line 628
    .line 629
    const-string v1, "h263"

    .line 630
    .line 631
    const-string v2, "video/h263"

    .line 632
    .line 633
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    const-string v1, "h264"

    .line 637
    .line 638
    const-string v2, "video/h264"

    .line 639
    .line 640
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 641
    .line 642
    .line 643
    const-string v1, "jpgv"

    .line 644
    .line 645
    const-string v2, "video/jpeg"

    .line 646
    .line 647
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 648
    .line 649
    .line 650
    const-string v1, "jpgm"

    .line 651
    .line 652
    const-string v2, "video/jpm"

    .line 653
    .line 654
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 655
    .line 656
    .line 657
    const-string v1, "jpm"

    .line 658
    .line 659
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 660
    .line 661
    .line 662
    const-string v1, "mj2"

    .line 663
    .line 664
    const-string v2, "video/mj2"

    .line 665
    .line 666
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    const-string v1, "mjp2"

    .line 670
    .line 671
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    const-string v1, "ts"

    .line 675
    .line 676
    const-string v2, "video/mp2t"

    .line 677
    .line 678
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    const-string v1, "mp4"

    .line 682
    .line 683
    const-string v2, "video/mp4"

    .line 684
    .line 685
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 686
    .line 687
    .line 688
    const-string v1, "mp4v"

    .line 689
    .line 690
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 691
    .line 692
    .line 693
    const-string v1, "mpg4"

    .line 694
    .line 695
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 696
    .line 697
    .line 698
    const-string v1, "m1v"

    .line 699
    .line 700
    const-string v2, "video/mpeg"

    .line 701
    .line 702
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 703
    .line 704
    .line 705
    const-string v1, "m2v"

    .line 706
    .line 707
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    const-string v1, "mpa"

    .line 711
    .line 712
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 713
    .line 714
    .line 715
    const-string v1, "mpe"

    .line 716
    .line 717
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 718
    .line 719
    .line 720
    const-string v1, "mpeg"

    .line 721
    .line 722
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 723
    .line 724
    .line 725
    const-string v1, "mpg"

    .line 726
    .line 727
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 728
    .line 729
    .line 730
    const-string v1, "ogv"

    .line 731
    .line 732
    const-string v2, "video/ogg"

    .line 733
    .line 734
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    const-string v1, "mov"

    .line 738
    .line 739
    const-string v2, "video/quicktime"

    .line 740
    .line 741
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    const-string v1, "qt"

    .line 745
    .line 746
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 747
    .line 748
    .line 749
    const-string v1, "fvt"

    .line 750
    .line 751
    const-string v2, "video/vnd.fvt"

    .line 752
    .line 753
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 754
    .line 755
    .line 756
    const-string v1, "m4u"

    .line 757
    .line 758
    const-string v2, "video/vnd.mpegurl"

    .line 759
    .line 760
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    const-string v1, "mxu"

    .line 764
    .line 765
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 766
    .line 767
    .line 768
    const-string v1, "pyv"

    .line 769
    .line 770
    const-string v2, "video/vnd.ms-playready.media.pyv"

    .line 771
    .line 772
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 773
    .line 774
    .line 775
    const-string v1, "viv"

    .line 776
    .line 777
    const-string v2, "video/vnd.vivo"

    .line 778
    .line 779
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 780
    .line 781
    .line 782
    const-string v1, "webm"

    .line 783
    .line 784
    const-string v2, "video/webm"

    .line 785
    .line 786
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 787
    .line 788
    .line 789
    const-string v1, "f4v"

    .line 790
    .line 791
    const-string v2, "video/x-f4v"

    .line 792
    .line 793
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    const-string v1, "fli"

    .line 797
    .line 798
    const-string v2, "video/x-fli"

    .line 799
    .line 800
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 801
    .line 802
    .line 803
    const-string v1, "flv"

    .line 804
    .line 805
    const-string v2, "video/x-flv"

    .line 806
    .line 807
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    const-string v1, "m4v"

    .line 811
    .line 812
    const-string v2, "video/x-m4v"

    .line 813
    .line 814
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 815
    .line 816
    .line 817
    const-string v1, "mkv"

    .line 818
    .line 819
    const-string v2, "video/x-matroska"

    .line 820
    .line 821
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 822
    .line 823
    .line 824
    const-string v1, "asf"

    .line 825
    .line 826
    const-string v2, "video/x-ms-asf"

    .line 827
    .line 828
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 829
    .line 830
    .line 831
    const-string v1, "asx"

    .line 832
    .line 833
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 834
    .line 835
    .line 836
    const-string v1, "wm"

    .line 837
    .line 838
    const-string v2, "video/x-ms-wm"

    .line 839
    .line 840
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 841
    .line 842
    .line 843
    const-string v1, "wmv"

    .line 844
    .line 845
    const-string v2, "video/x-ms-wmv"

    .line 846
    .line 847
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 848
    .line 849
    .line 850
    const-string v1, "wmx"

    .line 851
    .line 852
    const-string v2, "video/x-ms-wmx"

    .line 853
    .line 854
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 855
    .line 856
    .line 857
    const-string v1, "wvx"

    .line 858
    .line 859
    const-string v2, "video/x-ms-wvx"

    .line 860
    .line 861
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 862
    .line 863
    .line 864
    const-string v1, "avi"

    .line 865
    .line 866
    const-string v2, "video/x-msvideo"

    .line 867
    .line 868
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 869
    .line 870
    .line 871
    const-string v1, "movie"

    .line 872
    .line 873
    const-string v2, "video/x-sgi-movie"

    .line 874
    .line 875
    invoke-virtual {v0, v1, v2}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 876
    .line 877
    .line 878
    invoke-virtual {v0}, Lnx0/f;->b()Lnx0/f;

    .line 879
    .line 880
    .line 881
    move-result-object v0

    .line 882
    sput-object v0, Lsm/f;->a:Lnx0/f;

    .line 883
    .line 884
    return-void
.end method
