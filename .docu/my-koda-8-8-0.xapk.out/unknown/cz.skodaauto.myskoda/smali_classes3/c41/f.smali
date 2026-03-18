.class public final Lc41/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lc41/f;->d:I

    iput-object p2, p0, Lc41/f;->e:Ljava/lang/Object;

    iput-object p3, p0, Lc41/f;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 2
    iput p4, p0, Lc41/f;->d:I

    iput-object p1, p0, Lc41/f;->f:Ljava/lang/Object;

    iput-object p2, p0, Lc41/f;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lc41/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lay0/k;

    .line 9
    .line 10
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ly70/y;

    .line 13
    .line 14
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lay0/k;

    .line 23
    .line 24
    new-instance v1, Lfh/c;

    .line 25
    .line 26
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Lfh/f;

    .line 29
    .line 30
    iget-boolean p0, p0, Lfh/f;->a:Z

    .line 31
    .line 32
    xor-int/lit8 p0, p0, 0x1

    .line 33
    .line 34
    invoke-direct {v1, p0}, Lfh/c;-><init>(Z)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_1
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v0, Lay0/k;

    .line 46
    .line 47
    new-instance v1, Lhh/i;

    .line 48
    .line 49
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Ljava/lang/String;

    .line 52
    .line 53
    invoke-direct {v1, p0}, Lhh/i;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_2
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Lay0/k;

    .line 65
    .line 66
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lr40/g;

    .line 69
    .line 70
    iget-object p0, p0, Lr40/g;->a:Ljava/lang/String;

    .line 71
    .line 72
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_3
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v0, Lay0/k;

    .line 81
    .line 82
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p0, Lbl0/o;

    .line 85
    .line 86
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_4
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v0, Lay0/k;

    .line 95
    .line 96
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p0, Ll70/s;

    .line 99
    .line 100
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    :pswitch_5
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Lay0/k;

    .line 109
    .line 110
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast p0, Ll60/b;

    .line 113
    .line 114
    iget-object p0, p0, Ll60/b;->a:Lap0/p;

    .line 115
    .line 116
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_6
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Lc3/j;

    .line 125
    .line 126
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 127
    .line 128
    .line 129
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast p0, Lay0/a;

    .line 132
    .line 133
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_7
    iget-object v0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v0, Lk01/p;

    .line 142
    .line 143
    iget-object v1, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v1, Lk01/t;

    .line 146
    .line 147
    sget-object v2, Lk01/b;->h:Lk01/b;

    .line 148
    .line 149
    const/4 v3, 0x1

    .line 150
    const/4 v4, 0x0

    .line 151
    :try_start_0
    invoke-virtual {v1, v3, p0}, Lk01/t;->a(ZLc41/f;)Z

    .line 152
    .line 153
    .line 154
    move-result v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 155
    if-eqz v3, :cond_1

    .line 156
    .line 157
    :cond_0
    const/4 v3, 0x0

    .line 158
    :try_start_1
    invoke-virtual {v1, v3, p0}, Lk01/t;->a(ZLc41/f;)Z

    .line 159
    .line 160
    .line 161
    move-result v3

    .line 162
    if-nez v3, :cond_0

    .line 163
    .line 164
    sget-object p0, Lk01/b;->f:Lk01/b;
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 165
    .line 166
    :try_start_2
    sget-object v2, Lk01/b;->k:Lk01/b;
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 167
    .line 168
    invoke-virtual {v0, p0, v2, v4}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V

    .line 169
    .line 170
    .line 171
    :goto_0
    invoke-static {v1}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 172
    .line 173
    .line 174
    goto :goto_4

    .line 175
    :catchall_0
    move-exception v3

    .line 176
    goto :goto_5

    .line 177
    :catch_0
    move-exception v3

    .line 178
    move-object v4, v3

    .line 179
    goto :goto_3

    .line 180
    :catchall_1
    move-exception v3

    .line 181
    :goto_1
    move-object p0, v2

    .line 182
    goto :goto_5

    .line 183
    :catch_1
    move-exception p0

    .line 184
    move-object v4, p0

    .line 185
    move-object p0, v2

    .line 186
    goto :goto_3

    .line 187
    :cond_1
    :try_start_3
    new-instance p0, Ljava/io/IOException;

    .line 188
    .line 189
    const-string v3, "Required SETTINGS preface not received"

    .line 190
    .line 191
    invoke-direct {p0, v3}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    throw p0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 195
    :goto_2
    move-object v3, p0

    .line 196
    goto :goto_1

    .line 197
    :catchall_2
    move-exception p0

    .line 198
    goto :goto_2

    .line 199
    :goto_3
    :try_start_4
    sget-object p0, Lk01/b;->g:Lk01/b;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 200
    .line 201
    invoke-virtual {v0, p0, p0, v4}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V

    .line 202
    .line 203
    .line 204
    goto :goto_0

    .line 205
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 206
    .line 207
    return-object p0

    .line 208
    :goto_5
    invoke-virtual {v0, p0, v2, v4}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V

    .line 209
    .line 210
    .line 211
    invoke-static {v1}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 212
    .line 213
    .line 214
    throw v3

    .line 215
    :pswitch_8
    iget-object v0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast v0, Lh50/i0;

    .line 218
    .line 219
    instance-of v1, v0, Lh50/h0;

    .line 220
    .line 221
    if-eqz v1, :cond_2

    .line 222
    .line 223
    iget-object p0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast p0, Lay0/k;

    .line 226
    .line 227
    check-cast v0, Lh50/h0;

    .line 228
    .line 229
    iget v0, v0, Lh50/h0;->b:I

    .line 230
    .line 231
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 239
    .line 240
    return-object p0

    .line 241
    :pswitch_9
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 242
    .line 243
    check-cast v0, Lay0/k;

    .line 244
    .line 245
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 246
    .line 247
    check-cast p0, Lh40/z;

    .line 248
    .line 249
    iget-object p0, p0, Lh40/z;->c:Ljava/lang/String;

    .line 250
    .line 251
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 255
    .line 256
    return-object p0

    .line 257
    :pswitch_a
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 258
    .line 259
    check-cast v0, Lay0/k;

    .line 260
    .line 261
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast p0, Lh40/y;

    .line 264
    .line 265
    iget-object p0, p0, Lh40/y;->c:Ljava/lang/String;

    .line 266
    .line 267
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_b
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v0, Lay0/k;

    .line 276
    .line 277
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast p0, Lh40/x;

    .line 280
    .line 281
    iget-object p0, p0, Lh40/x;->c:Ljava/lang/String;

    .line 282
    .line 283
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    return-object p0

    .line 289
    :pswitch_c
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v0, Lay0/k;

    .line 292
    .line 293
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast p0, Lbz/c;

    .line 296
    .line 297
    iget-object p0, p0, Lbz/c;->c:Laz/c;

    .line 298
    .line 299
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 303
    .line 304
    return-object p0

    .line 305
    :pswitch_d
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v0, Lay0/k;

    .line 308
    .line 309
    new-instance v1, Ltd/l;

    .line 310
    .line 311
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast p0, Ltd/a;

    .line 314
    .line 315
    iget-object p0, p0, Ltd/a;->a:Ltd/b;

    .line 316
    .line 317
    invoke-direct {v1, p0}, Ltd/l;-><init>(Ltd/b;)V

    .line 318
    .line 319
    .line 320
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 324
    .line 325
    return-object p0

    .line 326
    :pswitch_e
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 327
    .line 328
    check-cast v0, Lay0/k;

    .line 329
    .line 330
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 331
    .line 332
    check-cast p0, Lba0/j;

    .line 333
    .line 334
    iget-object p0, p0, Lba0/j;->c:Laa0/e;

    .line 335
    .line 336
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 340
    .line 341
    return-object p0

    .line 342
    :pswitch_f
    iget-object v0, p0, Lc41/f;->e:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast v0, Lay0/k;

    .line 345
    .line 346
    iget-object p0, p0, Lc41/f;->f:Ljava/lang/Object;

    .line 347
    .line 348
    check-cast p0, Lp31/c;

    .line 349
    .line 350
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 354
    .line 355
    return-object p0

    .line 356
    nop

    .line 357
    :pswitch_data_0
    .packed-switch 0x0
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
