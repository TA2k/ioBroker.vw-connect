.class public final synthetic Lxk0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Li91/s2;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;II)V
    .locals 0

    .line 1
    iput p7, p0, Lxk0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lxk0/a;->f:Li91/s2;

    .line 6
    .line 7
    iput-object p3, p0, Lxk0/a;->g:Lay0/k;

    .line 8
    .line 9
    iput-object p4, p0, Lxk0/a;->h:Lay0/k;

    .line 10
    .line 11
    iput-object p5, p0, Lxk0/a;->i:Lay0/k;

    .line 12
    .line 13
    iput p6, p0, Lxk0/a;->j:I

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lxk0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v6, p1

    .line 7
    check-cast v6, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    iget p1, p0, Lxk0/a;->j:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v7

    .line 22
    iget-object v1, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v2, p0, Lxk0/a;->f:Li91/s2;

    .line 25
    .line 26
    iget-object v3, p0, Lxk0/a;->g:Lay0/k;

    .line 27
    .line 28
    iget-object v4, p0, Lxk0/a;->h:Lay0/k;

    .line 29
    .line 30
    iget-object v5, p0, Lxk0/a;->i:Lay0/k;

    .line 31
    .line 32
    invoke-static/range {v1 .. v7}, Lxk0/i0;->g(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 33
    .line 34
    .line 35
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    move-object v5, p1

    .line 39
    check-cast v5, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    iget p1, p0, Lxk0/a;->j:I

    .line 47
    .line 48
    or-int/lit8 p1, p1, 0x1

    .line 49
    .line 50
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result v6

    .line 54
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 57
    .line 58
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 59
    .line 60
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 61
    .line 62
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 63
    .line 64
    invoke-static/range {v0 .. v6}, Lxk0/i0;->g(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :pswitch_1
    move-object v5, p1

    .line 69
    check-cast v5, Ll2/o;

    .line 70
    .line 71
    check-cast p2, Ljava/lang/Integer;

    .line 72
    .line 73
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 74
    .line 75
    .line 76
    iget p1, p0, Lxk0/a;->j:I

    .line 77
    .line 78
    or-int/lit8 p1, p1, 0x1

    .line 79
    .line 80
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 87
    .line 88
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 89
    .line 90
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 91
    .line 92
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 93
    .line 94
    invoke-static/range {v0 .. v6}, Lxk0/f0;->d(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :pswitch_2
    move-object v5, p1

    .line 99
    check-cast v5, Ll2/o;

    .line 100
    .line 101
    check-cast p2, Ljava/lang/Integer;

    .line 102
    .line 103
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 104
    .line 105
    .line 106
    iget p1, p0, Lxk0/a;->j:I

    .line 107
    .line 108
    or-int/lit8 p1, p1, 0x1

    .line 109
    .line 110
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 115
    .line 116
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 117
    .line 118
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 119
    .line 120
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 121
    .line 122
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 123
    .line 124
    invoke-static/range {v0 .. v6}, Lxk0/f0;->d(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    :pswitch_3
    move-object v5, p1

    .line 129
    check-cast v5, Ll2/o;

    .line 130
    .line 131
    check-cast p2, Ljava/lang/Integer;

    .line 132
    .line 133
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 134
    .line 135
    .line 136
    iget p1, p0, Lxk0/a;->j:I

    .line 137
    .line 138
    or-int/lit8 p1, p1, 0x1

    .line 139
    .line 140
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 145
    .line 146
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 147
    .line 148
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 149
    .line 150
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 151
    .line 152
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 153
    .line 154
    invoke-static/range {v0 .. v6}, Lxk0/h;->b0(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 155
    .line 156
    .line 157
    goto :goto_0

    .line 158
    :pswitch_4
    move-object v5, p1

    .line 159
    check-cast v5, Ll2/o;

    .line 160
    .line 161
    check-cast p2, Ljava/lang/Integer;

    .line 162
    .line 163
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 164
    .line 165
    .line 166
    iget p1, p0, Lxk0/a;->j:I

    .line 167
    .line 168
    or-int/lit8 p1, p1, 0x1

    .line 169
    .line 170
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 171
    .line 172
    .line 173
    move-result v6

    .line 174
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 175
    .line 176
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 177
    .line 178
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 179
    .line 180
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 181
    .line 182
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 183
    .line 184
    invoke-static/range {v0 .. v6}, Lxk0/h;->b0(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 185
    .line 186
    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :pswitch_5
    move-object v5, p1

    .line 190
    check-cast v5, Ll2/o;

    .line 191
    .line 192
    check-cast p2, Ljava/lang/Integer;

    .line 193
    .line 194
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 195
    .line 196
    .line 197
    iget p1, p0, Lxk0/a;->j:I

    .line 198
    .line 199
    or-int/lit8 p1, p1, 0x1

    .line 200
    .line 201
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 202
    .line 203
    .line 204
    move-result v6

    .line 205
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 206
    .line 207
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 208
    .line 209
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 210
    .line 211
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 212
    .line 213
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 214
    .line 215
    invoke-static/range {v0 .. v6}, Lxk0/h;->H(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    goto/16 :goto_0

    .line 219
    .line 220
    :pswitch_6
    move-object v5, p1

    .line 221
    check-cast v5, Ll2/o;

    .line 222
    .line 223
    check-cast p2, Ljava/lang/Integer;

    .line 224
    .line 225
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 226
    .line 227
    .line 228
    iget p1, p0, Lxk0/a;->j:I

    .line 229
    .line 230
    or-int/lit8 p1, p1, 0x1

    .line 231
    .line 232
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 233
    .line 234
    .line 235
    move-result v6

    .line 236
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 237
    .line 238
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 239
    .line 240
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 241
    .line 242
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 243
    .line 244
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 245
    .line 246
    invoke-static/range {v0 .. v6}, Lxk0/h;->H(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 247
    .line 248
    .line 249
    goto/16 :goto_0

    .line 250
    .line 251
    :pswitch_7
    move-object v5, p1

    .line 252
    check-cast v5, Ll2/o;

    .line 253
    .line 254
    check-cast p2, Ljava/lang/Integer;

    .line 255
    .line 256
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 257
    .line 258
    .line 259
    iget p1, p0, Lxk0/a;->j:I

    .line 260
    .line 261
    or-int/lit8 p1, p1, 0x1

    .line 262
    .line 263
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 264
    .line 265
    .line 266
    move-result v6

    .line 267
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 268
    .line 269
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 270
    .line 271
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 272
    .line 273
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 274
    .line 275
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 276
    .line 277
    invoke-static/range {v0 .. v6}, Lxk0/h;->h(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 278
    .line 279
    .line 280
    goto/16 :goto_0

    .line 281
    .line 282
    :pswitch_8
    move-object v5, p1

    .line 283
    check-cast v5, Ll2/o;

    .line 284
    .line 285
    check-cast p2, Ljava/lang/Integer;

    .line 286
    .line 287
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 288
    .line 289
    .line 290
    iget p1, p0, Lxk0/a;->j:I

    .line 291
    .line 292
    or-int/lit8 p1, p1, 0x1

    .line 293
    .line 294
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 295
    .line 296
    .line 297
    move-result v6

    .line 298
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 299
    .line 300
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 301
    .line 302
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 303
    .line 304
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 305
    .line 306
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 307
    .line 308
    invoke-static/range {v0 .. v6}, Lxk0/h;->h(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 309
    .line 310
    .line 311
    goto/16 :goto_0

    .line 312
    .line 313
    :pswitch_9
    move-object v5, p1

    .line 314
    check-cast v5, Ll2/o;

    .line 315
    .line 316
    check-cast p2, Ljava/lang/Integer;

    .line 317
    .line 318
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 319
    .line 320
    .line 321
    iget p1, p0, Lxk0/a;->j:I

    .line 322
    .line 323
    or-int/lit8 p1, p1, 0x1

    .line 324
    .line 325
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 330
    .line 331
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 332
    .line 333
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 334
    .line 335
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 336
    .line 337
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 338
    .line 339
    invoke-static/range {v0 .. v6}, Lxk0/d;->c(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 340
    .line 341
    .line 342
    goto/16 :goto_0

    .line 343
    .line 344
    :pswitch_a
    move-object v5, p1

    .line 345
    check-cast v5, Ll2/o;

    .line 346
    .line 347
    check-cast p2, Ljava/lang/Integer;

    .line 348
    .line 349
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 350
    .line 351
    .line 352
    iget p1, p0, Lxk0/a;->j:I

    .line 353
    .line 354
    or-int/lit8 p1, p1, 0x1

    .line 355
    .line 356
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 357
    .line 358
    .line 359
    move-result v6

    .line 360
    iget-object v0, p0, Lxk0/a;->e:Ljava/lang/String;

    .line 361
    .line 362
    iget-object v1, p0, Lxk0/a;->f:Li91/s2;

    .line 363
    .line 364
    iget-object v2, p0, Lxk0/a;->g:Lay0/k;

    .line 365
    .line 366
    iget-object v3, p0, Lxk0/a;->h:Lay0/k;

    .line 367
    .line 368
    iget-object v4, p0, Lxk0/a;->i:Lay0/k;

    .line 369
    .line 370
    invoke-static/range {v0 .. v6}, Lxk0/d;->c(Ljava/lang/String;Li91/s2;Lay0/k;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 371
    .line 372
    .line 373
    goto/16 :goto_0

    .line 374
    .line 375
    :pswitch_data_0
    .packed-switch 0x0
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
