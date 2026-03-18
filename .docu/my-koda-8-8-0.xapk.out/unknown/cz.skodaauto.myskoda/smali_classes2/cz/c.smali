.class public final synthetic Lcz/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p4, p0, Lcz/c;->d:I

    iput-object p1, p0, Lcz/c;->e:Lay0/a;

    iput-object p2, p0, Lcz/c;->f:Lay0/a;

    iput p3, p0, Lcz/c;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/a;Lay0/a;III)V
    .locals 0

    .line 2
    iput p5, p0, Lcz/c;->d:I

    iput-object p1, p0, Lcz/c;->e:Lay0/a;

    iput-object p2, p0, Lcz/c;->f:Lay0/a;

    iput p4, p0, Lcz/c;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lcz/c;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lcz/c;->g:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 22
    .line 23
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Lz20/a;->e(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget p2, p0, Lcz/c;->g:I

    .line 35
    .line 36
    or-int/lit8 p2, p2, 0x1

    .line 37
    .line 38
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 43
    .line 44
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 45
    .line 46
    invoke-static {v0, p0, p1, p2}, Lz20/a;->f(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    iget p2, p0, Lcz/c;->g:I

    .line 54
    .line 55
    or-int/lit8 p2, p2, 0x1

    .line 56
    .line 57
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 62
    .line 63
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 64
    .line 65
    invoke-static {v0, p0, p1, p2}, Lx40/a;->k(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget p2, p0, Lcz/c;->g:I

    .line 73
    .line 74
    or-int/lit8 p2, p2, 0x1

    .line 75
    .line 76
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 81
    .line 82
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 83
    .line 84
    invoke-static {v0, p0, p1, p2}, Lv50/a;->a0(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    iget p2, p0, Lcz/c;->g:I

    .line 92
    .line 93
    or-int/lit8 p2, p2, 0x1

    .line 94
    .line 95
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 100
    .line 101
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 102
    .line 103
    invoke-static {v0, p0, p1, p2}, Lv50/a;->O(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    iget p2, p0, Lcz/c;->g:I

    .line 111
    .line 112
    or-int/lit8 p2, p2, 0x1

    .line 113
    .line 114
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 115
    .line 116
    .line 117
    move-result p2

    .line 118
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 119
    .line 120
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 121
    .line 122
    invoke-static {v0, p0, p1, p2}, Lv50/a;->I(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    const/4 p2, 0x1

    .line 130
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 131
    .line 132
    .line 133
    move-result p2

    .line 134
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 135
    .line 136
    iget-object v1, p0, Lcz/c;->f:Lay0/a;

    .line 137
    .line 138
    iget p0, p0, Lcz/c;->g:I

    .line 139
    .line 140
    invoke-static {v0, v1, p1, p2, p0}, Luz/k0;->T(Lay0/a;Lay0/a;Ll2/o;II)V

    .line 141
    .line 142
    .line 143
    goto :goto_0

    .line 144
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    iget p2, p0, Lcz/c;->g:I

    .line 148
    .line 149
    or-int/lit8 p2, p2, 0x1

    .line 150
    .line 151
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 152
    .line 153
    .line 154
    move-result p2

    .line 155
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 156
    .line 157
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 158
    .line 159
    invoke-static {v0, p0, p1, p2}, Luz/t;->j(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 160
    .line 161
    .line 162
    goto/16 :goto_0

    .line 163
    .line 164
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 165
    .line 166
    .line 167
    iget p2, p0, Lcz/c;->g:I

    .line 168
    .line 169
    or-int/lit8 p2, p2, 0x1

    .line 170
    .line 171
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 172
    .line 173
    .line 174
    move-result p2

    .line 175
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 176
    .line 177
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 178
    .line 179
    invoke-static {v0, p0, p1, p2}, Ls60/a;->c(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 180
    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :pswitch_8
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 185
    .line 186
    .line 187
    iget p2, p0, Lcz/c;->g:I

    .line 188
    .line 189
    or-int/lit8 p2, p2, 0x1

    .line 190
    .line 191
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 192
    .line 193
    .line 194
    move-result p2

    .line 195
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 196
    .line 197
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 198
    .line 199
    invoke-static {v0, p0, p1, p2}, Lr40/a;->c(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 200
    .line 201
    .line 202
    goto/16 :goto_0

    .line 203
    .line 204
    :pswitch_9
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    const/4 p2, 0x1

    .line 208
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 213
    .line 214
    iget-object v1, p0, Lcz/c;->f:Lay0/a;

    .line 215
    .line 216
    iget p0, p0, Lcz/c;->g:I

    .line 217
    .line 218
    invoke-static {v0, v1, p1, p2, p0}, Lr30/a;->b(Lay0/a;Lay0/a;Ll2/o;II)V

    .line 219
    .line 220
    .line 221
    goto/16 :goto_0

    .line 222
    .line 223
    :pswitch_a
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 224
    .line 225
    .line 226
    iget p2, p0, Lcz/c;->g:I

    .line 227
    .line 228
    or-int/lit8 p2, p2, 0x1

    .line 229
    .line 230
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 231
    .line 232
    .line 233
    move-result p2

    .line 234
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 235
    .line 236
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 237
    .line 238
    invoke-static {v0, p0, p1, p2}, Lo50/a;->d(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 239
    .line 240
    .line 241
    goto/16 :goto_0

    .line 242
    .line 243
    :pswitch_b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 244
    .line 245
    .line 246
    const/4 p2, 0x1

    .line 247
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 248
    .line 249
    .line 250
    move-result p2

    .line 251
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 252
    .line 253
    iget-object v1, p0, Lcz/c;->f:Lay0/a;

    .line 254
    .line 255
    iget p0, p0, Lcz/c;->g:I

    .line 256
    .line 257
    invoke-static {v0, v1, p1, p2, p0}, Ln80/a;->k(Lay0/a;Lay0/a;Ll2/o;II)V

    .line 258
    .line 259
    .line 260
    goto/16 :goto_0

    .line 261
    .line 262
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 263
    .line 264
    .line 265
    iget p2, p0, Lcz/c;->g:I

    .line 266
    .line 267
    or-int/lit8 p2, p2, 0x1

    .line 268
    .line 269
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 270
    .line 271
    .line 272
    move-result p2

    .line 273
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 274
    .line 275
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 276
    .line 277
    invoke-static {v0, p0, p1, p2}, Lm60/a;->c(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 278
    .line 279
    .line 280
    goto/16 :goto_0

    .line 281
    .line 282
    :pswitch_d
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 283
    .line 284
    .line 285
    iget p2, p0, Lcz/c;->g:I

    .line 286
    .line 287
    or-int/lit8 p2, p2, 0x1

    .line 288
    .line 289
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 290
    .line 291
    .line 292
    move-result p2

    .line 293
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 294
    .line 295
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 296
    .line 297
    invoke-static {v0, p0, p1, p2}, Li40/l1;->u0(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 298
    .line 299
    .line 300
    goto/16 :goto_0

    .line 301
    .line 302
    :pswitch_e
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 303
    .line 304
    .line 305
    iget p2, p0, Lcz/c;->g:I

    .line 306
    .line 307
    or-int/lit8 p2, p2, 0x1

    .line 308
    .line 309
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 310
    .line 311
    .line 312
    move-result p2

    .line 313
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 314
    .line 315
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 316
    .line 317
    invoke-static {v0, p0, p1, p2}, Li40/l1;->e0(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 318
    .line 319
    .line 320
    goto/16 :goto_0

    .line 321
    .line 322
    :pswitch_f
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 323
    .line 324
    .line 325
    const/4 p2, 0x1

    .line 326
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 327
    .line 328
    .line 329
    move-result p2

    .line 330
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 331
    .line 332
    iget-object v1, p0, Lcz/c;->f:Lay0/a;

    .line 333
    .line 334
    iget p0, p0, Lcz/c;->g:I

    .line 335
    .line 336
    invoke-static {v0, v1, p1, p2, p0}, Ld80/b;->n(Lay0/a;Lay0/a;Ll2/o;II)V

    .line 337
    .line 338
    .line 339
    goto/16 :goto_0

    .line 340
    .line 341
    :pswitch_10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 342
    .line 343
    .line 344
    iget p2, p0, Lcz/c;->g:I

    .line 345
    .line 346
    or-int/lit8 p2, p2, 0x1

    .line 347
    .line 348
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 349
    .line 350
    .line 351
    move-result p2

    .line 352
    iget-object v0, p0, Lcz/c;->e:Lay0/a;

    .line 353
    .line 354
    iget-object p0, p0, Lcz/c;->f:Lay0/a;

    .line 355
    .line 356
    invoke-static {v0, p0, p1, p2}, Lcz/e;->c(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 357
    .line 358
    .line 359
    goto/16 :goto_0

    .line 360
    .line 361
    :pswitch_data_0
    .packed-switch 0x0
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
