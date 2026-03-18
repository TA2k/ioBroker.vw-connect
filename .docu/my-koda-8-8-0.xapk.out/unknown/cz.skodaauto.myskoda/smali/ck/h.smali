.class public final synthetic Lck/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IIILjava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    const/16 p3, 0x9

    iput p3, p0, Lck/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lck/h;->e:I

    iput-object p4, p0, Lck/h;->g:Ljava/lang/Object;

    iput p2, p0, Lck/h;->f:I

    iput-object p5, p0, Lck/h;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(IILay0/a;Ljava/util/List;)V
    .locals 1

    .line 2
    const/16 v0, 0xa

    iput v0, p0, Lck/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lck/h;->e:I

    iput-object p4, p0, Lck/h;->g:Ljava/lang/Object;

    iput-object p3, p0, Lck/h;->h:Ljava/lang/Object;

    iput p2, p0, Lck/h;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ILay0/k;II)V
    .locals 0

    .line 3
    iput p5, p0, Lck/h;->d:I

    iput-object p1, p0, Lck/h;->g:Ljava/lang/Object;

    iput p2, p0, Lck/h;->e:I

    iput-object p3, p0, Lck/h;->h:Ljava/lang/Object;

    iput p4, p0, Lck/h;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;III)V
    .locals 0

    .line 4
    iput p5, p0, Lck/h;->d:I

    iput-object p1, p0, Lck/h;->g:Ljava/lang/Object;

    iput-object p2, p0, Lck/h;->h:Ljava/lang/Object;

    iput p3, p0, Lck/h;->e:I

    iput p4, p0, Lck/h;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lck/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/List;

    .line 9
    .line 10
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lay0/a;

    .line 13
    .line 14
    check-cast p1, Ll2/o;

    .line 15
    .line 16
    check-cast p2, Ljava/lang/Integer;

    .line 17
    .line 18
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    iget p2, p0, Lck/h;->f:I

    .line 22
    .line 23
    or-int/lit8 p2, p2, 0x1

    .line 24
    .line 25
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result p2

    .line 29
    iget p0, p0, Lck/h;->e:I

    .line 30
    .line 31
    invoke-static {p0, v0, v1, p1, p2}, Lxk0/p;->a(ILjava/util/List;Lay0/a;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v2, v0

    .line 40
    check-cast v2, Ljava/lang/String;

    .line 41
    .line 42
    iget-object v0, p0, Lck/h;->h:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v4, v0

    .line 45
    check-cast v4, Ljava/lang/String;

    .line 46
    .line 47
    move-object v5, p1

    .line 48
    check-cast v5, Ll2/o;

    .line 49
    .line 50
    check-cast p2, Ljava/lang/Integer;

    .line 51
    .line 52
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    const/16 p1, 0xc31

    .line 56
    .line 57
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    iget v1, p0, Lck/h;->e:I

    .line 62
    .line 63
    iget v3, p0, Lck/h;->f:I

    .line 64
    .line 65
    invoke-static/range {v1 .. v6}, Ln70/a;->L(ILjava/lang/String;ILjava/lang/String;Ll2/o;I)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_1
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Ljava/util/List;

    .line 72
    .line 73
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v1, Lbd/a;

    .line 76
    .line 77
    check-cast p1, Ll2/o;

    .line 78
    .line 79
    check-cast p2, Ljava/lang/Integer;

    .line 80
    .line 81
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    iget p2, p0, Lck/h;->e:I

    .line 85
    .line 86
    or-int/lit8 p2, p2, 0x1

    .line 87
    .line 88
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    iget p0, p0, Lck/h;->f:I

    .line 93
    .line 94
    invoke-static {v0, v1, p1, p2, p0}, Llp/jf;->b(Ljava/util/List;Lbd/a;Ll2/o;II)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :pswitch_2
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v0, Lhe/a;

    .line 101
    .line 102
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v1, Lay0/k;

    .line 105
    .line 106
    check-cast p1, Ll2/o;

    .line 107
    .line 108
    check-cast p2, Ljava/lang/Integer;

    .line 109
    .line 110
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 111
    .line 112
    .line 113
    iget p2, p0, Lck/h;->f:I

    .line 114
    .line 115
    or-int/lit8 p2, p2, 0x1

    .line 116
    .line 117
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 118
    .line 119
    .line 120
    move-result p2

    .line 121
    iget p0, p0, Lck/h;->e:I

    .line 122
    .line 123
    invoke-static {v0, p0, v1, p1, p2}, Ljk/a;->b(Lhe/a;ILay0/k;Ll2/o;I)V

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :pswitch_3
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v0, Lx2/s;

    .line 130
    .line 131
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v1, Lt3/k;

    .line 134
    .line 135
    check-cast p1, Ll2/o;

    .line 136
    .line 137
    check-cast p2, Ljava/lang/Integer;

    .line 138
    .line 139
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    iget p2, p0, Lck/h;->f:I

    .line 143
    .line 144
    or-int/lit8 p2, p2, 0x1

    .line 145
    .line 146
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 147
    .line 148
    .line 149
    move-result p2

    .line 150
    iget p0, p0, Lck/h;->e:I

    .line 151
    .line 152
    invoke-static {v0, v1, p0, p1, p2}, Llp/xa;->b(Lx2/s;Lt3/k;ILl2/o;I)V

    .line 153
    .line 154
    .line 155
    goto :goto_0

    .line 156
    :pswitch_4
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v0, Lh2/t9;

    .line 159
    .line 160
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v1, Lx2/s;

    .line 163
    .line 164
    check-cast p1, Ll2/o;

    .line 165
    .line 166
    check-cast p2, Ljava/lang/Integer;

    .line 167
    .line 168
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    iget p2, p0, Lck/h;->e:I

    .line 172
    .line 173
    or-int/lit8 p2, p2, 0x1

    .line 174
    .line 175
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 176
    .line 177
    .line 178
    move-result p2

    .line 179
    iget p0, p0, Lck/h;->f:I

    .line 180
    .line 181
    invoke-static {v0, v1, p1, p2, p0}, Li91/j0;->n0(Lh2/t9;Lx2/s;Ll2/o;II)V

    .line 182
    .line 183
    .line 184
    goto/16 :goto_0

    .line 185
    .line 186
    :pswitch_5
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 187
    .line 188
    check-cast v0, Li91/k1;

    .line 189
    .line 190
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 191
    .line 192
    check-cast v1, Lx2/s;

    .line 193
    .line 194
    check-cast p1, Ll2/o;

    .line 195
    .line 196
    check-cast p2, Ljava/lang/Integer;

    .line 197
    .line 198
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 199
    .line 200
    .line 201
    iget p2, p0, Lck/h;->e:I

    .line 202
    .line 203
    or-int/lit8 p2, p2, 0x1

    .line 204
    .line 205
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 206
    .line 207
    .line 208
    move-result p2

    .line 209
    iget p0, p0, Lck/h;->f:I

    .line 210
    .line 211
    invoke-static {v0, v1, p1, p2, p0}, Li91/j0;->E(Li91/k1;Lx2/s;Ll2/o;II)V

    .line 212
    .line 213
    .line 214
    goto/16 :goto_0

    .line 215
    .line 216
    :pswitch_6
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v0, Lh50/u;

    .line 219
    .line 220
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v1, Lx2/s;

    .line 223
    .line 224
    check-cast p1, Ll2/o;

    .line 225
    .line 226
    check-cast p2, Ljava/lang/Integer;

    .line 227
    .line 228
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 229
    .line 230
    .line 231
    iget p2, p0, Lck/h;->e:I

    .line 232
    .line 233
    or-int/lit8 p2, p2, 0x1

    .line 234
    .line 235
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 236
    .line 237
    .line 238
    move-result p2

    .line 239
    iget p0, p0, Lck/h;->f:I

    .line 240
    .line 241
    invoke-static {v0, v1, p1, p2, p0}, Li50/c;->j(Lh50/u;Lx2/s;Ll2/o;II)V

    .line 242
    .line 243
    .line 244
    goto/16 :goto_0

    .line 245
    .line 246
    :pswitch_7
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v0, Lh40/a0;

    .line 249
    .line 250
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v1, Lx2/s;

    .line 253
    .line 254
    check-cast p1, Ll2/o;

    .line 255
    .line 256
    check-cast p2, Ljava/lang/Integer;

    .line 257
    .line 258
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 259
    .line 260
    .line 261
    iget p2, p0, Lck/h;->e:I

    .line 262
    .line 263
    or-int/lit8 p2, p2, 0x1

    .line 264
    .line 265
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 266
    .line 267
    .line 268
    move-result p2

    .line 269
    iget p0, p0, Lck/h;->f:I

    .line 270
    .line 271
    invoke-static {v0, v1, p1, p2, p0}, Li40/f3;->d(Lh40/a0;Lx2/s;Ll2/o;II)V

    .line 272
    .line 273
    .line 274
    goto/16 :goto_0

    .line 275
    .line 276
    :pswitch_8
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 277
    .line 278
    check-cast v0, Lc80/i;

    .line 279
    .line 280
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast v1, Lay0/a;

    .line 283
    .line 284
    check-cast p1, Ll2/o;

    .line 285
    .line 286
    check-cast p2, Ljava/lang/Integer;

    .line 287
    .line 288
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 289
    .line 290
    .line 291
    iget p2, p0, Lck/h;->e:I

    .line 292
    .line 293
    or-int/lit8 p2, p2, 0x1

    .line 294
    .line 295
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 296
    .line 297
    .line 298
    move-result p2

    .line 299
    iget p0, p0, Lck/h;->f:I

    .line 300
    .line 301
    invoke-static {v0, v1, p1, p2, p0}, Ld80/b;->f(Lc80/i;Lay0/a;Ll2/o;II)V

    .line 302
    .line 303
    .line 304
    goto/16 :goto_0

    .line 305
    .line 306
    :pswitch_9
    iget-object v0, p0, Lck/h;->g:Ljava/lang/Object;

    .line 307
    .line 308
    check-cast v0, Ltd/e;

    .line 309
    .line 310
    iget-object v1, p0, Lck/h;->h:Ljava/lang/Object;

    .line 311
    .line 312
    check-cast v1, Lay0/k;

    .line 313
    .line 314
    check-cast p1, Ll2/o;

    .line 315
    .line 316
    check-cast p2, Ljava/lang/Integer;

    .line 317
    .line 318
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 319
    .line 320
    .line 321
    iget p2, p0, Lck/h;->f:I

    .line 322
    .line 323
    or-int/lit8 p2, p2, 0x1

    .line 324
    .line 325
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 326
    .line 327
    .line 328
    move-result p2

    .line 329
    iget p0, p0, Lck/h;->e:I

    .line 330
    .line 331
    invoke-static {v0, p0, v1, p1, p2}, Lck/i;->d(Ltd/e;ILay0/k;Ll2/o;I)V

    .line 332
    .line 333
    .line 334
    goto/16 :goto_0

    .line 335
    .line 336
    nop

    .line 337
    :pswitch_data_0
    .packed-switch 0x0
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
