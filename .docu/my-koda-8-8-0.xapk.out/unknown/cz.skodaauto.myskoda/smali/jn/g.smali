.class public final Ljn/g;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Ljn/g;->f:I

    iput-object p3, p0, Ljn/g;->h:Ljava/lang/Object;

    iput-object p4, p0, Ljn/g;->i:Ljava/lang/Object;

    iput p1, p0, Ljn/g;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(ILk1/a1;Lt2/b;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Ljn/g;->f:I

    .line 2
    iput p1, p0, Ljn/g;->g:I

    iput-object p2, p0, Ljn/g;->h:Ljava/lang/Object;

    iput-object p3, p0, Ljn/g;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZII)V
    .locals 0

    .line 3
    iput p5, p0, Ljn/g;->f:I

    iput-object p1, p0, Ljn/g;->i:Ljava/lang/Object;

    iput-object p2, p0, Ljn/g;->h:Ljava/lang/Object;

    iput p4, p0, Ljn/g;->g:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ljn/g;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    iget-object p2, p0, Ljn/g;->i:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p2, Lx2/s;

    .line 16
    .line 17
    iget-object v0, p0, Ljn/g;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lay0/n;

    .line 20
    .line 21
    iget p0, p0, Ljn/g;->g:I

    .line 22
    .line 23
    or-int/lit8 p0, p0, 0x1

    .line 24
    .line 25
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    invoke-static {p2, v0, p1, p0}, Llp/ge;->b(Lx2/s;Lay0/n;Ll2/o;I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 36
    .line 37
    check-cast p2, Ljava/lang/Number;

    .line 38
    .line 39
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    const/4 v0, 0x0

    .line 44
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    and-int/lit8 p2, p2, 0xb

    .line 49
    .line 50
    const/4 v2, 0x2

    .line 51
    if-ne p2, v2, :cond_1

    .line 52
    .line 53
    move-object p2, p1

    .line 54
    check-cast p2, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-nez v2, :cond_0

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 64
    .line 65
    .line 66
    goto/16 :goto_3

    .line 67
    .line 68
    :cond_1
    :goto_0
    move p2, v0

    .line 69
    :goto_1
    iget v2, p0, Ljn/g;->g:I

    .line 70
    .line 71
    if-ge p2, v2, :cond_5

    .line 72
    .line 73
    iget-object v2, p0, Ljn/g;->h:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v2, Lk1/a1;

    .line 76
    .line 77
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 78
    .line 79
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    iget-object v3, p0, Ljn/g;->i:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v3, Lt2/b;

    .line 86
    .line 87
    move-object v4, p1

    .line 88
    check-cast v4, Ll2/t;

    .line 89
    .line 90
    const v5, 0x2bb5b5d7

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4, v5}, Ll2/t;->Z(I)V

    .line 94
    .line 95
    .line 96
    invoke-static {v4}, Lk1/n;->e(Ll2/o;)Lk1/p;

    .line 97
    .line 98
    .line 99
    move-result-object v5

    .line 100
    const v6, -0x4ee9b9da

    .line 101
    .line 102
    .line 103
    invoke-virtual {v4, v6}, Ll2/t;->Z(I)V

    .line 104
    .line 105
    .line 106
    iget-wide v6, v4, Ll2/t;->T:J

    .line 107
    .line 108
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 109
    .line 110
    .line 111
    move-result v6

    .line 112
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 117
    .line 118
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 122
    .line 123
    invoke-static {v2}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 128
    .line 129
    .line 130
    iget-boolean v9, v4, Ll2/t;->S:Z

    .line 131
    .line 132
    if-eqz v9, :cond_2

    .line 133
    .line 134
    invoke-virtual {v4, v8}, Ll2/t;->l(Lay0/a;)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_2
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 139
    .line 140
    .line 141
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 142
    .line 143
    invoke-static {v8, v5, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 144
    .line 145
    .line 146
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 147
    .line 148
    invoke-static {v5, v7, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    .line 150
    .line 151
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 152
    .line 153
    iget-boolean v7, v4, Ll2/t;->S:Z

    .line 154
    .line 155
    if-nez v7, :cond_3

    .line 156
    .line 157
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v7

    .line 161
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 162
    .line 163
    .line 164
    move-result-object v8

    .line 165
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v7

    .line 169
    if-nez v7, :cond_4

    .line 170
    .line 171
    :cond_3
    invoke-static {v6, v4, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 172
    .line 173
    .line 174
    :cond_4
    new-instance v5, Ll2/d2;

    .line 175
    .line 176
    invoke-direct {v5, v4}, Ll2/d2;-><init>(Ll2/o;)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v2, v5, v4, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    const v2, 0x7ab4aae9

    .line 183
    .line 184
    .line 185
    invoke-virtual {v4, v2}, Ll2/t;->Z(I)V

    .line 186
    .line 187
    .line 188
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    invoke-virtual {v3, v2, v4, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 196
    .line 197
    .line 198
    const/4 v2, 0x1

    .line 199
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 206
    .line 207
    .line 208
    add-int/lit8 p2, p2, 0x1

    .line 209
    .line 210
    goto/16 :goto_1

    .line 211
    .line 212
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 213
    .line 214
    return-object p0

    .line 215
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 216
    .line 217
    check-cast p2, Ljava/lang/Number;

    .line 218
    .line 219
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 220
    .line 221
    .line 222
    iget-object p2, p0, Ljn/g;->i:Ljava/lang/Object;

    .line 223
    .line 224
    check-cast p2, Lvv/m0;

    .line 225
    .line 226
    iget-object v0, p0, Ljn/g;->h:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast v0, Ljava/lang/String;

    .line 229
    .line 230
    iget p0, p0, Ljn/g;->g:I

    .line 231
    .line 232
    or-int/lit8 p0, p0, 0x1

    .line 233
    .line 234
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 235
    .line 236
    .line 237
    move-result p0

    .line 238
    invoke-static {p2, v0, p1, p0}, Lvv/j;->a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V

    .line 239
    .line 240
    .line 241
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 242
    .line 243
    return-object p0

    .line 244
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 245
    .line 246
    check-cast p2, Ljava/lang/Number;

    .line 247
    .line 248
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 249
    .line 250
    .line 251
    iget-object p2, p0, Ljn/g;->h:Ljava/lang/Object;

    .line 252
    .line 253
    check-cast p2, Lvv/c;

    .line 254
    .line 255
    iget-object v0, p0, Ljn/g;->i:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v0, Lvv/m0;

    .line 258
    .line 259
    iget p0, p0, Ljn/g;->g:I

    .line 260
    .line 261
    or-int/lit8 p0, p0, 0x1

    .line 262
    .line 263
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 264
    .line 265
    .line 266
    move-result p0

    .line 267
    invoke-virtual {p2, v0, p1, p0}, Lvv/c;->a(Lvv/m0;Ll2/o;I)V

    .line 268
    .line 269
    .line 270
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 274
    .line 275
    check-cast p2, Ljava/lang/Number;

    .line 276
    .line 277
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 278
    .line 279
    .line 280
    iget-object p2, p0, Ljn/g;->h:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast p2, Ljava/lang/String;

    .line 283
    .line 284
    iget-object v0, p0, Ljn/g;->i:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v0, Lx2/s;

    .line 287
    .line 288
    iget p0, p0, Ljn/g;->g:I

    .line 289
    .line 290
    or-int/lit8 p0, p0, 0x1

    .line 291
    .line 292
    invoke-static {p0, p2, p1, v0}, Llp/dc;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 293
    .line 294
    .line 295
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    return-object p0

    .line 298
    nop

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
