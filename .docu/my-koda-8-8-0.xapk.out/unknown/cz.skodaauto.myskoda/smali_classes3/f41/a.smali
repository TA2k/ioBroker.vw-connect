.class public final synthetic Lf41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/b;

.field public final synthetic f:Ls31/k;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lz70/b;Ls31/k;Lay0/k;I)V
    .locals 0

    .line 1
    iput p4, p0, Lf41/a;->d:I

    iput-object p1, p0, Lf41/a;->e:Lz70/b;

    iput-object p2, p0, Lf41/a;->f:Ls31/k;

    iput-object p3, p0, Lf41/a;->g:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lz70/b;Ls31/k;Lay0/k;II)V
    .locals 0

    .line 2
    iput p5, p0, Lf41/a;->d:I

    iput-object p1, p0, Lf41/a;->e:Lz70/b;

    iput-object p2, p0, Lf41/a;->f:Ls31/k;

    iput-object p3, p0, Lf41/a;->g:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lf41/a;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_1

    .line 31
    .line 32
    const/16 p2, 0x40

    .line 33
    .line 34
    iget-object v0, p0, Lf41/a;->e:Lz70/b;

    .line 35
    .line 36
    iget-object v1, p0, Lf41/a;->f:Ls31/k;

    .line 37
    .line 38
    iget-object p0, p0, Lf41/a;->g:Lay0/k;

    .line 39
    .line 40
    invoke-static {v0, v1, p0, p1, p2}, Lkp/h7;->h(Lz70/b;Ls31/k;Lay0/k;Ll2/o;I)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 45
    .line 46
    .line 47
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    and-int/lit8 v0, p2, 0x3

    .line 55
    .line 56
    const/4 v1, 0x2

    .line 57
    const/4 v2, 0x1

    .line 58
    if-eq v0, v1, :cond_2

    .line 59
    .line 60
    move v0, v2

    .line 61
    goto :goto_2

    .line 62
    :cond_2
    const/4 v0, 0x0

    .line 63
    :goto_2
    and-int/2addr p2, v2

    .line 64
    check-cast p1, Ll2/t;

    .line 65
    .line 66
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_3

    .line 71
    .line 72
    const/16 p2, 0x40

    .line 73
    .line 74
    iget-object v0, p0, Lf41/a;->e:Lz70/b;

    .line 75
    .line 76
    iget-object v1, p0, Lf41/a;->f:Ls31/k;

    .line 77
    .line 78
    iget-object p0, p0, Lf41/a;->g:Lay0/k;

    .line 79
    .line 80
    invoke-static {v0, v1, p0, p1, p2}, Lkp/h7;->a(Lz70/b;Ls31/k;Lay0/k;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 85
    .line 86
    .line 87
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    const/16 p2, 0x41

    .line 94
    .line 95
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    iget-object v0, p0, Lf41/a;->e:Lz70/b;

    .line 100
    .line 101
    iget-object v1, p0, Lf41/a;->f:Ls31/k;

    .line 102
    .line 103
    iget-object p0, p0, Lf41/a;->g:Lay0/k;

    .line 104
    .line 105
    invoke-static {v0, v1, p0, p1, p2}, Lkp/h7;->d(Lz70/b;Ls31/k;Lay0/k;Ll2/o;I)V

    .line 106
    .line 107
    .line 108
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0

    .line 111
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    const/16 p2, 0x41

    .line 115
    .line 116
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    iget-object v0, p0, Lf41/a;->e:Lz70/b;

    .line 121
    .line 122
    iget-object v1, p0, Lf41/a;->f:Ls31/k;

    .line 123
    .line 124
    iget-object p0, p0, Lf41/a;->g:Lay0/k;

    .line 125
    .line 126
    invoke-static {v0, v1, p0, p1, p2}, Lkp/h7;->a(Lz70/b;Ls31/k;Lay0/k;Ll2/o;I)V

    .line 127
    .line 128
    .line 129
    goto :goto_4

    .line 130
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    const/16 p2, 0x41

    .line 134
    .line 135
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    iget-object v0, p0, Lf41/a;->e:Lz70/b;

    .line 140
    .line 141
    iget-object v1, p0, Lf41/a;->f:Ls31/k;

    .line 142
    .line 143
    iget-object p0, p0, Lf41/a;->g:Lay0/k;

    .line 144
    .line 145
    invoke-static {v0, v1, p0, p1, p2}, Lkp/h7;->h(Lz70/b;Ls31/k;Lay0/k;Ll2/o;I)V

    .line 146
    .line 147
    .line 148
    goto :goto_4

    .line 149
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 150
    .line 151
    .line 152
    move-result p2

    .line 153
    and-int/lit8 v0, p2, 0x3

    .line 154
    .line 155
    const/4 v1, 0x2

    .line 156
    const/4 v2, 0x1

    .line 157
    const/4 v3, 0x0

    .line 158
    if-eq v0, v1, :cond_4

    .line 159
    .line 160
    move v0, v2

    .line 161
    goto :goto_5

    .line 162
    :cond_4
    move v0, v3

    .line 163
    :goto_5
    and-int/2addr p2, v2

    .line 164
    move-object v8, p1

    .line 165
    check-cast v8, Ll2/t;

    .line 166
    .line 167
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 168
    .line 169
    .line 170
    move-result p1

    .line 171
    if-eqz p1, :cond_8

    .line 172
    .line 173
    const/16 p1, 0x40

    .line 174
    .line 175
    iget-object p2, p0, Lf41/a;->e:Lz70/b;

    .line 176
    .line 177
    iget-object v0, p0, Lf41/a;->f:Ls31/k;

    .line 178
    .line 179
    iget-object p0, p0, Lf41/a;->g:Lay0/k;

    .line 180
    .line 181
    invoke-static {p2, v0, p0, v8, p1}, Lkp/h7;->d(Lz70/b;Ls31/k;Lay0/k;Ll2/o;I)V

    .line 182
    .line 183
    .line 184
    iget-object p1, p2, Lz70/b;->a:Lij0/a;

    .line 185
    .line 186
    iget-boolean p2, v0, Ls31/k;->g:Z

    .line 187
    .line 188
    if-eqz p2, :cond_7

    .line 189
    .line 190
    const p2, 0x7bbfa315

    .line 191
    .line 192
    .line 193
    invoke-virtual {v8, p2}, Ll2/t;->Y(I)V

    .line 194
    .line 195
    .line 196
    sget-object p2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 197
    .line 198
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 199
    .line 200
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    check-cast v0, Lj91/e;

    .line 205
    .line 206
    invoke-virtual {v0}, Lj91/e;->b()J

    .line 207
    .line 208
    .line 209
    move-result-wide v0

    .line 210
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 211
    .line 212
    invoke-static {p2, v0, v1, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 213
    .line 214
    .line 215
    move-result-object p2

    .line 216
    invoke-static {p2, v8, v3}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result p2

    .line 223
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    if-nez p2, :cond_5

    .line 228
    .line 229
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 230
    .line 231
    if-ne v0, p2, :cond_6

    .line 232
    .line 233
    :cond_5
    new-instance v0, Le41/b;

    .line 234
    .line 235
    const/16 p2, 0xb

    .line 236
    .line 237
    invoke-direct {v0, p2, p0}, Le41/b;-><init>(ILay0/k;)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    :cond_6
    move-object v4, v0

    .line 244
    check-cast v4, Lay0/a;

    .line 245
    .line 246
    new-array p0, v3, [Ljava/lang/Object;

    .line 247
    .line 248
    check-cast p1, Ljj0/f;

    .line 249
    .line 250
    const p2, 0x7f1207b7

    .line 251
    .line 252
    .line 253
    invoke-virtual {p1, p2, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v5

    .line 257
    const p0, 0x7f1207b5

    .line 258
    .line 259
    .line 260
    new-array p2, v3, [Ljava/lang/Object;

    .line 261
    .line 262
    invoke-virtual {p1, p0, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v6

    .line 266
    const p0, 0x7f120382

    .line 267
    .line 268
    .line 269
    new-array p2, v3, [Ljava/lang/Object;

    .line 270
    .line 271
    invoke-virtual {p1, p0, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v7

    .line 275
    const/4 v9, 0x0

    .line 276
    invoke-static/range {v4 .. v9}, Lkp/h7;->c(Lay0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 277
    .line 278
    .line 279
    :goto_6
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 280
    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_7
    const p0, 0x7b7d1287

    .line 284
    .line 285
    .line 286
    invoke-virtual {v8, p0}, Ll2/t;->Y(I)V

    .line 287
    .line 288
    .line 289
    goto :goto_6

    .line 290
    :cond_8
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 291
    .line 292
    .line 293
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 294
    .line 295
    return-object p0

    .line 296
    nop

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
