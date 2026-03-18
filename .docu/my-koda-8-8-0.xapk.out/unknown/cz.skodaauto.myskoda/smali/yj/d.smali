.class public final Lyj/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Ljd/i;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Lay0/k;Ljd/i;I)V
    .locals 0

    .line 1
    iput p4, p0, Lyj/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyj/d;->e:Ljava/util/ArrayList;

    .line 4
    .line 5
    iput-object p2, p0, Lyj/d;->f:Lay0/k;

    .line 6
    .line 7
    iput-object p3, p0, Lyj/d;->g:Ljd/i;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lyj/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    check-cast p3, Ll2/o;

    .line 15
    .line 16
    check-cast p4, Ljava/lang/Number;

    .line 17
    .line 18
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    and-int/lit8 p4, p2, 0x6

    .line 23
    .line 24
    if-nez p4, :cond_1

    .line 25
    .line 26
    move-object p4, p3

    .line 27
    check-cast p4, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_0

    .line 34
    .line 35
    const/4 p1, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p1, 0x2

    .line 38
    :goto_0
    or-int/2addr p1, p2

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move p1, p2

    .line 41
    :goto_1
    and-int/lit8 p2, p2, 0x30

    .line 42
    .line 43
    if-nez p2, :cond_3

    .line 44
    .line 45
    move-object p2, p3

    .line 46
    check-cast p2, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {p2, v2}, Ll2/t;->e(I)Z

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    if-eqz p2, :cond_2

    .line 53
    .line 54
    const/16 p2, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 p2, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr p1, p2

    .line 60
    :cond_3
    and-int/lit16 p2, p1, 0x93

    .line 61
    .line 62
    const/16 p4, 0x92

    .line 63
    .line 64
    const/4 v7, 0x1

    .line 65
    const/4 v8, 0x0

    .line 66
    if-eq p2, p4, :cond_4

    .line 67
    .line 68
    move p2, v7

    .line 69
    goto :goto_3

    .line 70
    :cond_4
    move p2, v8

    .line 71
    :goto_3
    and-int/lit8 p4, p1, 0x1

    .line 72
    .line 73
    move-object v4, p3

    .line 74
    check-cast v4, Ll2/t;

    .line 75
    .line 76
    invoke-virtual {v4, p4, p2}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    if-eqz p2, :cond_6

    .line 81
    .line 82
    iget-object p2, p0, Lyj/d;->e:Ljava/util/ArrayList;

    .line 83
    .line 84
    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    and-int/lit8 p1, p1, 0x7e

    .line 89
    .line 90
    move-object v0, p2

    .line 91
    check-cast v0, Lkd/a;

    .line 92
    .line 93
    const p2, -0x1a1040b7

    .line 94
    .line 95
    .line 96
    invoke-virtual {v4, p2}, Ll2/t;->Y(I)V

    .line 97
    .line 98
    .line 99
    shl-int/lit8 p1, p1, 0x3

    .line 100
    .line 101
    and-int/lit16 v5, p1, 0x380

    .line 102
    .line 103
    const/16 v6, 0x8

    .line 104
    .line 105
    iget-object v1, p0, Lyj/d;->f:Lay0/k;

    .line 106
    .line 107
    const/4 v3, 0x0

    .line 108
    invoke-static/range {v0 .. v6}, Lyj/a;->i(Lkd/a;Lay0/k;IZLl2/o;II)V

    .line 109
    .line 110
    .line 111
    iget-object p0, p0, Lyj/d;->g:Ljd/i;

    .line 112
    .line 113
    iget-object p0, p0, Ljd/i;->c:Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-eq v2, p0, :cond_5

    .line 120
    .line 121
    const p0, -0x1a0ec954

    .line 122
    .line 123
    .line 124
    invoke-virtual {v4, p0}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    const/4 p0, 0x0

    .line 128
    invoke-static {v8, v7, v4, p0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 129
    .line 130
    .line 131
    :goto_4
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 132
    .line 133
    .line 134
    goto :goto_5

    .line 135
    :cond_5
    const p0, -0x1a71755d

    .line 136
    .line 137
    .line 138
    invoke-virtual {v4, p0}, Ll2/t;->Y(I)V

    .line 139
    .line 140
    .line 141
    goto :goto_4

    .line 142
    :goto_5
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 143
    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_6
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 147
    .line 148
    .line 149
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_0
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 153
    .line 154
    check-cast p2, Ljava/lang/Number;

    .line 155
    .line 156
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    check-cast p3, Ll2/o;

    .line 161
    .line 162
    check-cast p4, Ljava/lang/Number;

    .line 163
    .line 164
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 165
    .line 166
    .line 167
    move-result p2

    .line 168
    and-int/lit8 p4, p2, 0x6

    .line 169
    .line 170
    if-nez p4, :cond_8

    .line 171
    .line 172
    move-object p4, p3

    .line 173
    check-cast p4, Ll2/t;

    .line 174
    .line 175
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result p1

    .line 179
    if-eqz p1, :cond_7

    .line 180
    .line 181
    const/4 p1, 0x4

    .line 182
    goto :goto_7

    .line 183
    :cond_7
    const/4 p1, 0x2

    .line 184
    :goto_7
    or-int/2addr p1, p2

    .line 185
    goto :goto_8

    .line 186
    :cond_8
    move p1, p2

    .line 187
    :goto_8
    and-int/lit8 p2, p2, 0x30

    .line 188
    .line 189
    if-nez p2, :cond_a

    .line 190
    .line 191
    move-object p2, p3

    .line 192
    check-cast p2, Ll2/t;

    .line 193
    .line 194
    invoke-virtual {p2, v2}, Ll2/t;->e(I)Z

    .line 195
    .line 196
    .line 197
    move-result p2

    .line 198
    if-eqz p2, :cond_9

    .line 199
    .line 200
    const/16 p2, 0x20

    .line 201
    .line 202
    goto :goto_9

    .line 203
    :cond_9
    const/16 p2, 0x10

    .line 204
    .line 205
    :goto_9
    or-int/2addr p1, p2

    .line 206
    :cond_a
    and-int/lit16 p2, p1, 0x93

    .line 207
    .line 208
    const/16 p4, 0x92

    .line 209
    .line 210
    const/4 v7, 0x1

    .line 211
    const/4 v8, 0x0

    .line 212
    if-eq p2, p4, :cond_b

    .line 213
    .line 214
    move p2, v7

    .line 215
    goto :goto_a

    .line 216
    :cond_b
    move p2, v8

    .line 217
    :goto_a
    and-int/lit8 p4, p1, 0x1

    .line 218
    .line 219
    move-object v4, p3

    .line 220
    check-cast v4, Ll2/t;

    .line 221
    .line 222
    invoke-virtual {v4, p4, p2}, Ll2/t;->O(IZ)Z

    .line 223
    .line 224
    .line 225
    move-result p2

    .line 226
    if-eqz p2, :cond_d

    .line 227
    .line 228
    iget-object p2, p0, Lyj/d;->e:Ljava/util/ArrayList;

    .line 229
    .line 230
    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p2

    .line 234
    and-int/lit8 p1, p1, 0x7e

    .line 235
    .line 236
    move-object v0, p2

    .line 237
    check-cast v0, Lkd/a;

    .line 238
    .line 239
    const p2, 0x60905e21

    .line 240
    .line 241
    .line 242
    invoke-virtual {v4, p2}, Ll2/t;->Y(I)V

    .line 243
    .line 244
    .line 245
    shl-int/lit8 p1, p1, 0x3

    .line 246
    .line 247
    and-int/lit16 p1, p1, 0x380

    .line 248
    .line 249
    const/16 p2, 0xc00

    .line 250
    .line 251
    or-int v5, p2, p1

    .line 252
    .line 253
    const/4 v6, 0x0

    .line 254
    iget-object v1, p0, Lyj/d;->f:Lay0/k;

    .line 255
    .line 256
    const/4 v3, 0x1

    .line 257
    invoke-static/range {v0 .. v6}, Lyj/a;->i(Lkd/a;Lay0/k;IZLl2/o;II)V

    .line 258
    .line 259
    .line 260
    iget-object p0, p0, Lyj/d;->g:Ljd/i;

    .line 261
    .line 262
    iget-object p0, p0, Ljd/i;->b:Ljava/util/ArrayList;

    .line 263
    .line 264
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 265
    .line 266
    .line 267
    move-result p0

    .line 268
    if-eq v2, p0, :cond_c

    .line 269
    .line 270
    const p0, 0x6091d1c3

    .line 271
    .line 272
    .line 273
    invoke-virtual {v4, p0}, Ll2/t;->Y(I)V

    .line 274
    .line 275
    .line 276
    const/4 p0, 0x0

    .line 277
    invoke-static {v8, v7, v4, p0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 278
    .line 279
    .line 280
    :goto_b
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 281
    .line 282
    .line 283
    goto :goto_c

    .line 284
    :cond_c
    const p0, 0x6035f19a

    .line 285
    .line 286
    .line 287
    invoke-virtual {v4, p0}, Ll2/t;->Y(I)V

    .line 288
    .line 289
    .line 290
    goto :goto_b

    .line 291
    :goto_c
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 292
    .line 293
    .line 294
    goto :goto_d

    .line 295
    :cond_d
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 296
    .line 297
    .line 298
    :goto_d
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 299
    .line 300
    return-object p0

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
