.class public final synthetic Ld90/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILc90/a;Lay0/k;Lc90/e0;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld90/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ld90/k;->e:I

    iput-object p2, p0, Ld90/k;->g:Ljava/lang/Object;

    iput-object p3, p0, Ld90/k;->f:Lay0/k;

    iput-object p4, p0, Ld90/k;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;ILvy0/b0;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ld90/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld90/k;->g:Ljava/lang/Object;

    iput p2, p0, Ld90/k;->e:I

    iput-object p3, p0, Ld90/k;->h:Ljava/lang/Object;

    iput-object p4, p0, Ld90/k;->f:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Ld90/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld90/k;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/util/List;

    .line 10
    .line 11
    iget-object v0, p0, Ld90/k;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvy0/b0;

    .line 14
    .line 15
    check-cast p1, Lxf0/d2;

    .line 16
    .line 17
    check-cast p2, Ll2/o;

    .line 18
    .line 19
    check-cast p3, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 22
    .line 23
    .line 24
    move-result p3

    .line 25
    const-string v2, "$this$ModalBottomSheetDialog"

    .line 26
    .line 27
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    and-int/lit8 v2, p3, 0x6

    .line 31
    .line 32
    const/4 v3, 0x4

    .line 33
    if-nez v2, :cond_2

    .line 34
    .line 35
    and-int/lit8 v2, p3, 0x8

    .line 36
    .line 37
    if-nez v2, :cond_0

    .line 38
    .line 39
    move-object v2, p2

    .line 40
    check-cast v2, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {v2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move-object v2, p2

    .line 48
    check-cast v2, Ll2/t;

    .line 49
    .line 50
    invoke-virtual {v2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    :goto_0
    if-eqz v2, :cond_1

    .line 55
    .line 56
    move v2, v3

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    const/4 v2, 0x2

    .line 59
    :goto_1
    or-int/2addr p3, v2

    .line 60
    :cond_2
    and-int/lit8 v2, p3, 0x13

    .line 61
    .line 62
    const/16 v4, 0x12

    .line 63
    .line 64
    const/4 v5, 0x0

    .line 65
    const/4 v6, 0x1

    .line 66
    if-eq v2, v4, :cond_3

    .line 67
    .line 68
    move v2, v6

    .line 69
    goto :goto_2

    .line 70
    :cond_3
    move v2, v5

    .line 71
    :goto_2
    and-int/lit8 v4, p3, 0x1

    .line 72
    .line 73
    check-cast p2, Ll2/t;

    .line 74
    .line 75
    invoke-virtual {p2, v4, v2}, Ll2/t;->O(IZ)Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-eqz v2, :cond_8

    .line 80
    .line 81
    invoke-virtual {p2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    and-int/lit8 v4, p3, 0xe

    .line 86
    .line 87
    if-eq v4, v3, :cond_4

    .line 88
    .line 89
    and-int/lit8 p3, p3, 0x8

    .line 90
    .line 91
    if-eqz p3, :cond_5

    .line 92
    .line 93
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p3

    .line 97
    if-eqz p3, :cond_5

    .line 98
    .line 99
    :cond_4
    move v5, v6

    .line 100
    :cond_5
    or-int p3, v2, v5

    .line 101
    .line 102
    iget-object v2, p0, Ld90/k;->f:Lay0/k;

    .line 103
    .line 104
    invoke-virtual {p2, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    or-int/2addr p3, v3

    .line 109
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    if-nez p3, :cond_6

    .line 114
    .line 115
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 116
    .line 117
    if-ne v3, p3, :cond_7

    .line 118
    .line 119
    :cond_6
    new-instance v3, Li40/g2;

    .line 120
    .line 121
    const/4 p3, 0x1

    .line 122
    invoke-direct {v3, v0, p1, v2, p3}, Li40/g2;-><init>(Lvy0/b0;Lxf0/d2;Lay0/k;I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_7
    check-cast v3, Lay0/k;

    .line 129
    .line 130
    const/4 v5, 0x0

    .line 131
    const/4 v6, 0x0

    .line 132
    iget v2, p0, Ld90/k;->e:I

    .line 133
    .line 134
    move-object v4, p2

    .line 135
    invoke-static/range {v1 .. v6}, Lx80/a;->b(Ljava/util/List;ILay0/k;Ll2/o;II)V

    .line 136
    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_8
    move-object v4, p2

    .line 140
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 141
    .line 142
    .line 143
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 144
    .line 145
    return-object p0

    .line 146
    :pswitch_0
    iget-object v0, p0, Ld90/k;->g:Ljava/lang/Object;

    .line 147
    .line 148
    move-object v1, v0

    .line 149
    check-cast v1, Lc90/a;

    .line 150
    .line 151
    iget-object v0, p0, Ld90/k;->h:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v0, Lc90/e0;

    .line 154
    .line 155
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 156
    .line 157
    check-cast p2, Ll2/o;

    .line 158
    .line 159
    check-cast p3, Ljava/lang/Integer;

    .line 160
    .line 161
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 162
    .line 163
    .line 164
    move-result p3

    .line 165
    const-string v2, "$this$item"

    .line 166
    .line 167
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    and-int/lit8 p1, p3, 0x11

    .line 171
    .line 172
    const/16 v2, 0x10

    .line 173
    .line 174
    const/4 v3, 0x1

    .line 175
    const/4 v7, 0x0

    .line 176
    if-eq p1, v2, :cond_9

    .line 177
    .line 178
    move p1, v3

    .line 179
    goto :goto_4

    .line 180
    :cond_9
    move p1, v7

    .line 181
    :goto_4
    and-int/2addr p3, v3

    .line 182
    move-object v4, p2

    .line 183
    check-cast v4, Ll2/t;

    .line 184
    .line 185
    invoke-virtual {v4, p3, p1}, Ll2/t;->O(IZ)Z

    .line 186
    .line 187
    .line 188
    move-result p1

    .line 189
    if-eqz p1, :cond_c

    .line 190
    .line 191
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 192
    .line 193
    iget p2, p0, Ld90/k;->e:I

    .line 194
    .line 195
    const p3, -0x342ffc93    # -2.726473E7f

    .line 196
    .line 197
    .line 198
    if-nez p2, :cond_a

    .line 199
    .line 200
    const v2, -0x33ed5ce2    # -3.8440056E7f

    .line 201
    .line 202
    .line 203
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    .line 204
    .line 205
    .line 206
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 207
    .line 208
    invoke-virtual {v4, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v2

    .line 212
    check-cast v2, Lj91/c;

    .line 213
    .line 214
    iget v2, v2, Lj91/c;->e:F

    .line 215
    .line 216
    invoke-static {p1, v2, v4, v7}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 217
    .line 218
    .line 219
    goto :goto_5

    .line 220
    :cond_a
    invoke-virtual {v4, p3}, Ll2/t;->Y(I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v4, v7}, Ll2/t;->q(Z)V

    .line 224
    .line 225
    .line 226
    :goto_5
    sget v2, Ld90/l;->a:F

    .line 227
    .line 228
    invoke-static {p1, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    const/16 v5, 0x30

    .line 233
    .line 234
    const/4 v6, 0x0

    .line 235
    iget-object v3, p0, Ld90/k;->f:Lay0/k;

    .line 236
    .line 237
    invoke-static/range {v1 .. v6}, Ld90/x;->a(Lc90/a;Lx2/s;Lay0/k;Ll2/o;II)V

    .line 238
    .line 239
    .line 240
    iget-object p0, v0, Lc90/e0;->c:Ljava/util/List;

    .line 241
    .line 242
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 243
    .line 244
    .line 245
    move-result p0

    .line 246
    if-ne p2, p0, :cond_b

    .line 247
    .line 248
    const p0, -0x33e77982    # -3.9983608E7f

    .line 249
    .line 250
    .line 251
    invoke-virtual {v4, p0}, Ll2/t;->Y(I)V

    .line 252
    .line 253
    .line 254
    sget-object p0, Lj91/a;->a:Ll2/u2;

    .line 255
    .line 256
    invoke-virtual {v4, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object p0

    .line 260
    check-cast p0, Lj91/c;

    .line 261
    .line 262
    iget p0, p0, Lj91/c;->e:F

    .line 263
    .line 264
    invoke-static {p1, p0, v4, v7}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 265
    .line 266
    .line 267
    goto :goto_6

    .line 268
    :cond_b
    invoke-virtual {v4, p3}, Ll2/t;->Y(I)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v4, v7}, Ll2/t;->q(Z)V

    .line 272
    .line 273
    .line 274
    goto :goto_6

    .line 275
    :cond_c
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 276
    .line 277
    .line 278
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 279
    .line 280
    return-object p0

    .line 281
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
