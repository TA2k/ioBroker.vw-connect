.class public final synthetic Li40/v1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/v2;


# direct methods
.method public synthetic constructor <init>(Lh40/v2;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li40/v1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/v1;->e:Lh40/v2;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/v2;II)V
    .locals 0

    .line 2
    iput p3, p0, Li40/v1;->d:I

    iput-object p1, p0, Li40/v1;->e:Lh40/v2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Li40/v1;->d:I

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
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object p0, p0, Li40/v1;->e:Lh40/v2;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Li40/l1;->L(Lh40/v2;Ll2/o;I)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const/4 p2, 0x1

    .line 30
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    iget-object p0, p0, Li40/v1;->e:Lh40/v2;

    .line 35
    .line 36
    invoke-static {p0, p1, p2}, Li40/l1;->m(Lh40/v2;Ll2/o;I)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    and-int/lit8 v0, p2, 0x3

    .line 45
    .line 46
    const/4 v1, 0x2

    .line 47
    const/4 v2, 0x1

    .line 48
    const/4 v3, 0x0

    .line 49
    if-eq v0, v1, :cond_0

    .line 50
    .line 51
    move v0, v2

    .line 52
    goto :goto_1

    .line 53
    :cond_0
    move v0, v3

    .line 54
    :goto_1
    and-int/2addr p2, v2

    .line 55
    check-cast p1, Ll2/t;

    .line 56
    .line 57
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    if-eqz p2, :cond_7

    .line 62
    .line 63
    sget-object p2, Lj91/a;->a:Ll2/u2;

    .line 64
    .line 65
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, Lj91/c;

    .line 70
    .line 71
    iget v0, v0, Lj91/c;->d:F

    .line 72
    .line 73
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 74
    .line 75
    invoke-static {v4, v0}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 80
    .line 81
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 82
    .line 83
    invoke-static {v1, v5, p1, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    iget-wide v5, p1, Ll2/t;->T:J

    .line 88
    .line 89
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 90
    .line 91
    .line 92
    move-result v5

    .line 93
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    invoke-static {p1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 102
    .line 103
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 107
    .line 108
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 109
    .line 110
    .line 111
    iget-boolean v8, p1, Ll2/t;->S:Z

    .line 112
    .line 113
    if-eqz v8, :cond_1

    .line 114
    .line 115
    invoke-virtual {p1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 116
    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 120
    .line 121
    .line 122
    :goto_2
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 123
    .line 124
    invoke-static {v7, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 125
    .line 126
    .line 127
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 128
    .line 129
    invoke-static {v1, v6, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 133
    .line 134
    iget-boolean v6, p1, Ll2/t;->S:Z

    .line 135
    .line 136
    if-nez v6, :cond_2

    .line 137
    .line 138
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object v7

    .line 146
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v6

    .line 150
    if-nez v6, :cond_3

    .line 151
    .line 152
    :cond_2
    invoke-static {v5, p1, v5, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 153
    .line 154
    .line 155
    :cond_3
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 156
    .line 157
    invoke-static {v1, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 158
    .line 159
    .line 160
    const/4 v0, 0x0

    .line 161
    invoke-static {v3, v2, p1, v0}, Li40/l1;->r0(IILl2/o;Lx2/s;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p2

    .line 168
    check-cast p2, Lj91/c;

    .line 169
    .line 170
    iget v6, p2, Lj91/c;->d:F

    .line 171
    .line 172
    const/16 p2, 0xc

    .line 173
    .line 174
    int-to-float v8, p2

    .line 175
    const/4 v9, 0x5

    .line 176
    const/4 v5, 0x0

    .line 177
    const/4 v7, 0x0

    .line 178
    invoke-static/range {v4 .. v9}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 179
    .line 180
    .line 181
    move-result-object p2

    .line 182
    invoke-static {v3, v3, p1, p2}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 183
    .line 184
    .line 185
    iget-object p0, p0, Li40/v1;->e:Lh40/v2;

    .line 186
    .line 187
    iget-boolean p2, p0, Lh40/v2;->a:Z

    .line 188
    .line 189
    if-eqz p2, :cond_4

    .line 190
    .line 191
    const p0, 0x7847a7ad

    .line 192
    .line 193
    .line 194
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 195
    .line 196
    .line 197
    invoke-static {p1, v3}, Li40/l1;->n(Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_4
    iget-object p2, p0, Lh40/v2;->b:Ljava/lang/Boolean;

    .line 205
    .line 206
    if-nez p2, :cond_5

    .line 207
    .line 208
    const p0, 0x7847aff1

    .line 209
    .line 210
    .line 211
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 212
    .line 213
    .line 214
    invoke-static {p1, v3}, Li40/l1;->M(Ll2/o;I)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 218
    .line 219
    .line 220
    goto :goto_3

    .line 221
    :cond_5
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 222
    .line 223
    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result p2

    .line 227
    if-eqz p2, :cond_6

    .line 228
    .line 229
    const p2, 0x7847b8b5

    .line 230
    .line 231
    .line 232
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 233
    .line 234
    .line 235
    invoke-static {p0, p1, v3}, Li40/l1;->m(Lh40/v2;Ll2/o;I)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 239
    .line 240
    .line 241
    goto :goto_3

    .line 242
    :cond_6
    const p2, 0x7847bf2b

    .line 243
    .line 244
    .line 245
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 246
    .line 247
    .line 248
    invoke-static {p0, p1, v3}, Li40/l1;->L(Lh40/v2;Ll2/o;I)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 252
    .line 253
    .line 254
    :goto_3
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 255
    .line 256
    .line 257
    goto :goto_4

    .line 258
    :cond_7
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 259
    .line 260
    .line 261
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    return-object p0

    .line 264
    nop

    .line 265
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
