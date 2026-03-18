.class public abstract Llp/mb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Ly6/q;Lj7/g;ILl2/o;II)V
    .locals 9

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, -0xb7f9811

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p5, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p5

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p5

    .line 25
    :goto_1
    and-int/lit8 v1, p6, 0x2

    .line 26
    .line 27
    if-eqz v1, :cond_2

    .line 28
    .line 29
    or-int/lit8 v0, v0, 0x30

    .line 30
    .line 31
    goto :goto_3

    .line 32
    :cond_2
    and-int/lit8 v2, p5, 0x30

    .line 33
    .line 34
    if-nez v2, :cond_4

    .line 35
    .line 36
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_3

    .line 41
    .line 42
    const/16 v2, 0x20

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_3
    const/16 v2, 0x10

    .line 46
    .line 47
    :goto_2
    or-int/2addr v0, v2

    .line 48
    :cond_4
    :goto_3
    and-int/lit16 v2, p5, 0x180

    .line 49
    .line 50
    if-nez v2, :cond_6

    .line 51
    .line 52
    invoke-virtual {p4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_5

    .line 57
    .line 58
    const/16 v2, 0x100

    .line 59
    .line 60
    goto :goto_4

    .line 61
    :cond_5
    const/16 v2, 0x80

    .line 62
    .line 63
    :goto_4
    or-int/2addr v0, v2

    .line 64
    :cond_6
    and-int/lit8 v2, p6, 0x8

    .line 65
    .line 66
    if-eqz v2, :cond_7

    .line 67
    .line 68
    or-int/lit16 v0, v0, 0xc00

    .line 69
    .line 70
    goto :goto_6

    .line 71
    :cond_7
    and-int/lit16 v3, p5, 0xc00

    .line 72
    .line 73
    if-nez v3, :cond_9

    .line 74
    .line 75
    invoke-virtual {p4, p3}, Ll2/t;->e(I)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_8

    .line 80
    .line 81
    const/16 v3, 0x800

    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_8
    const/16 v3, 0x400

    .line 85
    .line 86
    :goto_5
    or-int/2addr v0, v3

    .line 87
    :cond_9
    :goto_6
    and-int/lit16 v0, v0, 0x493

    .line 88
    .line 89
    const/16 v3, 0x492

    .line 90
    .line 91
    if-ne v0, v3, :cond_b

    .line 92
    .line 93
    invoke-virtual {p4}, Ll2/t;->A()Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-nez v0, :cond_a

    .line 98
    .line 99
    goto :goto_8

    .line 100
    :cond_a
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 101
    .line 102
    .line 103
    :goto_7
    move-object v4, p1

    .line 104
    move v6, p3

    .line 105
    goto/16 :goto_c

    .line 106
    .line 107
    :cond_b
    :goto_8
    invoke-virtual {p4}, Ll2/t;->T()V

    .line 108
    .line 109
    .line 110
    and-int/lit8 v0, p5, 0x1

    .line 111
    .line 112
    if-eqz v0, :cond_d

    .line 113
    .line 114
    invoke-virtual {p4}, Ll2/t;->y()Z

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-eqz v0, :cond_c

    .line 119
    .line 120
    goto :goto_9

    .line 121
    :cond_c
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 122
    .line 123
    .line 124
    goto :goto_a

    .line 125
    :cond_d
    :goto_9
    if-eqz v1, :cond_e

    .line 126
    .line 127
    sget-object p1, Ly6/o;->a:Ly6/o;

    .line 128
    .line 129
    :cond_e
    if-eqz v2, :cond_f

    .line 130
    .line 131
    const p3, 0x7fffffff

    .line 132
    .line 133
    .line 134
    :cond_f
    :goto_a
    invoke-virtual {p4}, Ll2/t;->r()V

    .line 135
    .line 136
    .line 137
    sget-object v0, Lj7/d;->d:Lj7/d;

    .line 138
    .line 139
    const v1, -0x428332f6

    .line 140
    .line 141
    .line 142
    invoke-virtual {p4, v1}, Ll2/t;->Z(I)V

    .line 143
    .line 144
    .line 145
    const v1, 0x7076b8d0

    .line 146
    .line 147
    .line 148
    invoke-virtual {p4, v1}, Ll2/t;->Z(I)V

    .line 149
    .line 150
    .line 151
    iget-object v1, p4, Ll2/t;->a:Leb/j0;

    .line 152
    .line 153
    instance-of v1, v1, Ly6/b;

    .line 154
    .line 155
    if-eqz v1, :cond_14

    .line 156
    .line 157
    invoke-virtual {p4}, Ll2/t;->W()V

    .line 158
    .line 159
    .line 160
    iget-boolean v1, p4, Ll2/t;->S:Z

    .line 161
    .line 162
    if-eqz v1, :cond_10

    .line 163
    .line 164
    new-instance v1, La7/j;

    .line 165
    .line 166
    invoke-direct {v1, v0}, La7/j;-><init>(Lay0/a;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {p4, v1}, Ll2/t;->l(Lay0/a;)V

    .line 170
    .line 171
    .line 172
    goto :goto_b

    .line 173
    :cond_10
    invoke-virtual {p4}, Ll2/t;->m0()V

    .line 174
    .line 175
    .line 176
    :goto_b
    sget-object v0, Lj7/e;->g:Lj7/e;

    .line 177
    .line 178
    invoke-static {v0, p0, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 179
    .line 180
    .line 181
    sget-object v0, Lj7/e;->h:Lj7/e;

    .line 182
    .line 183
    invoke-static {v0, p1, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 184
    .line 185
    .line 186
    sget-object v0, Lj7/e;->i:Lj7/e;

    .line 187
    .line 188
    invoke-static {v0, p2, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 189
    .line 190
    .line 191
    sget-object v0, Lj7/e;->j:Lj7/e;

    .line 192
    .line 193
    iget-boolean v1, p4, Ll2/t;->S:Z

    .line 194
    .line 195
    if-nez v1, :cond_11

    .line 196
    .line 197
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v1

    .line 209
    if-nez v1, :cond_12

    .line 210
    .line 211
    :cond_11
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    invoke-virtual {p4, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    invoke-virtual {p4, v1, v0}, Ll2/t;->b(Ljava/lang/Object;Lay0/n;)V

    .line 223
    .line 224
    .line 225
    :cond_12
    const/4 v0, 0x1

    .line 226
    const/4 v1, 0x0

    .line 227
    invoke-static {p4, v0, v1, v1}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 228
    .line 229
    .line 230
    goto :goto_7

    .line 231
    :goto_c
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    if-eqz p1, :cond_13

    .line 236
    .line 237
    new-instance v2, Lj7/f;

    .line 238
    .line 239
    move-object v3, p0

    .line 240
    move-object v5, p2

    .line 241
    move v7, p5

    .line 242
    move v8, p6

    .line 243
    invoke-direct/range {v2 .. v8}, Lj7/f;-><init>(Ljava/lang/String;Ly6/q;Lj7/g;III)V

    .line 244
    .line 245
    .line 246
    iput-object v2, p1, Ll2/u1;->d:Lay0/n;

    .line 247
    .line 248
    :cond_13
    return-void

    .line 249
    :cond_14
    invoke-static {}, Ll2/b;->l()V

    .line 250
    .line 251
    .line 252
    const/4 p0, 0x0

    .line 253
    throw p0
.end method
