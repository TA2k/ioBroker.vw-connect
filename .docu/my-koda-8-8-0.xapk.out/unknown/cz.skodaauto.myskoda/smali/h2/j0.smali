.class public final Lh2/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lh2/r8;

.field public final synthetic e:Lvy0/b0;

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/String;

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Lay0/n;


# direct methods
.method public constructor <init>(Lh2/r8;Lvy0/b0;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/j0;->d:Lh2/r8;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/j0;->e:Lvy0/b0;

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/j0;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lh2/j0;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/j0;->h:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/j0;->i:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/j0;->j:Lay0/n;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v6

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v6

    .line 26
    check-cast v1, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_8

    .line 33
    .line 34
    iget-object v2, v0, Lh2/j0;->d:Lh2/r8;

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    iget-object v4, v0, Lh2/j0;->e:Lvy0/b0;

    .line 41
    .line 42
    invoke-virtual {v1, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v7

    .line 46
    or-int/2addr v3, v7

    .line 47
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 52
    .line 53
    if-nez v3, :cond_1

    .line 54
    .line 55
    if-ne v7, v8, :cond_2

    .line 56
    .line 57
    :cond_1
    new-instance v7, Lh2/g0;

    .line 58
    .line 59
    const/4 v3, 0x0

    .line 60
    invoke-direct {v7, v2, v4, v3}, Lh2/g0;-><init>(Lh2/r8;Lvy0/b0;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v1, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    check-cast v7, Lay0/a;

    .line 67
    .line 68
    invoke-static {v7}, Landroidx/compose/foundation/a;->e(Lay0/a;)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    iget-boolean v7, v0, Lh2/j0;->f:Z

    .line 77
    .line 78
    invoke-virtual {v1, v7}, Ll2/t;->h(Z)Z

    .line 79
    .line 80
    .line 81
    move-result v7

    .line 82
    or-int/2addr v2, v7

    .line 83
    iget-object v7, v0, Lh2/j0;->g:Ljava/lang/String;

    .line 84
    .line 85
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v7

    .line 89
    or-int/2addr v2, v7

    .line 90
    invoke-virtual {v1, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v4

    .line 94
    or-int/2addr v2, v4

    .line 95
    iget-object v4, v0, Lh2/j0;->h:Ljava/lang/String;

    .line 96
    .line 97
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    or-int/2addr v2, v4

    .line 102
    iget-object v4, v0, Lh2/j0;->i:Ljava/lang/String;

    .line 103
    .line 104
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v4

    .line 108
    or-int/2addr v2, v4

    .line 109
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    if-nez v2, :cond_3

    .line 114
    .line 115
    if-ne v4, v8, :cond_4

    .line 116
    .line 117
    :cond_3
    new-instance v9, Lh2/h0;

    .line 118
    .line 119
    const/16 v16, 0x0

    .line 120
    .line 121
    iget-object v10, v0, Lh2/j0;->d:Lh2/r8;

    .line 122
    .line 123
    iget-boolean v11, v0, Lh2/j0;->f:Z

    .line 124
    .line 125
    iget-object v12, v0, Lh2/j0;->g:Ljava/lang/String;

    .line 126
    .line 127
    iget-object v13, v0, Lh2/j0;->h:Ljava/lang/String;

    .line 128
    .line 129
    iget-object v14, v0, Lh2/j0;->i:Ljava/lang/String;

    .line 130
    .line 131
    iget-object v15, v0, Lh2/j0;->e:Lvy0/b0;

    .line 132
    .line 133
    invoke-direct/range {v9 .. v16}, Lh2/h0;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    move-object v4, v9

    .line 140
    :cond_4
    check-cast v4, Lay0/k;

    .line 141
    .line 142
    invoke-static {v3, v6, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 147
    .line 148
    invoke-static {v3, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    iget-wide v7, v1, Ll2/t;->T:J

    .line 153
    .line 154
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 155
    .line 156
    .line 157
    move-result v4

    .line 158
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 167
    .line 168
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 169
    .line 170
    .line 171
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 172
    .line 173
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 174
    .line 175
    .line 176
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 177
    .line 178
    if-eqz v9, :cond_5

    .line 179
    .line 180
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 181
    .line 182
    .line 183
    goto :goto_1

    .line 184
    :cond_5
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 185
    .line 186
    .line 187
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 188
    .line 189
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 190
    .line 191
    .line 192
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 193
    .line 194
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 195
    .line 196
    .line 197
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 198
    .line 199
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 200
    .line 201
    if-nez v7, :cond_6

    .line 202
    .line 203
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v7

    .line 207
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v8

    .line 211
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v7

    .line 215
    if-nez v7, :cond_7

    .line 216
    .line 217
    :cond_6
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 218
    .line 219
    .line 220
    :cond_7
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 221
    .line 222
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 223
    .line 224
    .line 225
    iget-object v0, v0, Lh2/j0;->j:Lay0/n;

    .line 226
    .line 227
    invoke-static {v5, v0, v1, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 228
    .line 229
    .line 230
    goto :goto_2

    .line 231
    :cond_8
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 232
    .line 233
    .line 234
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object v0
.end method
