.class public final Lx21/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:Lx21/y;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Z

.field public final synthetic i:Lx21/c;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/n;


# direct methods
.method public constructor <init>(Lx21/y;Lay0/a;ZLx21/c;Lay0/k;Lay0/n;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lx21/h;->f:Lx21/y;

    .line 2
    .line 3
    iput-object p2, p0, Lx21/h;->g:Lay0/a;

    .line 4
    .line 5
    iput-boolean p3, p0, Lx21/h;->h:Z

    .line 6
    .line 7
    iput-object p4, p0, Lx21/h;->i:Lx21/c;

    .line 8
    .line 9
    iput-object p5, p0, Lx21/h;->j:Lay0/k;

    .line 10
    .line 11
    iput-object p6, p0, Lx21/h;->k:Lay0/n;

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lx2/s;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 16
    .line 17
    .line 18
    const-string v3, "$this$composed"

    .line 19
    .line 20
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    check-cast v2, Ll2/t;

    .line 24
    .line 25
    const v3, 0x4ec8dacc

    .line 26
    .line 27
    .line 28
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 36
    .line 37
    if-ne v3, v4, :cond_0

    .line 38
    .line 39
    invoke-static {v2}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    new-instance v5, Ll2/d0;

    .line 44
    .line 45
    invoke-direct {v5, v3}, Ll2/d0;-><init>(Lvy0/b0;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object v3, v5

    .line 52
    :cond_0
    check-cast v3, Ll2/d0;

    .line 53
    .line 54
    iget-object v9, v3, Ll2/d0;->d:Lvy0/b0;

    .line 55
    .line 56
    const v3, -0x5e2eadc

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    const/4 v11, 0x0

    .line 67
    if-ne v3, v4, :cond_1

    .line 68
    .line 69
    invoke-static {v11}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-virtual {v2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :cond_1
    move-object v12, v3

    .line 77
    check-cast v12, Ll2/b1;

    .line 78
    .line 79
    const v3, -0x5e2e0d3

    .line 80
    .line 81
    .line 82
    const/4 v15, 0x0

    .line 83
    invoke-static {v3, v2, v15}, Lvj/b;->d(ILl2/t;Z)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    if-ne v3, v4, :cond_2

    .line 88
    .line 89
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 90
    .line 91
    invoke-static {v3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-virtual {v2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    :cond_2
    move-object v7, v3

    .line 99
    check-cast v7, Ll2/b1;

    .line 100
    .line 101
    invoke-virtual {v2, v15}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    const v3, -0x5e2d777

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v2, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v3

    .line 114
    invoke-virtual {v2, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    or-int/2addr v3, v5

    .line 119
    iget-object v13, v0, Lx21/h;->g:Lay0/a;

    .line 120
    .line 121
    invoke-virtual {v2, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    or-int/2addr v3, v5

    .line 126
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    if-nez v3, :cond_3

    .line 131
    .line 132
    if-ne v5, v4, :cond_4

    .line 133
    .line 134
    :cond_3
    new-instance v5, Lkn/k;

    .line 135
    .line 136
    const/4 v10, 0x1

    .line 137
    move-object v8, v12

    .line 138
    move-object v6, v13

    .line 139
    invoke-direct/range {v5 .. v10}, Lkn/k;-><init>(Llx0/e;Ll2/b1;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    :cond_4
    check-cast v5, Lay0/k;

    .line 146
    .line 147
    invoke-virtual {v2, v15}, Ll2/t;->q(Z)V

    .line 148
    .line 149
    .line 150
    iget-object v3, v0, Lx21/h;->f:Lx21/y;

    .line 151
    .line 152
    invoke-static {v3, v5, v2}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 153
    .line 154
    .line 155
    iget-boolean v5, v0, Lx21/h;->h:Z

    .line 156
    .line 157
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 158
    .line 159
    .line 160
    move-result-object v18

    .line 161
    const v6, -0x5e29bb4

    .line 162
    .line 163
    .line 164
    invoke-virtual {v2, v6}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v2, v5}, Ll2/t;->h(Z)Z

    .line 168
    .line 169
    .line 170
    move-result v5

    .line 171
    move-object v10, v7

    .line 172
    iget-object v7, v0, Lx21/h;->i:Lx21/c;

    .line 173
    .line 174
    invoke-virtual {v2, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v6

    .line 178
    or-int/2addr v5, v6

    .line 179
    invoke-virtual {v2, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v6

    .line 183
    or-int/2addr v5, v6

    .line 184
    invoke-virtual {v2, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v6

    .line 188
    or-int/2addr v5, v6

    .line 189
    move-object v11, v9

    .line 190
    iget-object v9, v0, Lx21/h;->j:Lay0/k;

    .line 191
    .line 192
    invoke-virtual {v2, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result v6

    .line 196
    or-int/2addr v5, v6

    .line 197
    invoke-virtual {v2, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v6

    .line 201
    or-int/2addr v5, v6

    .line 202
    iget-object v8, v0, Lx21/h;->k:Lay0/n;

    .line 203
    .line 204
    invoke-virtual {v2, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v6

    .line 208
    or-int/2addr v5, v6

    .line 209
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    if-nez v5, :cond_5

    .line 214
    .line 215
    if-ne v6, v4, :cond_6

    .line 216
    .line 217
    :cond_5
    new-instance v5, Lx21/g;

    .line 218
    .line 219
    const/4 v14, 0x0

    .line 220
    iget-boolean v6, v0, Lx21/h;->h:Z

    .line 221
    .line 222
    invoke-direct/range {v5 .. v14}, Lx21/g;-><init>(ZLx21/c;Lay0/n;Lay0/k;Ll2/b1;Lvy0/b0;Ll2/b1;Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v2, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    move-object v6, v5

    .line 229
    :cond_6
    check-cast v6, Lay0/n;

    .line 230
    .line 231
    invoke-virtual {v2, v15}, Ll2/t;->q(Z)V

    .line 232
    .line 233
    .line 234
    sget-object v0, Lp3/f0;->a:Lp3/k;

    .line 235
    .line 236
    new-instance v16, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;

    .line 237
    .line 238
    new-instance v0, Lp3/e0;

    .line 239
    .line 240
    invoke-direct {v0, v6}, Lp3/e0;-><init>(Lay0/n;)V

    .line 241
    .line 242
    .line 243
    const/16 v21, 0x4

    .line 244
    .line 245
    const/16 v19, 0x0

    .line 246
    .line 247
    move-object/from16 v20, v0

    .line 248
    .line 249
    move-object/from16 v17, v3

    .line 250
    .line 251
    invoke-direct/range {v16 .. v21}, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;-><init>(Ljava/lang/Object;Ljava/lang/Object;[Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;I)V

    .line 252
    .line 253
    .line 254
    move-object/from16 v0, v16

    .line 255
    .line 256
    invoke-interface {v1, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    invoke-virtual {v2, v15}, Ll2/t;->q(Z)V

    .line 261
    .line 262
    .line 263
    return-object v0
.end method
