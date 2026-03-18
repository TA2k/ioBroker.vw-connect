.class public final synthetic Ld00/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, Ld00/k;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Ld00/k;->e:Z

    iput-object p1, p0, Ld00/k;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/a;II)V
    .locals 0

    .line 2
    iput p4, p0, Ld00/k;->d:I

    iput-boolean p1, p0, Ld00/k;->e:Z

    iput-object p2, p0, Ld00/k;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld00/k;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 25
    .line 26
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 27
    .line 28
    invoke-static {v3, v0, v1, v2}, Lx30/b;->B(ZLay0/a;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_0
    move-object/from16 v1, p1

    .line 35
    .line 36
    check-cast v1, Ll2/o;

    .line 37
    .line 38
    move-object/from16 v2, p2

    .line 39
    .line 40
    check-cast v2, Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    const/4 v2, 0x1

    .line 46
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 51
    .line 52
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 53
    .line 54
    invoke-static {v3, v0, v1, v2}, Luz/t;->s(ZLay0/a;Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_1
    move-object/from16 v1, p1

    .line 59
    .line 60
    check-cast v1, Ll2/o;

    .line 61
    .line 62
    move-object/from16 v2, p2

    .line 63
    .line 64
    check-cast v2, Ljava/lang/Integer;

    .line 65
    .line 66
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    const/4 v2, 0x1

    .line 70
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 75
    .line 76
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 77
    .line 78
    invoke-static {v3, v0, v1, v2}, Luz/k0;->C(ZLay0/a;Ll2/o;I)V

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :pswitch_2
    move-object/from16 v1, p1

    .line 83
    .line 84
    check-cast v1, Ll2/o;

    .line 85
    .line 86
    move-object/from16 v2, p2

    .line 87
    .line 88
    check-cast v2, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    const/16 v2, 0x31

    .line 94
    .line 95
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 100
    .line 101
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 102
    .line 103
    invoke-static {v3, v0, v1, v2}, Lr30/h;->b(ZLay0/a;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_0

    .line 107
    :pswitch_3
    move-object/from16 v1, p1

    .line 108
    .line 109
    check-cast v1, Ll2/o;

    .line 110
    .line 111
    move-object/from16 v2, p2

    .line 112
    .line 113
    check-cast v2, Ljava/lang/Integer;

    .line 114
    .line 115
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    and-int/lit8 v3, v2, 0x3

    .line 120
    .line 121
    const/4 v4, 0x2

    .line 122
    const/4 v5, 0x1

    .line 123
    const/4 v6, 0x0

    .line 124
    if-eq v3, v4, :cond_0

    .line 125
    .line 126
    move v3, v5

    .line 127
    goto :goto_1

    .line 128
    :cond_0
    move v3, v6

    .line 129
    :goto_1
    and-int/2addr v2, v5

    .line 130
    move-object v14, v1

    .line 131
    check-cast v14, Ll2/t;

    .line 132
    .line 133
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    if-eqz v1, :cond_2

    .line 138
    .line 139
    iget-boolean v1, v0, Ld00/k;->e:Z

    .line 140
    .line 141
    if-eqz v1, :cond_1

    .line 142
    .line 143
    const v1, 0x2173663f

    .line 144
    .line 145
    .line 146
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    const v1, 0x7f1204c2

    .line 150
    .line 151
    .line 152
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    new-instance v10, Li91/w2;

    .line 157
    .line 158
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 159
    .line 160
    const/4 v1, 0x3

    .line 161
    invoke-direct {v10, v0, v1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 162
    .line 163
    .line 164
    const/4 v15, 0x0

    .line 165
    const/16 v16, 0x3bd

    .line 166
    .line 167
    const/4 v7, 0x0

    .line 168
    const/4 v9, 0x0

    .line 169
    const/4 v11, 0x0

    .line 170
    const/4 v12, 0x0

    .line 171
    const/4 v13, 0x0

    .line 172
    invoke-static/range {v7 .. v16}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 173
    .line 174
    .line 175
    :goto_2
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 176
    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_1
    const v0, 0x213a41c2

    .line 180
    .line 181
    .line 182
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 183
    .line 184
    .line 185
    goto :goto_2

    .line 186
    :cond_2
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 187
    .line 188
    .line 189
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object v0

    .line 192
    :pswitch_4
    move-object/from16 v1, p1

    .line 193
    .line 194
    check-cast v1, Ll2/o;

    .line 195
    .line 196
    move-object/from16 v2, p2

    .line 197
    .line 198
    check-cast v2, Ljava/lang/Integer;

    .line 199
    .line 200
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 201
    .line 202
    .line 203
    const/4 v2, 0x7

    .line 204
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 205
    .line 206
    .line 207
    move-result v2

    .line 208
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 209
    .line 210
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 211
    .line 212
    invoke-static {v3, v0, v1, v2}, Ljp/wb;->b(ZLay0/a;Ll2/o;I)V

    .line 213
    .line 214
    .line 215
    goto/16 :goto_0

    .line 216
    .line 217
    :pswitch_5
    move-object/from16 v1, p1

    .line 218
    .line 219
    check-cast v1, Ll2/o;

    .line 220
    .line 221
    move-object/from16 v2, p2

    .line 222
    .line 223
    check-cast v2, Ljava/lang/Integer;

    .line 224
    .line 225
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 226
    .line 227
    .line 228
    const/4 v2, 0x1

    .line 229
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 230
    .line 231
    .line 232
    move-result v2

    .line 233
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 234
    .line 235
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 236
    .line 237
    invoke-static {v3, v0, v1, v2}, Lmk/a;->g(ZLay0/a;Ll2/o;I)V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_0

    .line 241
    .line 242
    :pswitch_6
    move-object/from16 v1, p1

    .line 243
    .line 244
    check-cast v1, Ll2/o;

    .line 245
    .line 246
    move-object/from16 v2, p2

    .line 247
    .line 248
    check-cast v2, Ljava/lang/Integer;

    .line 249
    .line 250
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 251
    .line 252
    .line 253
    const/4 v2, 0x1

    .line 254
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    iget-boolean v3, v0, Ld00/k;->e:Z

    .line 259
    .line 260
    iget-object v0, v0, Ld00/k;->f:Lay0/a;

    .line 261
    .line 262
    invoke-static {v3, v0, v1, v2}, Ld00/o;->J(ZLay0/a;Ll2/o;I)V

    .line 263
    .line 264
    .line 265
    goto/16 :goto_0

    .line 266
    .line 267
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
