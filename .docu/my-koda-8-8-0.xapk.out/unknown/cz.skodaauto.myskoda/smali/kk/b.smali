.class public final synthetic Lkk/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lmc/r;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lmc/r;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lkk/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lkk/b;->e:Lmc/r;

    .line 4
    .line 5
    iput-object p2, p0, Lkk/b;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lkk/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/t;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$AddOrReplacePaymentForm"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v4, v3, 0x6

    .line 30
    .line 31
    if-nez v4, :cond_1

    .line 32
    .line 33
    move-object v4, v2

    .line 34
    check-cast v4, Ll2/t;

    .line 35
    .line 36
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    const/4 v4, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v4, 0x2

    .line 45
    :goto_0
    or-int/2addr v3, v4

    .line 46
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 47
    .line 48
    const/16 v5, 0x12

    .line 49
    .line 50
    const/4 v6, 0x0

    .line 51
    const/4 v7, 0x1

    .line 52
    if-eq v4, v5, :cond_2

    .line 53
    .line 54
    move v4, v7

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    move v4, v6

    .line 57
    :goto_1
    and-int/2addr v3, v7

    .line 58
    move-object v13, v2

    .line 59
    check-cast v13, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v13, v3, v4}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_7

    .line 66
    .line 67
    iget-object v2, v0, Lkk/b;->e:Lmc/r;

    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_4

    .line 74
    .line 75
    if-ne v2, v7, :cond_3

    .line 76
    .line 77
    const v2, -0x1f4248f1

    .line 78
    .line 79
    .line 80
    const v3, 0x7f120951

    .line 81
    .line 82
    .line 83
    :goto_2
    invoke-static {v2, v3, v13, v13, v6}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    move-object v12, v2

    .line 88
    goto :goto_3

    .line 89
    :cond_3
    const v0, -0x1f4260c6

    .line 90
    .line 91
    .line 92
    invoke-static {v0, v13, v6}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    throw v0

    .line 97
    :cond_4
    const v2, -0x1f4254b1

    .line 98
    .line 99
    .line 100
    const v3, 0x7f120a57

    .line 101
    .line 102
    .line 103
    goto :goto_2

    .line 104
    :goto_3
    const/16 v2, 0x20

    .line 105
    .line 106
    int-to-float v7, v2

    .line 107
    const/4 v8, 0x7

    .line 108
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 109
    .line 110
    const/4 v4, 0x0

    .line 111
    const/4 v5, 0x0

    .line 112
    const/4 v6, 0x0

    .line 113
    invoke-static/range {v3 .. v8}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    sget-object v3, Lx2/c;->q:Lx2/h;

    .line 118
    .line 119
    invoke-virtual {v1, v3, v2}, Lk1/t;->a(Lx2/h;Lx2/s;)Lx2/s;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    const-string v2, "add_or_replace_payment_form_cta"

    .line 124
    .line 125
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 126
    .line 127
    .line 128
    move-result-object v14

    .line 129
    iget-object v0, v0, Lkk/b;->f:Lay0/k;

    .line 130
    .line 131
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    if-nez v1, :cond_5

    .line 140
    .line 141
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 142
    .line 143
    if-ne v2, v1, :cond_6

    .line 144
    .line 145
    :cond_5
    new-instance v2, Lik/b;

    .line 146
    .line 147
    const/16 v1, 0xc

    .line 148
    .line 149
    invoke-direct {v2, v1, v0}, Lik/b;-><init>(ILay0/k;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    :cond_6
    move-object v10, v2

    .line 156
    check-cast v10, Lay0/a;

    .line 157
    .line 158
    const/4 v8, 0x0

    .line 159
    const/16 v9, 0x38

    .line 160
    .line 161
    const/4 v11, 0x0

    .line 162
    const/4 v15, 0x0

    .line 163
    const/16 v16, 0x0

    .line 164
    .line 165
    invoke-static/range {v8 .. v16}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 166
    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_7
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 170
    .line 171
    .line 172
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    return-object v0

    .line 175
    :pswitch_0
    move-object/from16 v1, p1

    .line 176
    .line 177
    check-cast v1, Lmc/m;

    .line 178
    .line 179
    move-object/from16 v2, p2

    .line 180
    .line 181
    check-cast v2, Ll2/o;

    .line 182
    .line 183
    move-object/from16 v3, p3

    .line 184
    .line 185
    check-cast v3, Ljava/lang/Integer;

    .line 186
    .line 187
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 188
    .line 189
    .line 190
    move-result v3

    .line 191
    const-string v4, "it"

    .line 192
    .line 193
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    and-int/lit8 v4, v3, 0x6

    .line 197
    .line 198
    if-nez v4, :cond_a

    .line 199
    .line 200
    and-int/lit8 v4, v3, 0x8

    .line 201
    .line 202
    if-nez v4, :cond_8

    .line 203
    .line 204
    move-object v4, v2

    .line 205
    check-cast v4, Ll2/t;

    .line 206
    .line 207
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    goto :goto_5

    .line 212
    :cond_8
    move-object v4, v2

    .line 213
    check-cast v4, Ll2/t;

    .line 214
    .line 215
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v4

    .line 219
    :goto_5
    if-eqz v4, :cond_9

    .line 220
    .line 221
    const/4 v4, 0x4

    .line 222
    goto :goto_6

    .line 223
    :cond_9
    const/4 v4, 0x2

    .line 224
    :goto_6
    or-int/2addr v3, v4

    .line 225
    :cond_a
    and-int/lit8 v4, v3, 0x13

    .line 226
    .line 227
    const/16 v5, 0x12

    .line 228
    .line 229
    if-eq v4, v5, :cond_b

    .line 230
    .line 231
    const/4 v4, 0x1

    .line 232
    goto :goto_7

    .line 233
    :cond_b
    const/4 v4, 0x0

    .line 234
    :goto_7
    and-int/lit8 v5, v3, 0x1

    .line 235
    .line 236
    check-cast v2, Ll2/t;

    .line 237
    .line 238
    invoke-virtual {v2, v5, v4}, Ll2/t;->O(IZ)Z

    .line 239
    .line 240
    .line 241
    move-result v4

    .line 242
    if-eqz v4, :cond_c

    .line 243
    .line 244
    shl-int/lit8 v3, v3, 0x3

    .line 245
    .line 246
    and-int/lit8 v3, v3, 0x70

    .line 247
    .line 248
    iget-object v4, v0, Lkk/b;->e:Lmc/r;

    .line 249
    .line 250
    iget-object v0, v0, Lkk/b;->f:Lay0/k;

    .line 251
    .line 252
    invoke-static {v4, v1, v0, v2, v3}, Lkk/a;->a(Lmc/r;Lmc/m;Lay0/k;Ll2/o;I)V

    .line 253
    .line 254
    .line 255
    goto :goto_8

    .line 256
    :cond_c
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 257
    .line 258
    .line 259
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 260
    .line 261
    return-object v0

    .line 262
    nop

    .line 263
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
