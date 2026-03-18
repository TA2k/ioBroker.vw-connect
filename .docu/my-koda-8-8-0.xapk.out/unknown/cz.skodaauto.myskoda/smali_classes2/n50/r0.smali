.class public final Ln50/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ln50/d1;


# direct methods
.method public synthetic constructor <init>(Ln50/d1;I)V
    .locals 0

    .line 1
    iput p2, p0, Ln50/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln50/r0;->e:Ln50/d1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln50/r0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/s;

    .line 11
    .line 12
    instance-of v2, v1, Lne0/e;

    .line 13
    .line 14
    iget-object v0, v0, Ln50/r0;->e:Ln50/d1;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    move-object v3, v2

    .line 23
    check-cast v3, Ln50/o0;

    .line 24
    .line 25
    check-cast v1, Lne0/e;

    .line 26
    .line 27
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 28
    .line 29
    move-object v6, v1

    .line 30
    check-cast v6, Ljava/util/List;

    .line 31
    .line 32
    const/16 v22, 0x0

    .line 33
    .line 34
    const v23, 0x7ffbb

    .line 35
    .line 36
    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v7, 0x0

    .line 40
    const/4 v8, 0x0

    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    const/4 v11, 0x0

    .line 44
    const/4 v12, 0x0

    .line 45
    const/4 v13, 0x0

    .line 46
    const/4 v14, 0x0

    .line 47
    const/4 v15, 0x0

    .line 48
    const/16 v16, 0x0

    .line 49
    .line 50
    const/16 v17, 0x0

    .line 51
    .line 52
    const/16 v18, 0x0

    .line 53
    .line 54
    const/16 v19, 0x0

    .line 55
    .line 56
    const/16 v20, 0x0

    .line 57
    .line 58
    const/16 v21, 0x0

    .line 59
    .line 60
    invoke-static/range {v3 .. v23}, Ln50/o0;->a(Ln50/o0;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZZZLm50/b;Lql0/g;ZLjava/lang/Integer;ZLhl0/a;ZLyj0/a;ZZZZI)Ln50/o0;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    instance-of v2, v1, Lne0/c;

    .line 69
    .line 70
    if-eqz v2, :cond_1

    .line 71
    .line 72
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    move-object v3, v2

    .line 77
    check-cast v3, Ln50/o0;

    .line 78
    .line 79
    check-cast v1, Lne0/c;

    .line 80
    .line 81
    iget-object v2, v0, Ln50/d1;->z:Lij0/a;

    .line 82
    .line 83
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 84
    .line 85
    .line 86
    move-result-object v12

    .line 87
    const/16 v22, 0x0

    .line 88
    .line 89
    const v23, 0x7febf

    .line 90
    .line 91
    .line 92
    const/4 v4, 0x0

    .line 93
    const/4 v5, 0x0

    .line 94
    const/4 v6, 0x0

    .line 95
    const/4 v7, 0x0

    .line 96
    const/4 v8, 0x0

    .line 97
    const/4 v9, 0x0

    .line 98
    const/4 v10, 0x0

    .line 99
    const/4 v11, 0x0

    .line 100
    const/4 v13, 0x0

    .line 101
    const/4 v14, 0x0

    .line 102
    const/4 v15, 0x0

    .line 103
    const/16 v16, 0x0

    .line 104
    .line 105
    const/16 v17, 0x0

    .line 106
    .line 107
    const/16 v18, 0x0

    .line 108
    .line 109
    const/16 v19, 0x0

    .line 110
    .line 111
    const/16 v20, 0x0

    .line 112
    .line 113
    const/16 v21, 0x0

    .line 114
    .line 115
    invoke-static/range {v3 .. v23}, Ln50/o0;->a(Ln50/o0;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZZZLm50/b;Lql0/g;ZLjava/lang/Integer;ZLhl0/a;ZLyj0/a;ZZZZI)Ln50/o0;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_1
    instance-of v0, v1, Lne0/d;

    .line 124
    .line 125
    if-eqz v0, :cond_2

    .line 126
    .line 127
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 128
    .line 129
    return-object v0

    .line 130
    :cond_2
    new-instance v0, La8/r0;

    .line 131
    .line 132
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 133
    .line 134
    .line 135
    throw v0

    .line 136
    :pswitch_0
    move-object/from16 v1, p1

    .line 137
    .line 138
    check-cast v1, Lne0/t;

    .line 139
    .line 140
    instance-of v2, v1, Lne0/e;

    .line 141
    .line 142
    iget-object v0, v0, Ln50/r0;->e:Ln50/d1;

    .line 143
    .line 144
    if-eqz v2, :cond_4

    .line 145
    .line 146
    invoke-virtual {v0}, Ln50/d1;->V()V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    check-cast v1, Ln50/o0;

    .line 154
    .line 155
    iget-object v1, v1, Ln50/o0;->h:Lm50/b;

    .line 156
    .line 157
    if-eqz v1, :cond_3

    .line 158
    .line 159
    iget-boolean v1, v1, Lm50/b;->b:Z

    .line 160
    .line 161
    const/4 v2, 0x1

    .line 162
    if-ne v1, v2, :cond_3

    .line 163
    .line 164
    iget-object v1, v0, Ln50/d1;->q:Ll50/q;

    .line 165
    .line 166
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    :cond_3
    iget-object v0, v0, Ln50/d1;->j:Ll50/h0;

    .line 170
    .line 171
    const/4 v1, 0x0

    .line 172
    invoke-virtual {v0, v1}, Ll50/h0;->a(Lm50/b;)V

    .line 173
    .line 174
    .line 175
    goto :goto_1

    .line 176
    :cond_4
    instance-of v2, v1, Lne0/c;

    .line 177
    .line 178
    if-eqz v2, :cond_5

    .line 179
    .line 180
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    move-object v3, v2

    .line 185
    check-cast v3, Ln50/o0;

    .line 186
    .line 187
    move-object v4, v1

    .line 188
    check-cast v4, Lne0/c;

    .line 189
    .line 190
    iget-object v5, v0, Ln50/d1;->z:Lij0/a;

    .line 191
    .line 192
    const/4 v1, 0x0

    .line 193
    new-array v2, v1, [Ljava/lang/Object;

    .line 194
    .line 195
    move-object v6, v5

    .line 196
    check-cast v6, Ljj0/f;

    .line 197
    .line 198
    const v7, 0x7f120647

    .line 199
    .line 200
    .line 201
    invoke-virtual {v6, v7, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v6

    .line 205
    iget-object v2, v0, Ln50/d1;->z:Lij0/a;

    .line 206
    .line 207
    new-array v7, v1, [Ljava/lang/Object;

    .line 208
    .line 209
    check-cast v2, Ljj0/f;

    .line 210
    .line 211
    const v8, 0x7f120648

    .line 212
    .line 213
    .line 214
    invoke-virtual {v2, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    const v8, 0x7f12038c

    .line 219
    .line 220
    .line 221
    new-array v1, v1, [Ljava/lang/Object;

    .line 222
    .line 223
    invoke-virtual {v2, v8, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v8

    .line 227
    const/4 v11, 0x0

    .line 228
    const/16 v12, 0x70

    .line 229
    .line 230
    const/4 v9, 0x0

    .line 231
    const/4 v10, 0x0

    .line 232
    invoke-static/range {v4 .. v12}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 233
    .line 234
    .line 235
    move-result-object v12

    .line 236
    const/16 v22, 0x0

    .line 237
    .line 238
    const v23, 0x7feff

    .line 239
    .line 240
    .line 241
    const/4 v4, 0x0

    .line 242
    const/4 v5, 0x0

    .line 243
    const/4 v6, 0x0

    .line 244
    const/4 v7, 0x0

    .line 245
    const/4 v8, 0x0

    .line 246
    const/4 v9, 0x0

    .line 247
    const/4 v13, 0x0

    .line 248
    const/4 v14, 0x0

    .line 249
    const/4 v15, 0x0

    .line 250
    const/16 v16, 0x0

    .line 251
    .line 252
    const/16 v17, 0x0

    .line 253
    .line 254
    const/16 v18, 0x0

    .line 255
    .line 256
    const/16 v19, 0x0

    .line 257
    .line 258
    const/16 v20, 0x0

    .line 259
    .line 260
    const/16 v21, 0x0

    .line 261
    .line 262
    invoke-static/range {v3 .. v23}, Ln50/o0;->a(Ln50/o0;Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZZZLm50/b;Lql0/g;ZLjava/lang/Integer;ZLhl0/a;ZLyj0/a;ZZZZI)Ln50/o0;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 267
    .line 268
    .line 269
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 270
    .line 271
    return-object v0

    .line 272
    :cond_5
    new-instance v0, La8/r0;

    .line 273
    .line 274
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 275
    .line 276
    .line 277
    throw v0

    .line 278
    nop

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
