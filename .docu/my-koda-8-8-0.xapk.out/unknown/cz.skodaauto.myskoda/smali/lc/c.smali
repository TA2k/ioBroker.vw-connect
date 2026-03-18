.class public final Llc/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/Throwable;Lay0/k;)Llc/l;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Llc/f;->e:Llc/f;

    .line 4
    .line 5
    new-instance v2, Llc/g;

    .line 6
    .line 7
    move-object/from16 v3, p1

    .line 8
    .line 9
    invoke-direct {v2, v3}, Llc/g;-><init>(Lay0/k;)V

    .line 10
    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    instance-of v4, v0, Lrc/a;

    .line 16
    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    move-object v4, v0

    .line 20
    check-cast v4, Lrc/a;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move-object v4, v3

    .line 24
    :goto_0
    if-eqz v4, :cond_1

    .line 25
    .line 26
    iget-object v4, v4, Lrc/a;->e:Ltb/c;

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    move-object v4, v3

    .line 30
    :goto_1
    if-eqz v4, :cond_2

    .line 31
    .line 32
    iget-object v5, v4, Ltb/c;->b:Ltb/f;

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_2
    move-object v5, v3

    .line 36
    :goto_2
    if-eqz v4, :cond_3

    .line 37
    .line 38
    iget-object v4, v4, Ltb/c;->c:Ljava/lang/String;

    .line 39
    .line 40
    goto :goto_3

    .line 41
    :cond_3
    move-object v4, v3

    .line 42
    :goto_3
    const/4 v6, 0x0

    .line 43
    const/4 v7, 0x1

    .line 44
    if-eqz v4, :cond_5

    .line 45
    .line 46
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    if-nez v8, :cond_4

    .line 51
    .line 52
    goto :goto_4

    .line 53
    :cond_4
    move v8, v6

    .line 54
    goto :goto_5

    .line 55
    :cond_5
    :goto_4
    move v8, v7

    .line 56
    :goto_5
    xor-int/lit8 v12, v8, 0x1

    .line 57
    .line 58
    const-string v8, ""

    .line 59
    .line 60
    if-eqz v5, :cond_12

    .line 61
    .line 62
    iget-object v0, v5, Ltb/f;->a:Ltb/i;

    .line 63
    .line 64
    if-eqz v0, :cond_6

    .line 65
    .line 66
    new-instance v1, Llc/d;

    .line 67
    .line 68
    iget-object v9, v0, Ltb/i;->a:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v0, v0, Ltb/i;->b:Ljava/lang/String;

    .line 71
    .line 72
    invoke-direct {v1, v9, v0}, Llc/d;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    :cond_6
    move-object v10, v1

    .line 76
    iget-object v0, v5, Ltb/f;->c:Ltb/l;

    .line 77
    .line 78
    if-eqz v0, :cond_a

    .line 79
    .line 80
    sget-object v1, Llc/b;->i:Lsx0/b;

    .line 81
    .line 82
    invoke-virtual {v1}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    :cond_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v9

    .line 90
    if-eqz v9, :cond_8

    .line 91
    .line 92
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v9

    .line 96
    move-object v11, v9

    .line 97
    check-cast v11, Llc/b;

    .line 98
    .line 99
    iget-object v11, v11, Llc/b;->d:Ljava/lang/String;

    .line 100
    .line 101
    iget-object v13, v0, Ltb/l;->a:Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {v11, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v11

    .line 107
    if-eqz v11, :cond_7

    .line 108
    .line 109
    goto :goto_6

    .line 110
    :cond_8
    move-object v9, v3

    .line 111
    :goto_6
    check-cast v9, Llc/b;

    .line 112
    .line 113
    if-eqz v9, :cond_9

    .line 114
    .line 115
    iget-object v1, v2, Llc/g;->a:Ljava/util/ArrayList;

    .line 116
    .line 117
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-eqz v1, :cond_9

    .line 122
    .line 123
    new-instance v1, Llc/h;

    .line 124
    .line 125
    iget-object v0, v0, Ltb/l;->b:Ljava/lang/String;

    .line 126
    .line 127
    invoke-direct {v1, v0, v9}, Llc/h;-><init>(Ljava/lang/String;Llc/b;)V

    .line 128
    .line 129
    .line 130
    goto :goto_7

    .line 131
    :cond_9
    move-object v1, v3

    .line 132
    :goto_7
    if-eqz v1, :cond_a

    .line 133
    .line 134
    :goto_8
    move-object/from16 v18, v1

    .line 135
    .line 136
    goto :goto_9

    .line 137
    :cond_a
    sget-object v1, Llc/j;->f:Llc/j;

    .line 138
    .line 139
    goto :goto_8

    .line 140
    :goto_9
    iget-object v0, v5, Ltb/f;->b:Ltb/z;

    .line 141
    .line 142
    if-eqz v0, :cond_b

    .line 143
    .line 144
    new-instance v1, Llx0/r;

    .line 145
    .line 146
    iget-object v2, v0, Ltb/z;->a:Ljava/lang/String;

    .line 147
    .line 148
    iget-object v0, v0, Ltb/z;->b:Ljava/lang/String;

    .line 149
    .line 150
    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 151
    .line 152
    invoke-direct {v1, v2, v0, v3}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    goto :goto_a

    .line 156
    :cond_b
    new-instance v1, Llx0/r;

    .line 157
    .line 158
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 159
    .line 160
    invoke-direct {v1, v3, v3, v0}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    :goto_a
    iget-object v0, v1, Llx0/r;->d:Ljava/lang/Object;

    .line 164
    .line 165
    check-cast v0, Ljava/lang/String;

    .line 166
    .line 167
    iget-object v2, v1, Llx0/r;->e:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v2, Ljava/lang/String;

    .line 170
    .line 171
    iget-object v1, v1, Llx0/r;->f:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v1, Ljava/lang/Boolean;

    .line 174
    .line 175
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 176
    .line 177
    .line 178
    move-result v15

    .line 179
    iget-object v1, v5, Ltb/f;->d:Ljava/lang/String;

    .line 180
    .line 181
    new-instance v9, Llc/l;

    .line 182
    .line 183
    if-nez v4, :cond_c

    .line 184
    .line 185
    move-object v11, v8

    .line 186
    goto :goto_b

    .line 187
    :cond_c
    move-object v11, v4

    .line 188
    :goto_b
    if-nez v0, :cond_d

    .line 189
    .line 190
    move-object v13, v8

    .line 191
    goto :goto_c

    .line 192
    :cond_d
    move-object v13, v0

    .line 193
    :goto_c
    if-nez v2, :cond_e

    .line 194
    .line 195
    move-object v14, v8

    .line 196
    goto :goto_d

    .line 197
    :cond_e
    move-object v14, v2

    .line 198
    :goto_d
    if-nez v1, :cond_f

    .line 199
    .line 200
    move-object/from16 v16, v8

    .line 201
    .line 202
    goto :goto_e

    .line 203
    :cond_f
    move-object/from16 v16, v1

    .line 204
    .line 205
    :goto_e
    if-eqz v1, :cond_10

    .line 206
    .line 207
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    if-eqz v0, :cond_11

    .line 212
    .line 213
    :cond_10
    move v6, v7

    .line 214
    :cond_11
    xor-int/lit8 v17, v6, 0x1

    .line 215
    .line 216
    invoke-direct/range {v9 .. v18}, Llc/l;-><init>(Llc/a;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLk/a;)V

    .line 217
    .line 218
    .line 219
    return-object v9

    .line 220
    :cond_12
    move v3, v12

    .line 221
    instance-of v0, v0, Ljava/io/IOException;

    .line 222
    .line 223
    if-eqz v0, :cond_13

    .line 224
    .line 225
    new-instance v9, Llc/l;

    .line 226
    .line 227
    sget-object v10, Llc/e;->e:Llc/e;

    .line 228
    .line 229
    const/16 v17, 0x0

    .line 230
    .line 231
    sget-object v18, Llc/i;->f:Llc/i;

    .line 232
    .line 233
    const-string v11, ""

    .line 234
    .line 235
    const/4 v12, 0x0

    .line 236
    const-string v13, ""

    .line 237
    .line 238
    const-string v14, ""

    .line 239
    .line 240
    const/4 v15, 0x0

    .line 241
    const-string v16, ""

    .line 242
    .line 243
    invoke-direct/range {v9 .. v18}, Llc/l;-><init>(Llc/a;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLk/a;)V

    .line 244
    .line 245
    .line 246
    return-object v9

    .line 247
    :cond_13
    new-instance v0, Llc/l;

    .line 248
    .line 249
    if-nez v4, :cond_14

    .line 250
    .line 251
    move-object v2, v8

    .line 252
    goto :goto_f

    .line 253
    :cond_14
    move-object v2, v4

    .line 254
    :goto_f
    const/4 v8, 0x0

    .line 255
    sget-object v9, Llc/k;->f:Llc/k;

    .line 256
    .line 257
    const-string v4, ""

    .line 258
    .line 259
    const-string v5, ""

    .line 260
    .line 261
    const/4 v6, 0x0

    .line 262
    const-string v7, ""

    .line 263
    .line 264
    invoke-direct/range {v0 .. v9}, Llc/l;-><init>(Llc/a;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLk/a;)V

    .line 265
    .line 266
    .line 267
    return-object v0
.end method

.method public static synthetic b(Ljava/lang/Throwable;)Llc/l;
    .locals 2

    .line 1
    new-instance v0, Lkq0/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lkq0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llc/c;->a(Ljava/lang/Throwable;Lay0/k;)Llc/l;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
