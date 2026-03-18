.class public final Lzu/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxu/a;

.field public final b:I

.field public c:Ljava/util/LinkedHashSet;

.field public d:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(DDDDI)V
    .locals 9

    .line 1
    new-instance v0, Lxu/a;

    move-wide v1, p1

    move-wide v3, p3

    move-wide v5, p5

    move-wide/from16 v7, p7

    invoke-direct/range {v0 .. v8}, Lxu/a;-><init>(DDDD)V

    move/from16 p1, p9

    invoke-direct {p0, v0, p1}, Lzu/a;-><init>(Lxu/a;I)V

    return-void
.end method

.method public constructor <init>(Lxu/a;I)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 3
    iput-object v0, p0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 4
    iput-object p1, p0, Lzu/a;->a:Lxu/a;

    .line 5
    iput p2, p0, Lzu/a;->b:I

    return-void
.end method


# virtual methods
.method public final a(DDLru/b;)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    iget-object v3, v0, Lzu/a;->a:Lxu/a;

    .line 7
    .line 8
    if-eqz v1, :cond_3

    .line 9
    .line 10
    iget-wide v4, v3, Lxu/a;->f:D

    .line 11
    .line 12
    iget-wide v6, v3, Lxu/a;->e:D

    .line 13
    .line 14
    cmpg-double v0, p3, v4

    .line 15
    .line 16
    if-gez v0, :cond_1

    .line 17
    .line 18
    cmpg-double v0, p1, v6

    .line 19
    .line 20
    if-gez v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    move-object v1, v0

    .line 28
    check-cast v1, Lzu/a;

    .line 29
    .line 30
    move-wide/from16 v2, p1

    .line 31
    .line 32
    move-wide/from16 v4, p3

    .line 33
    .line 34
    move-object/from16 v6, p5

    .line 35
    .line 36
    invoke-virtual/range {v1 .. v6}, Lzu/a;->a(DDLru/b;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    move-object v2, v0

    .line 45
    check-cast v2, Lzu/a;

    .line 46
    .line 47
    move-wide/from16 v3, p1

    .line 48
    .line 49
    move-wide/from16 v5, p3

    .line 50
    .line 51
    move-object/from16 v7, p5

    .line 52
    .line 53
    invoke-virtual/range {v2 .. v7}, Lzu/a;->a(DDLru/b;)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    cmpg-double v0, p1, v6

    .line 58
    .line 59
    if-gez v0, :cond_2

    .line 60
    .line 61
    const/4 v0, 0x2

    .line 62
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    move-object v2, v0

    .line 67
    check-cast v2, Lzu/a;

    .line 68
    .line 69
    move-wide/from16 v3, p1

    .line 70
    .line 71
    move-wide/from16 v5, p3

    .line 72
    .line 73
    move-object/from16 v7, p5

    .line 74
    .line 75
    invoke-virtual/range {v2 .. v7}, Lzu/a;->a(DDLru/b;)V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :cond_2
    const/4 v0, 0x3

    .line 80
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    move-object v2, v0

    .line 85
    check-cast v2, Lzu/a;

    .line 86
    .line 87
    move-wide/from16 v3, p1

    .line 88
    .line 89
    move-wide/from16 v5, p3

    .line 90
    .line 91
    move-object/from16 v7, p5

    .line 92
    .line 93
    invoke-virtual/range {v2 .. v7}, Lzu/a;->a(DDLru/b;)V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_3
    iget-object v1, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 98
    .line 99
    if-nez v1, :cond_4

    .line 100
    .line 101
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 102
    .line 103
    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 104
    .line 105
    .line 106
    iput-object v1, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 107
    .line 108
    :cond_4
    iget-object v1, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 109
    .line 110
    move-object/from16 v7, p5

    .line 111
    .line 112
    invoke-interface {v1, v7}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    iget-object v1, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 116
    .line 117
    invoke-interface {v1}, Ljava/util/Set;->size()I

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    const/16 v4, 0x32

    .line 122
    .line 123
    if-le v1, v4, :cond_5

    .line 124
    .line 125
    const/16 v1, 0x28

    .line 126
    .line 127
    iget v4, v0, Lzu/a;->b:I

    .line 128
    .line 129
    if-ge v4, v1, :cond_5

    .line 130
    .line 131
    new-instance v1, Ljava/util/ArrayList;

    .line 132
    .line 133
    const/4 v5, 0x4

    .line 134
    invoke-direct {v1, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 135
    .line 136
    .line 137
    iput-object v1, v0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 138
    .line 139
    new-instance v6, Lzu/a;

    .line 140
    .line 141
    iget-wide v7, v3, Lxu/a;->a:D

    .line 142
    .line 143
    iget-wide v9, v3, Lxu/a;->e:D

    .line 144
    .line 145
    iget-wide v11, v3, Lxu/a;->b:D

    .line 146
    .line 147
    iget-wide v13, v3, Lxu/a;->f:D

    .line 148
    .line 149
    add-int/lit8 v24, v4, 0x1

    .line 150
    .line 151
    move/from16 v15, v24

    .line 152
    .line 153
    invoke-direct/range {v6 .. v15}, Lzu/a;-><init>(DDDDI)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    iget-object v1, v0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 160
    .line 161
    new-instance v15, Lzu/a;

    .line 162
    .line 163
    iget-wide v4, v3, Lxu/a;->e:D

    .line 164
    .line 165
    iget-wide v6, v3, Lxu/a;->c:D

    .line 166
    .line 167
    iget-wide v8, v3, Lxu/a;->b:D

    .line 168
    .line 169
    iget-wide v10, v3, Lxu/a;->f:D

    .line 170
    .line 171
    move-wide/from16 v16, v4

    .line 172
    .line 173
    move-wide/from16 v18, v6

    .line 174
    .line 175
    move-wide/from16 v20, v8

    .line 176
    .line 177
    move-wide/from16 v22, v10

    .line 178
    .line 179
    invoke-direct/range {v15 .. v24}, Lzu/a;-><init>(DDDDI)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    iget-object v1, v0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 186
    .line 187
    new-instance v15, Lzu/a;

    .line 188
    .line 189
    iget-wide v4, v3, Lxu/a;->a:D

    .line 190
    .line 191
    iget-wide v6, v3, Lxu/a;->e:D

    .line 192
    .line 193
    iget-wide v8, v3, Lxu/a;->f:D

    .line 194
    .line 195
    iget-wide v10, v3, Lxu/a;->d:D

    .line 196
    .line 197
    move-wide/from16 v16, v4

    .line 198
    .line 199
    move-wide/from16 v18, v6

    .line 200
    .line 201
    move-wide/from16 v20, v8

    .line 202
    .line 203
    move-wide/from16 v22, v10

    .line 204
    .line 205
    invoke-direct/range {v15 .. v24}, Lzu/a;-><init>(DDDDI)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v1, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    iget-object v1, v0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 212
    .line 213
    new-instance v15, Lzu/a;

    .line 214
    .line 215
    iget-wide v4, v3, Lxu/a;->e:D

    .line 216
    .line 217
    iget-wide v6, v3, Lxu/a;->c:D

    .line 218
    .line 219
    iget-wide v8, v3, Lxu/a;->f:D

    .line 220
    .line 221
    iget-wide v2, v3, Lxu/a;->d:D

    .line 222
    .line 223
    move-wide/from16 v22, v2

    .line 224
    .line 225
    move-wide/from16 v16, v4

    .line 226
    .line 227
    move-wide/from16 v18, v6

    .line 228
    .line 229
    move-wide/from16 v20, v8

    .line 230
    .line 231
    invoke-direct/range {v15 .. v24}, Lzu/a;-><init>(DDDDI)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v1, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    iget-object v1, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 238
    .line 239
    const/4 v2, 0x0

    .line 240
    iput-object v2, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 241
    .line 242
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 243
    .line 244
    .line 245
    move-result-object v6

    .line 246
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 247
    .line 248
    .line 249
    move-result v1

    .line 250
    if-eqz v1, :cond_5

    .line 251
    .line 252
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    move-object v5, v1

    .line 257
    check-cast v5, Lru/b;

    .line 258
    .line 259
    iget-object v1, v5, Lru/b;->b:Lyu/a;

    .line 260
    .line 261
    iget-wide v2, v1, Lyu/a;->a:D

    .line 262
    .line 263
    iget-wide v7, v1, Lyu/a;->b:D

    .line 264
    .line 265
    move-wide v1, v2

    .line 266
    move-wide v3, v7

    .line 267
    invoke-virtual/range {v0 .. v5}, Lzu/a;->a(DDLru/b;)V

    .line 268
    .line 269
    .line 270
    move-object/from16 v0, p0

    .line 271
    .line 272
    goto :goto_0

    .line 273
    :cond_5
    return-void
.end method

.method public final b(Lxu/a;Ljava/util/ArrayList;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lzu/a;->a:Lxu/a;

    .line 8
    .line 9
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-wide v4, v1, Lxu/a;->a:D

    .line 13
    .line 14
    iget-wide v6, v1, Lxu/a;->c:D

    .line 15
    .line 16
    iget-wide v8, v1, Lxu/a;->b:D

    .line 17
    .line 18
    iget-wide v10, v1, Lxu/a;->d:D

    .line 19
    .line 20
    iget-wide v12, v3, Lxu/a;->c:D

    .line 21
    .line 22
    cmpg-double v14, v4, v12

    .line 23
    .line 24
    if-gez v14, :cond_3

    .line 25
    .line 26
    iget-wide v14, v3, Lxu/a;->a:D

    .line 27
    .line 28
    cmpg-double v16, v14, v6

    .line 29
    .line 30
    if-gez v16, :cond_3

    .line 31
    .line 32
    move-wide/from16 v16, v4

    .line 33
    .line 34
    iget-wide v4, v3, Lxu/a;->d:D

    .line 35
    .line 36
    cmpg-double v18, v8, v4

    .line 37
    .line 38
    if-gez v18, :cond_3

    .line 39
    .line 40
    move-wide/from16 v18, v4

    .line 41
    .line 42
    iget-wide v3, v3, Lxu/a;->b:D

    .line 43
    .line 44
    cmpg-double v5, v3, v10

    .line 45
    .line 46
    if-gez v5, :cond_3

    .line 47
    .line 48
    iget-object v5, v0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 49
    .line 50
    if-eqz v5, :cond_0

    .line 51
    .line 52
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_3

    .line 61
    .line 62
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    check-cast v3, Lzu/a;

    .line 67
    .line 68
    invoke-virtual {v3, v1, v2}, Lzu/a;->b(Lxu/a;Ljava/util/ArrayList;)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    iget-object v0, v0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 73
    .line 74
    if-eqz v0, :cond_3

    .line 75
    .line 76
    cmpl-double v5, v14, v16

    .line 77
    .line 78
    if-ltz v5, :cond_1

    .line 79
    .line 80
    cmpg-double v5, v12, v6

    .line 81
    .line 82
    if-gtz v5, :cond_1

    .line 83
    .line 84
    cmpl-double v3, v3, v8

    .line 85
    .line 86
    if-ltz v3, :cond_1

    .line 87
    .line 88
    cmpg-double v3, v18, v10

    .line 89
    .line 90
    if-gtz v3, :cond_1

    .line 91
    .line 92
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :cond_1
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    :cond_2
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    if-eqz v3, :cond_3

    .line 105
    .line 106
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v3

    .line 110
    check-cast v3, Lru/b;

    .line 111
    .line 112
    iget-object v4, v3, Lru/b;->b:Lyu/a;

    .line 113
    .line 114
    iget-wide v5, v4, Lyu/a;->a:D

    .line 115
    .line 116
    iget-wide v7, v4, Lyu/a;->b:D

    .line 117
    .line 118
    invoke-virtual {v1, v5, v6, v7, v8}, Lxu/a;->a(DD)Z

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    if-eqz v4, :cond_2

    .line 123
    .line 124
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_3
    return-void
.end method
