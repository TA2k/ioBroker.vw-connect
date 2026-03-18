.class public final synthetic Ls10/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls10/y;


# direct methods
.method public synthetic constructor <init>(Ls10/y;I)V
    .locals 0

    .line 1
    iput p2, p0, Ls10/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls10/v;->e:Ls10/y;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()Llx0/e;
    .locals 9

    .line 1
    iget v0, p0, Ls10/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onUpdateDepartureTimer(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Ls10/y;

    .line 13
    .line 14
    iget-object v5, p0, Ls10/v;->e:Ls10/y;

    .line 15
    .line 16
    const-string v6, "onUpdateDepartureTimer"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onDepartureTimer(Lcz/skodaauto/myskoda/feature/departuretimers/model/DepartureTimer;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Ls10/y;

    .line 29
    .line 30
    iget-object v6, p0, Ls10/v;->e:Ls10/y;

    .line 31
    .line 32
    const-string v7, "onDepartureTimer"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ls10/v;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v0, v0, Ls10/v;->e:Ls10/y;

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lne0/t;

    .line 15
    .line 16
    instance-of v3, v1, Lne0/e;

    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    iget-object v0, v0, Ls10/y;->h:Ltr0/b;

    .line 21
    .line 22
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    instance-of v3, v1, Lne0/c;

    .line 27
    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    move-object v4, v3

    .line 35
    check-cast v4, Ls10/x;

    .line 36
    .line 37
    check-cast v1, Lne0/c;

    .line 38
    .line 39
    iget-object v3, v0, Ls10/y;->m:Lij0/a;

    .line 40
    .line 41
    invoke-static {v1, v3}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    const/4 v13, 0x0

    .line 46
    const/16 v14, 0x1fe

    .line 47
    .line 48
    const/4 v6, 0x0

    .line 49
    const/4 v7, 0x0

    .line 50
    const/4 v8, 0x0

    .line 51
    const/4 v9, 0x0

    .line 52
    const/4 v10, 0x0

    .line 53
    const/4 v11, 0x0

    .line 54
    const/4 v12, 0x0

    .line 55
    invoke-static/range {v4 .. v14}, Ls10/x;->a(Ls10/x;Lql0/g;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/ArrayList;Ls10/w;I)Ls10/x;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 60
    .line 61
    .line 62
    :goto_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 63
    .line 64
    return-object v2

    .line 65
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    new-instance v0, La8/r0;

    .line 69
    .line 70
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 71
    .line 72
    .line 73
    throw v0

    .line 74
    :pswitch_0
    move-object/from16 v1, p1

    .line 75
    .line 76
    check-cast v1, Lr10/b;

    .line 77
    .line 78
    iget-object v3, v0, Ls10/y;->m:Lij0/a;

    .line 79
    .line 80
    iget-object v4, v0, Ls10/y;->o:Lr10/b;

    .line 81
    .line 82
    if-nez v4, :cond_2

    .line 83
    .line 84
    iput-object v1, v0, Ls10/y;->o:Lr10/b;

    .line 85
    .line 86
    :cond_2
    iput-object v1, v0, Ls10/y;->p:Lr10/b;

    .line 87
    .line 88
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    move-object v5, v4

    .line 93
    check-cast v5, Ls10/x;

    .line 94
    .line 95
    iget v4, v1, Lr10/b;->a:I

    .line 96
    .line 97
    const/4 v6, 0x1

    .line 98
    add-int/2addr v4, v6

    .line 99
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    move-object v7, v3

    .line 108
    check-cast v7, Ljj0/f;

    .line 109
    .line 110
    const v8, 0x7f120f4e

    .line 111
    .line 112
    .line 113
    invoke-virtual {v7, v8, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    iget-boolean v8, v1, Lr10/b;->d:Z

    .line 118
    .line 119
    iget-boolean v9, v1, Lr10/b;->c:Z

    .line 120
    .line 121
    iget-object v4, v0, Ls10/y;->o:Lr10/b;

    .line 122
    .line 123
    iget-object v10, v0, Ls10/y;->p:Lr10/b;

    .line 124
    .line 125
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v4

    .line 129
    if-nez v4, :cond_4

    .line 130
    .line 131
    iget-boolean v4, v1, Lr10/b;->d:Z

    .line 132
    .line 133
    if-nez v4, :cond_3

    .line 134
    .line 135
    iget-boolean v4, v1, Lr10/b;->c:Z

    .line 136
    .line 137
    if-eqz v4, :cond_4

    .line 138
    .line 139
    :cond_3
    :goto_1
    move v11, v6

    .line 140
    goto :goto_2

    .line 141
    :cond_4
    const/4 v6, 0x0

    .line 142
    goto :goto_1

    .line 143
    :goto_2
    iget-object v4, v1, Lr10/b;->e:Lqr0/l;

    .line 144
    .line 145
    const/4 v6, 0x0

    .line 146
    if-eqz v4, :cond_5

    .line 147
    .line 148
    invoke-static {v4}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    move-object v12, v4

    .line 153
    goto :goto_3

    .line 154
    :cond_5
    move-object v12, v6

    .line 155
    :goto_3
    iget-object v4, v1, Lr10/b;->f:Ljava/util/List;

    .line 156
    .line 157
    if-eqz v4, :cond_6

    .line 158
    .line 159
    check-cast v4, Ljava/lang/Iterable;

    .line 160
    .line 161
    new-instance v6, Ljava/util/ArrayList;

    .line 162
    .line 163
    const/16 v10, 0xa

    .line 164
    .line 165
    invoke-static {v4, v10}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 166
    .line 167
    .line 168
    move-result v10

    .line 169
    invoke-direct {v6, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 170
    .line 171
    .line 172
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 177
    .line 178
    .line 179
    move-result v10

    .line 180
    if-eqz v10, :cond_6

    .line 181
    .line 182
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    check-cast v10, Lao0/a;

    .line 187
    .line 188
    new-instance v13, Lao0/b;

    .line 189
    .line 190
    iget-wide v14, v10, Lao0/a;->a:J

    .line 191
    .line 192
    move-object/from16 p2, v2

    .line 193
    .line 194
    iget-object v2, v10, Lao0/a;->c:Ljava/time/LocalTime;

    .line 195
    .line 196
    invoke-static {v2}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    move-object/from16 p0, v4

    .line 201
    .line 202
    iget-object v4, v10, Lao0/a;->d:Ljava/time/LocalTime;

    .line 203
    .line 204
    invoke-static {v4}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v4

    .line 208
    move-object/from16 p1, v5

    .line 209
    .line 210
    const-string v5, " - "

    .line 211
    .line 212
    invoke-static {v2, v5, v4}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    iget-boolean v4, v10, Lao0/a;->b:Z

    .line 217
    .line 218
    invoke-direct {v13, v14, v15, v2, v4}, Lao0/b;-><init>(JLjava/lang/String;Z)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v6, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-object/from16 v4, p0

    .line 225
    .line 226
    move-object/from16 v5, p1

    .line 227
    .line 228
    move-object/from16 v2, p2

    .line 229
    .line 230
    goto :goto_4

    .line 231
    :cond_6
    move-object/from16 p2, v2

    .line 232
    .line 233
    move-object/from16 p1, v5

    .line 234
    .line 235
    move-object v13, v6

    .line 236
    iget-object v1, v1, Lr10/b;->g:Lao0/c;

    .line 237
    .line 238
    new-instance v14, Ls10/w;

    .line 239
    .line 240
    iget-object v2, v1, Lao0/c;->c:Ljava/time/LocalTime;

    .line 241
    .line 242
    invoke-static {v2}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    invoke-static {v1, v3}, Ljp/ab;->b(Lao0/c;Lij0/a;)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    invoke-direct {v14, v2, v1}, Ls10/w;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    const/16 v15, 0x11

    .line 254
    .line 255
    const/4 v6, 0x0

    .line 256
    const/4 v10, 0x0

    .line 257
    move-object/from16 v5, p1

    .line 258
    .line 259
    invoke-static/range {v5 .. v15}, Ls10/x;->a(Ls10/x;Lql0/g;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/util/ArrayList;Ls10/w;I)Ls10/x;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 264
    .line 265
    .line 266
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 267
    .line 268
    return-object p2

    .line 269
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Ls10/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyy0/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 20
    .line 21
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    :cond_0
    return v1

    .line 30
    :pswitch_0
    instance-of v0, p1, Lyy0/j;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 44
    .line 45
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    :cond_1
    return v1

    .line 54
    nop

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Ls10/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
