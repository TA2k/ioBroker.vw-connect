.class public final Lw30/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw30/t;


# direct methods
.method public synthetic constructor <init>(Lw30/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw30/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/o;->e:Lw30/t;

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
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lw30/o;->d:I

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
    instance-of v2, v1, Lne0/c;

    .line 13
    .line 14
    iget-object v0, v0, Lw30/o;->e:Lw30/t;

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
    check-cast v3, Lw30/s;

    .line 24
    .line 25
    check-cast v1, Lne0/c;

    .line 26
    .line 27
    iget-object v2, v0, Lw30/t;->w:Lij0/a;

    .line 28
    .line 29
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    const/4 v15, 0x0

    .line 34
    const/16 v16, 0xffc

    .line 35
    .line 36
    const/4 v5, 0x0

    .line 37
    const/4 v6, 0x0

    .line 38
    const/4 v7, 0x0

    .line 39
    const/4 v8, 0x0

    .line 40
    const/4 v9, 0x0

    .line 41
    const/4 v10, 0x0

    .line 42
    const/4 v11, 0x0

    .line 43
    const/4 v12, 0x0

    .line 44
    const/4 v13, 0x0

    .line 45
    const/4 v14, 0x0

    .line 46
    invoke-static/range {v3 .. v16}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    goto/16 :goto_4

    .line 51
    .line 52
    :cond_0
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 53
    .line 54
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_1

    .line 59
    .line 60
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    move-object v2, v1

    .line 65
    check-cast v2, Lw30/s;

    .line 66
    .line 67
    const/4 v14, 0x0

    .line 68
    const/16 v15, 0xffd

    .line 69
    .line 70
    const/4 v3, 0x0

    .line 71
    const/4 v4, 0x1

    .line 72
    const/4 v5, 0x0

    .line 73
    const/4 v6, 0x0

    .line 74
    const/4 v7, 0x0

    .line 75
    const/4 v8, 0x0

    .line 76
    const/4 v9, 0x0

    .line 77
    const/4 v10, 0x0

    .line 78
    const/4 v11, 0x0

    .line 79
    const/4 v12, 0x0

    .line 80
    const/4 v13, 0x0

    .line 81
    invoke-static/range {v2 .. v15}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    goto :goto_4

    .line 86
    :cond_1
    instance-of v2, v1, Lne0/e;

    .line 87
    .line 88
    if-eqz v2, :cond_6

    .line 89
    .line 90
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    move-object v3, v2

    .line 95
    check-cast v3, Lw30/s;

    .line 96
    .line 97
    const/4 v15, 0x0

    .line 98
    const/16 v16, 0xffd

    .line 99
    .line 100
    const/4 v4, 0x0

    .line 101
    const/4 v5, 0x0

    .line 102
    const/4 v6, 0x0

    .line 103
    const/4 v7, 0x0

    .line 104
    const/4 v8, 0x0

    .line 105
    const/4 v9, 0x0

    .line 106
    const/4 v10, 0x0

    .line 107
    const/4 v11, 0x0

    .line 108
    const/4 v12, 0x0

    .line 109
    const/4 v13, 0x0

    .line 110
    const/4 v14, 0x0

    .line 111
    invoke-static/range {v3 .. v16}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    iget-object v3, v0, Lw30/t;->y:Lbd0/c;

    .line 116
    .line 117
    check-cast v1, Lne0/e;

    .line 118
    .line 119
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v1, Lv30/a;

    .line 122
    .line 123
    iget-object v1, v1, Lv30/a;->a:Ljava/lang/String;

    .line 124
    .line 125
    const/16 v4, 0x1e

    .line 126
    .line 127
    and-int/lit8 v5, v4, 0x2

    .line 128
    .line 129
    const/4 v7, 0x1

    .line 130
    if-eqz v5, :cond_2

    .line 131
    .line 132
    move v10, v7

    .line 133
    goto :goto_0

    .line 134
    :cond_2
    move v10, v6

    .line 135
    :goto_0
    and-int/lit8 v5, v4, 0x4

    .line 136
    .line 137
    if-eqz v5, :cond_3

    .line 138
    .line 139
    move v11, v7

    .line 140
    goto :goto_1

    .line 141
    :cond_3
    move v11, v6

    .line 142
    :goto_1
    and-int/lit8 v5, v4, 0x8

    .line 143
    .line 144
    if-eqz v5, :cond_4

    .line 145
    .line 146
    move v12, v6

    .line 147
    goto :goto_2

    .line 148
    :cond_4
    move v12, v7

    .line 149
    :goto_2
    and-int/lit8 v4, v4, 0x10

    .line 150
    .line 151
    if-eqz v4, :cond_5

    .line 152
    .line 153
    move v13, v6

    .line 154
    goto :goto_3

    .line 155
    :cond_5
    move v13, v7

    .line 156
    :goto_3
    const-string v4, "url"

    .line 157
    .line 158
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    iget-object v3, v3, Lbd0/c;->a:Lbd0/a;

    .line 162
    .line 163
    new-instance v9, Ljava/net/URL;

    .line 164
    .line 165
    invoke-direct {v9, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    move-object v8, v3

    .line 169
    check-cast v8, Lzc0/b;

    .line 170
    .line 171
    invoke-virtual/range {v8 .. v13}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 172
    .line 173
    .line 174
    move-object v1, v2

    .line 175
    :goto_4
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 176
    .line 177
    .line 178
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    return-object v0

    .line 181
    :cond_6
    new-instance v0, La8/r0;

    .line 182
    .line 183
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 184
    .line 185
    .line 186
    throw v0

    .line 187
    :pswitch_0
    move-object/from16 v1, p1

    .line 188
    .line 189
    check-cast v1, Lss0/b;

    .line 190
    .line 191
    iget-object v0, v0, Lw30/o;->e:Lw30/t;

    .line 192
    .line 193
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    move-object v3, v2

    .line 198
    check-cast v3, Lw30/s;

    .line 199
    .line 200
    const/4 v2, 0x0

    .line 201
    if-eqz v1, :cond_7

    .line 202
    .line 203
    sget-object v4, Lss0/e;->f0:Lss0/e;

    .line 204
    .line 205
    invoke-static {v1, v4}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 206
    .line 207
    .line 208
    move-result v4

    .line 209
    move v6, v4

    .line 210
    goto :goto_5

    .line 211
    :cond_7
    move v6, v2

    .line 212
    :goto_5
    if-eqz v1, :cond_8

    .line 213
    .line 214
    sget-object v2, Lss0/e;->J:Lss0/e;

    .line 215
    .line 216
    invoke-static {v1, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 217
    .line 218
    .line 219
    move-result v2

    .line 220
    :cond_8
    move v8, v2

    .line 221
    const/4 v15, 0x0

    .line 222
    const/16 v16, 0xfeb

    .line 223
    .line 224
    const/4 v4, 0x0

    .line 225
    const/4 v5, 0x0

    .line 226
    const/4 v7, 0x0

    .line 227
    const/4 v9, 0x0

    .line 228
    const/4 v10, 0x0

    .line 229
    const/4 v11, 0x0

    .line 230
    const/4 v12, 0x0

    .line 231
    const/4 v13, 0x0

    .line 232
    const/4 v14, 0x0

    .line 233
    invoke-static/range {v3 .. v16}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 234
    .line 235
    .line 236
    move-result-object v1

    .line 237
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 238
    .line 239
    .line 240
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 241
    .line 242
    return-object v0

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
