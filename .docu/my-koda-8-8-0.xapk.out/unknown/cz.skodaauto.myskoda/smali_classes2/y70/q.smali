.class public final Ly70/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/e0;


# direct methods
.method public synthetic constructor <init>(Ly70/e0;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/q;->e:Ly70/e0;

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
    .locals 12

    .line 1
    iget v0, p0, Ly70/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/q;->e:Ly70/e0;

    .line 9
    .line 10
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Ly70/z;

    .line 15
    .line 16
    iget-object v0, v0, Ly70/z;->a:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    instance-of v0, p1, Lne0/e;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    check-cast p1, Lne0/e;

    .line 31
    .line 32
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Ljava/util/List;

    .line 35
    .line 36
    invoke-static {p0, p1, p2}, Ly70/e0;->j(Ly70/e0;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    move-object v1, p0

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 47
    .line 48
    if-eqz p2, :cond_1

    .line 49
    .line 50
    check-cast p1, Lne0/c;

    .line 51
    .line 52
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    move-object v2, p2

    .line 57
    check-cast v2, Ly70/z;

    .line 58
    .line 59
    iget-object p2, p0, Ly70/e0;->w:Lij0/a;

    .line 60
    .line 61
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    const/4 v10, 0x0

    .line 66
    const/16 v11, 0xa7

    .line 67
    .line 68
    const/4 v3, 0x0

    .line 69
    const/4 v4, 0x0

    .line 70
    const/4 v5, 0x0

    .line 71
    const/4 v6, 0x0

    .line 72
    const/4 v8, 0x0

    .line 73
    const/4 v9, 0x0

    .line 74
    invoke-static/range {v2 .. v11}, Ly70/z;->a(Ly70/z;Ljava/lang/String;ZLjava/lang/Boolean;Ljava/util/List;Lql0/g;Lql0/g;ZZI)Ly70/z;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    :goto_0
    return-object v1

    .line 82
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 83
    .line 84
    instance-of v0, p1, Lne0/e;

    .line 85
    .line 86
    iget-object p0, p0, Ly70/q;->e:Ly70/e0;

    .line 87
    .line 88
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    if-eqz v0, :cond_4

    .line 91
    .line 92
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    move-object v2, p1

    .line 97
    check-cast v2, Ly70/z;

    .line 98
    .line 99
    const/4 v10, 0x0

    .line 100
    const/16 v11, 0xdf

    .line 101
    .line 102
    const/4 v3, 0x0

    .line 103
    const/4 v4, 0x0

    .line 104
    const/4 v5, 0x0

    .line 105
    const/4 v6, 0x0

    .line 106
    const/4 v7, 0x0

    .line 107
    const/4 v8, 0x0

    .line 108
    const/4 v9, 0x0

    .line 109
    invoke-static/range {v2 .. v11}, Ly70/z;->a(Ly70/z;Ljava/lang/String;ZLjava/lang/Boolean;Ljava/util/List;Lql0/g;Lql0/g;ZZI)Ly70/z;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    check-cast p1, Ly70/z;

    .line 121
    .line 122
    iget-boolean p1, p1, Ly70/z;->i:Z

    .line 123
    .line 124
    if-eqz p1, :cond_2

    .line 125
    .line 126
    invoke-virtual {p0, p2}, Ly70/e0;->k(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 131
    .line 132
    if-ne p0, p1, :cond_2

    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_2
    move-object p0, v1

    .line 136
    :goto_1
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 137
    .line 138
    if-ne p0, p1, :cond_3

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_3
    :goto_2
    move-object p0, v1

    .line 142
    goto :goto_3

    .line 143
    :cond_4
    instance-of p2, p1, Lne0/c;

    .line 144
    .line 145
    if-eqz p2, :cond_3

    .line 146
    .line 147
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 148
    .line 149
    .line 150
    move-result-object p2

    .line 151
    move-object v2, p2

    .line 152
    check-cast v2, Ly70/z;

    .line 153
    .line 154
    check-cast p1, Lne0/c;

    .line 155
    .line 156
    iget-object p2, p0, Ly70/e0;->w:Lij0/a;

    .line 157
    .line 158
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    const/4 v10, 0x0

    .line 163
    const/16 v11, 0xdf

    .line 164
    .line 165
    const/4 v3, 0x0

    .line 166
    const/4 v4, 0x0

    .line 167
    const/4 v5, 0x0

    .line 168
    const/4 v6, 0x0

    .line 169
    const/4 v7, 0x0

    .line 170
    const/4 v9, 0x0

    .line 171
    invoke-static/range {v2 .. v11}, Ly70/z;->a(Ly70/z;Ljava/lang/String;ZLjava/lang/Boolean;Ljava/util/List;Lql0/g;Lql0/g;ZZI)Ly70/z;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 176
    .line 177
    .line 178
    goto :goto_2

    .line 179
    :goto_3
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 180
    .line 181
    if-ne p0, p1, :cond_5

    .line 182
    .line 183
    move-object v1, p0

    .line 184
    :cond_5
    return-object v1

    .line 185
    :pswitch_1
    check-cast p1, Lgg0/a;

    .line 186
    .line 187
    iget-object p0, p0, Ly70/q;->e:Ly70/e0;

    .line 188
    .line 189
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    move-object v1, v0

    .line 194
    check-cast v1, Ly70/z;

    .line 195
    .line 196
    if-eqz p1, :cond_6

    .line 197
    .line 198
    const/4 p1, 0x1

    .line 199
    :goto_4
    move v3, p1

    .line 200
    goto :goto_5

    .line 201
    :cond_6
    const/4 p1, 0x0

    .line 202
    goto :goto_4

    .line 203
    :goto_5
    const/4 v9, 0x0

    .line 204
    const/16 v10, 0xfd

    .line 205
    .line 206
    const/4 v2, 0x0

    .line 207
    const/4 v4, 0x0

    .line 208
    const/4 v5, 0x0

    .line 209
    const/4 v6, 0x0

    .line 210
    const/4 v7, 0x0

    .line 211
    const/4 v8, 0x0

    .line 212
    invoke-static/range {v1 .. v10}, Ly70/z;->a(Ly70/z;Ljava/lang/String;ZLjava/lang/Boolean;Ljava/util/List;Lql0/g;Lql0/g;ZZI)Ly70/z;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    check-cast p1, Ly70/z;

    .line 224
    .line 225
    iget-boolean p1, p1, Ly70/z;->i:Z

    .line 226
    .line 227
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 228
    .line 229
    if-eqz p1, :cond_7

    .line 230
    .line 231
    invoke-virtual {p0, p2}, Ly70/e0;->k(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 236
    .line 237
    if-ne p0, p1, :cond_7

    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_7
    move-object p0, v0

    .line 241
    :goto_6
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 242
    .line 243
    if-ne p0, p1, :cond_8

    .line 244
    .line 245
    move-object v0, p0

    .line 246
    :cond_8
    return-object v0

    .line 247
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
