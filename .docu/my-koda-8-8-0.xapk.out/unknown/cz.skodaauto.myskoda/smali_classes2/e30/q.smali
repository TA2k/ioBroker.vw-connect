.class public final Le30/q;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Ltr0/b;

.field public final j:Lc30/k;

.field public final k:Lc30/c;

.field public final l:Lc30/m;

.field public final m:Llx0/q;

.field public final n:Llx0/q;


# direct methods
.method public constructor <init>(Lij0/a;Ltr0/b;Lc30/k;Lc30/c;Lc30/m;)V
    .locals 6

    .line 1
    new-instance v0, Le30/o;

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    const/4 v3, 0x0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v4, 0x0

    .line 7
    const/4 v5, 0x0

    .line 8
    invoke-direct/range {v0 .. v5}, Le30/o;-><init>(Ljava/util/List;ZZLql0/g;Le30/n;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Le30/q;->h:Lij0/a;

    .line 15
    .line 16
    iput-object p2, p0, Le30/q;->i:Ltr0/b;

    .line 17
    .line 18
    iput-object p3, p0, Le30/q;->j:Lc30/k;

    .line 19
    .line 20
    iput-object p4, p0, Le30/q;->k:Lc30/c;

    .line 21
    .line 22
    iput-object p5, p0, Le30/q;->l:Lc30/m;

    .line 23
    .line 24
    new-instance p1, Le30/k;

    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    invoke-direct {p1, p0, p2}, Le30/k;-><init>(Le30/q;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Le30/q;->m:Llx0/q;

    .line 35
    .line 36
    new-instance p1, Le30/k;

    .line 37
    .line 38
    const/4 p2, 0x1

    .line 39
    invoke-direct {p1, p0, p2}, Le30/k;-><init>(Le30/q;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Le30/q;->n:Llx0/q;

    .line 47
    .line 48
    new-instance p1, Le30/l;

    .line 49
    .line 50
    const/4 p2, 0x0

    .line 51
    const/4 p3, 0x0

    .line 52
    invoke-direct {p1, p0, p2, p3}, Le30/l;-><init>(Le30/q;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public static final h(Le30/q;Lne0/s;)V
    .locals 14

    .line 1
    iget-object v0, p0, Le30/q;->h:Lij0/a;

    .line 2
    .line 3
    instance-of v1, p1, Lne0/d;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    move-object v0, p1

    .line 12
    check-cast v0, Le30/o;

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    check-cast p1, Le30/o;

    .line 19
    .line 20
    iget-boolean p1, p1, Le30/o;->c:Z

    .line 21
    .line 22
    xor-int/lit8 v2, p1, 0x1

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    const/16 v6, 0x15

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    const/4 v3, 0x0

    .line 29
    const/4 v4, 0x0

    .line 30
    invoke-static/range {v0 .. v6}, Le30/o;->a(Le30/o;Ljava/util/ArrayList;ZZLql0/g;Le30/n;I)Le30/o;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    instance-of v1, p1, Lne0/e;

    .line 39
    .line 40
    if-eqz v1, :cond_8

    .line 41
    .line 42
    check-cast p1, Lne0/e;

    .line 43
    .line 44
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Ljava/util/List;

    .line 47
    .line 48
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    move-object v2, v1

    .line 53
    check-cast v2, Le30/o;

    .line 54
    .line 55
    move-object v1, p1

    .line 56
    check-cast v1, Ljava/util/Collection;

    .line 57
    .line 58
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    const/4 v3, 0x0

    .line 63
    if-nez v1, :cond_5

    .line 64
    .line 65
    move-object v1, p1

    .line 66
    check-cast v1, Ljava/lang/Iterable;

    .line 67
    .line 68
    new-instance v4, Ljava/util/ArrayList;

    .line 69
    .line 70
    const/16 v5, 0xa

    .line 71
    .line 72
    invoke-static {v1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 73
    .line 74
    .line 75
    move-result v5

    .line 76
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 77
    .line 78
    .line 79
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v5

    .line 87
    if-eqz v5, :cond_6

    .line 88
    .line 89
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    move-object v12, v5

    .line 94
    check-cast v12, Ld30/a;

    .line 95
    .line 96
    new-instance v6, Le30/m;

    .line 97
    .line 98
    iget-object v7, v12, Ld30/a;->a:Ljava/lang/String;

    .line 99
    .line 100
    iget-boolean v5, v12, Ld30/a;->i:Z

    .line 101
    .line 102
    const v8, 0x7f1201aa

    .line 103
    .line 104
    .line 105
    const/4 v9, 0x0

    .line 106
    if-eqz v5, :cond_1

    .line 107
    .line 108
    invoke-static {v12}, Lkp/y;->b(Ld30/a;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v10

    .line 112
    if-nez v10, :cond_2

    .line 113
    .line 114
    new-array v10, v9, [Ljava/lang/Object;

    .line 115
    .line 116
    move-object v11, v0

    .line 117
    check-cast v11, Ljj0/f;

    .line 118
    .line 119
    invoke-virtual {v11, v8, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v10

    .line 123
    goto :goto_1

    .line 124
    :cond_1
    new-array v10, v9, [Ljava/lang/Object;

    .line 125
    .line 126
    move-object v11, v0

    .line 127
    check-cast v11, Ljj0/f;

    .line 128
    .line 129
    const v13, 0x7f1203dd

    .line 130
    .line 131
    .line 132
    invoke-virtual {v11, v13, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    :cond_2
    :goto_1
    if-eqz v5, :cond_4

    .line 137
    .line 138
    iget-object v5, v12, Ld30/a;->e:Ljava/lang/String;

    .line 139
    .line 140
    if-nez v5, :cond_3

    .line 141
    .line 142
    new-array v5, v9, [Ljava/lang/Object;

    .line 143
    .line 144
    move-object v9, v0

    .line 145
    check-cast v9, Ljj0/f;

    .line 146
    .line 147
    invoke-virtual {v9, v8, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    :cond_3
    :goto_2
    move-object v9, v5

    .line 152
    move-object v8, v10

    .line 153
    goto :goto_3

    .line 154
    :cond_4
    new-array v5, v9, [Ljava/lang/Object;

    .line 155
    .line 156
    move-object v8, v0

    .line 157
    check-cast v8, Ljj0/f;

    .line 158
    .line 159
    const v9, 0x7f1203d7

    .line 160
    .line 161
    .line 162
    invoke-virtual {v8, v9, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v5

    .line 166
    goto :goto_2

    .line 167
    :goto_3
    iget-object v10, v12, Ld30/a;->g:Ljava/lang/String;

    .line 168
    .line 169
    iget-boolean v11, v12, Ld30/a;->h:Z

    .line 170
    .line 171
    invoke-direct/range {v6 .. v12}, Le30/m;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLd30/a;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    goto :goto_0

    .line 178
    :cond_5
    move-object v4, v3

    .line 179
    :cond_6
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 180
    .line 181
    .line 182
    move-result p1

    .line 183
    if-eqz p1, :cond_7

    .line 184
    .line 185
    iget-object p1, p0, Le30/q;->m:Llx0/q;

    .line 186
    .line 187
    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    move-object v3, p1

    .line 192
    check-cast v3, Le30/n;

    .line 193
    .line 194
    :cond_7
    move-object v7, v3

    .line 195
    const/4 v6, 0x0

    .line 196
    const/4 v8, 0x4

    .line 197
    move-object v3, v4

    .line 198
    const/4 v4, 0x0

    .line 199
    const/4 v5, 0x0

    .line 200
    invoke-static/range {v2 .. v8}, Le30/o;->a(Le30/o;Ljava/util/ArrayList;ZZLql0/g;Le30/n;I)Le30/o;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 205
    .line 206
    .line 207
    return-void

    .line 208
    :cond_8
    instance-of v1, p1, Lne0/c;

    .line 209
    .line 210
    if-eqz v1, :cond_9

    .line 211
    .line 212
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    move-object v2, v1

    .line 217
    check-cast v2, Le30/o;

    .line 218
    .line 219
    check-cast p1, Lne0/c;

    .line 220
    .line 221
    invoke-static {p1, v0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 222
    .line 223
    .line 224
    move-result-object v6

    .line 225
    iget-object p1, p0, Le30/q;->n:Llx0/q;

    .line 226
    .line 227
    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object p1

    .line 231
    move-object v7, p1

    .line 232
    check-cast v7, Le30/n;

    .line 233
    .line 234
    const/4 v5, 0x0

    .line 235
    const/4 v8, 0x4

    .line 236
    const/4 v3, 0x0

    .line 237
    const/4 v4, 0x0

    .line 238
    invoke-static/range {v2 .. v8}, Le30/o;->a(Le30/o;Ljava/util/ArrayList;ZZLql0/g;Le30/n;I)Le30/o;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 243
    .line 244
    .line 245
    return-void

    .line 246
    :cond_9
    new-instance p0, La8/r0;

    .line 247
    .line 248
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 249
    .line 250
    .line 251
    throw p0
.end method
