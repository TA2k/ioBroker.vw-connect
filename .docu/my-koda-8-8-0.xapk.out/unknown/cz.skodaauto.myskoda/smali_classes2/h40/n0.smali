.class public final synthetic Lh40/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/p0;


# direct methods
.method public synthetic constructor <init>(Lh40/p0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/n0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/n0;->e:Lh40/p0;

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
    iget v0, p0, Lh40/n0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onStartCollecting(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Lh40/p0;

    .line 13
    .line 14
    iget-object v5, p0, Lh40/n0;->e:Lh40/p0;

    .line 15
    .line 16
    const-string v6, "onStartCollecting"

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
    const-string v8, "onBadgesFetched(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Lh40/p0;

    .line 29
    .line 30
    iget-object v6, p0, Lh40/n0;->e:Lh40/p0;

    .line 31
    .line 32
    const-string v7, "onBadgesFetched"

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
    .locals 3

    .line 1
    iget p2, p0, Lh40/n0;->d:I

    .line 2
    .line 3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    iget-object p0, p0, Lh40/n0;->e:Lh40/p0;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    packed-switch p2, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p1, Lne0/s;

    .line 13
    .line 14
    instance-of p2, p1, Lne0/d;

    .line 15
    .line 16
    if-eqz p2, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, Lh40/m0;

    .line 23
    .line 24
    invoke-static {p1, v1}, Lh40/m0;->a(Lh40/m0;Z)Lh40/m0;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 33
    .line 34
    if-eqz p2, :cond_1

    .line 35
    .line 36
    iget-object p1, p0, Lh40/p0;->k:Lf40/p0;

    .line 37
    .line 38
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance p2, Lh40/o0;

    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    invoke-direct {p2, p0, v1, v2}, Lh40/o0;-><init>(Lh40/p0;Lkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    const/4 p0, 0x3

    .line 52
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    instance-of p2, p1, Lne0/c;

    .line 57
    .line 58
    if-eqz p2, :cond_2

    .line 59
    .line 60
    check-cast p1, Lne0/c;

    .line 61
    .line 62
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    check-cast p2, Lh40/m0;

    .line 67
    .line 68
    iget-object v1, p0, Lh40/p0;->h:Lij0/a;

    .line 69
    .line 70
    invoke-static {p1, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    new-instance p2, Lh40/m0;

    .line 78
    .line 79
    invoke-direct {p2, p1, v2}, Lh40/m0;-><init>(Lql0/g;Z)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 83
    .line 84
    .line 85
    :goto_0
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 86
    .line 87
    return-object v0

    .line 88
    :cond_2
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    new-instance p0, La8/r0;

    .line 92
    .line 93
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 98
    .line 99
    instance-of p2, p1, Lne0/d;

    .line 100
    .line 101
    if-eqz p2, :cond_3

    .line 102
    .line 103
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    check-cast p1, Lh40/m0;

    .line 108
    .line 109
    invoke-static {p1, v1}, Lh40/m0;->a(Lh40/m0;Z)Lh40/m0;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 114
    .line 115
    .line 116
    goto/16 :goto_3

    .line 117
    .line 118
    :cond_3
    instance-of p2, p1, Lne0/e;

    .line 119
    .line 120
    if-eqz p2, :cond_8

    .line 121
    .line 122
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    check-cast p2, Lh40/m0;

    .line 127
    .line 128
    invoke-static {p2, v2}, Lh40/m0;->a(Lh40/m0;Z)Lh40/m0;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 133
    .line 134
    .line 135
    check-cast p1, Lne0/e;

    .line 136
    .line 137
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast p1, Ljava/lang/Iterable;

    .line 140
    .line 141
    new-instance p2, Ljava/util/ArrayList;

    .line 142
    .line 143
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 144
    .line 145
    .line 146
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    if-eqz v1, :cond_4

    .line 155
    .line 156
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    check-cast v1, Lg40/o;

    .line 161
    .line 162
    iget-object v1, v1, Lg40/o;->c:Ljava/util/List;

    .line 163
    .line 164
    check-cast v1, Ljava/lang/Iterable;

    .line 165
    .line 166
    invoke-static {v1, p2}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 167
    .line 168
    .line 169
    goto :goto_1

    .line 170
    :cond_4
    invoke-virtual {p2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 171
    .line 172
    .line 173
    move-result p1

    .line 174
    if-eqz p1, :cond_5

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_5
    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    :cond_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 182
    .line 183
    .line 184
    move-result p2

    .line 185
    if-eqz p2, :cond_7

    .line 186
    .line 187
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p2

    .line 191
    check-cast p2, Lg40/h;

    .line 192
    .line 193
    iget-boolean p2, p2, Lg40/h;->e:Z

    .line 194
    .line 195
    if-eqz p2, :cond_6

    .line 196
    .line 197
    iget-object p0, p0, Lh40/p0;->m:Lf40/s1;

    .line 198
    .line 199
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    goto :goto_3

    .line 203
    :cond_7
    :goto_2
    iget-object p0, p0, Lh40/p0;->i:Ltr0/b;

    .line 204
    .line 205
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    goto :goto_3

    .line 209
    :cond_8
    instance-of p2, p1, Lne0/c;

    .line 210
    .line 211
    if-eqz p2, :cond_9

    .line 212
    .line 213
    check-cast p1, Lne0/c;

    .line 214
    .line 215
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 216
    .line 217
    .line 218
    move-result-object p2

    .line 219
    check-cast p2, Lh40/m0;

    .line 220
    .line 221
    iget-object v1, p0, Lh40/p0;->h:Lij0/a;

    .line 222
    .line 223
    invoke-static {p1, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    new-instance p2, Lh40/m0;

    .line 231
    .line 232
    invoke-direct {p2, p1, v2}, Lh40/m0;-><init>(Lql0/g;Z)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 236
    .line 237
    .line 238
    :goto_3
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 239
    .line 240
    return-object v0

    .line 241
    :cond_9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 242
    .line 243
    .line 244
    new-instance p0, La8/r0;

    .line 245
    .line 246
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 247
    .line 248
    .line 249
    throw p0

    .line 250
    nop

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Lh40/n0;->d:I

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
    iget v0, p0, Lh40/n0;->d:I

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
