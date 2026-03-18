.class public final La7/r0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/util/Set;


# direct methods
.method public synthetic constructor <init>(Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, La7/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La7/r0;->f:Ljava/util/Set;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, La7/r0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, La7/r0;

    .line 7
    .line 8
    iget-object p0, p0, La7/r0;->f:Ljava/util/Set;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, La7/r0;-><init>(Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, La7/r0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, La7/r0;

    .line 18
    .line 19
    iget-object p0, p0, La7/r0;->f:Ljava/util/Set;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, La7/r0;-><init>(Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, La7/r0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La7/r0;->d:I

    .line 2
    .line 3
    check-cast p1, Lq6/b;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, La7/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La7/r0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La7/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La7/r0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, La7/r0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, La7/r0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, La7/r0;->d:I

    .line 2
    .line 3
    iget-object v1, p0, La7/r0;->f:Ljava/util/Set;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, La7/r0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lq6/b;

    .line 16
    .line 17
    invoke-virtual {p0}, Lq6/b;->a()Ljava/util/Map;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljava/lang/Iterable;

    .line 26
    .line 27
    new-instance p1, Ljava/util/ArrayList;

    .line 28
    .line 29
    const/16 v0, 0xa

    .line 30
    .line 31
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_0

    .line 47
    .line 48
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Lq6/e;

    .line 53
    .line 54
    iget-object v0, v0, Lq6/e;->a:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    sget-object p0, Lp6/j;->a:Ljava/util/LinkedHashSet;

    .line 61
    .line 62
    const/4 v0, 0x1

    .line 63
    if-ne v1, p0, :cond_1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    check-cast v1, Ljava/lang/Iterable;

    .line 67
    .line 68
    instance-of p0, v1, Ljava/util/Collection;

    .line 69
    .line 70
    const/4 v2, 0x0

    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    move-object p0, v1

    .line 74
    check-cast p0, Ljava/util/Collection;

    .line 75
    .line 76
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    if-eqz p0, :cond_3

    .line 81
    .line 82
    :cond_2
    move v0, v2

    .line 83
    goto :goto_1

    .line 84
    :cond_3
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_2

    .line 93
    .line 94
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    check-cast v1, Ljava/lang/String;

    .line 99
    .line 100
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-nez v1, :cond_4

    .line 105
    .line 106
    :goto_1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    return-object p0

    .line 111
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object p0, p0, La7/r0;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p0, Lq6/b;

    .line 119
    .line 120
    sget-object p1, La7/v0;->g:Lq6/e;

    .line 121
    .line 122
    invoke-virtual {p0, p1}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    check-cast p1, Ljava/util/Set;

    .line 127
    .line 128
    if-nez p1, :cond_5

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_5
    move-object v0, p1

    .line 132
    check-cast v0, Ljava/lang/Iterable;

    .line 133
    .line 134
    new-instance v2, Ljava/util/ArrayList;

    .line 135
    .line 136
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 137
    .line 138
    .line 139
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    :cond_6
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    if-eqz v3, :cond_7

    .line 148
    .line 149
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    move-object v4, v3

    .line 154
    check-cast v4, Ljava/lang/String;

    .line 155
    .line 156
    invoke-interface {v1, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    if-nez v4, :cond_6

    .line 161
    .line 162
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_7
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    if-eqz v0, :cond_8

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_8
    invoke-virtual {p0}, Lq6/b;->g()Lq6/b;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    sget-object v0, La7/v0;->g:Lq6/e;

    .line 178
    .line 179
    invoke-static {p1, v2}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    invoke-virtual {p0, v0, p1}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 187
    .line 188
    .line 189
    move-result-object p1

    .line 190
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    if-eqz v0, :cond_9

    .line 195
    .line 196
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    check-cast v0, Ljava/lang/String;

    .line 201
    .line 202
    sget-object v1, La7/v0;->d:La7/p0;

    .line 203
    .line 204
    invoke-static {v1, v0}, La7/p0;->a(La7/p0;Ljava/lang/String;)Lq6/e;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    invoke-virtual {p0, v0}, Lq6/b;->d(Lq6/e;)V

    .line 209
    .line 210
    .line 211
    goto :goto_3

    .line 212
    :cond_9
    invoke-virtual {p0}, Lq6/b;->h()Lq6/b;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    :goto_4
    return-object p0

    .line 217
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
