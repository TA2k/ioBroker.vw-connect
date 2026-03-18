.class public abstract Ljp/qg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lwq/f;Lhy0/a0;Z)Lqz0/a;
    .locals 5

    .line 1
    invoke-static {p1}, Luz0/b1;->j(Lhy0/a0;)Lhy0/d;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {p1}, Lhy0/a0;->isMarkedNullable()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-interface {p1}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Ljava/lang/Iterable;

    .line 14
    .line 15
    new-instance v2, Ljava/util/ArrayList;

    .line 16
    .line 17
    const/16 v3, 0xa

    .line 18
    .line 19
    invoke-static {p1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    check-cast v3, Lhy0/d0;

    .line 41
    .line 42
    const-string v4, "<this>"

    .line 43
    .line 44
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object v3, v3, Lhy0/d0;->b:Lhy0/a0;

    .line 48
    .line 49
    if-eqz v3, :cond_0

    .line 50
    .line 51
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 56
    .line 57
    const-string p1, "Star projections in type arguments are not allowed, but had "

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p1

    .line 79
    :cond_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    const/4 v3, 0x0

    .line 84
    if-eqz p1, :cond_5

    .line 85
    .line 86
    invoke-static {v0}, Luz0/b1;->i(Lhy0/d;)Z

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    if-eqz p1, :cond_2

    .line 91
    .line 92
    invoke-static {p0, v0}, Lwq/f;->l(Lwq/f;Lhy0/d;)V

    .line 93
    .line 94
    .line 95
    :cond_2
    sget-object p1, Lqz0/i;->a:Luz0/m1;

    .line 96
    .line 97
    if-nez v1, :cond_4

    .line 98
    .line 99
    sget-object p1, Lqz0/i;->a:Luz0/m1;

    .line 100
    .line 101
    invoke-interface {p1, v0}, Luz0/m1;->h(Lhy0/d;)Lqz0/a;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    if-eqz p1, :cond_3

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_3
    move-object p1, v3

    .line 109
    goto :goto_2

    .line 110
    :cond_4
    sget-object p1, Lqz0/i;->b:Luz0/m1;

    .line 111
    .line 112
    invoke-interface {p1, v0}, Luz0/m1;->h(Lhy0/d;)Lqz0/a;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    goto :goto_2

    .line 117
    :cond_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    sget-object p1, Lqz0/i;->a:Luz0/m1;

    .line 121
    .line 122
    if-nez v1, :cond_6

    .line 123
    .line 124
    sget-object p1, Lqz0/i;->c:Luz0/a1;

    .line 125
    .line 126
    invoke-interface {p1, v0, v2}, Luz0/a1;->x(Lhy0/d;Ljava/util/ArrayList;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    goto :goto_1

    .line 131
    :cond_6
    sget-object p1, Lqz0/i;->d:Luz0/a1;

    .line 132
    .line 133
    invoke-interface {p1, v0, v2}, Luz0/a1;->x(Lhy0/d;Ljava/util/ArrayList;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    :goto_1
    instance-of v4, p1, Llx0/n;

    .line 138
    .line 139
    if-eqz v4, :cond_7

    .line 140
    .line 141
    move-object p1, v3

    .line 142
    :cond_7
    check-cast p1, Lqz0/a;

    .line 143
    .line 144
    :goto_2
    if-eqz p1, :cond_8

    .line 145
    .line 146
    return-object p1

    .line 147
    :cond_8
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    if-eqz p1, :cond_a

    .line 152
    .line 153
    invoke-static {v0}, Ljp/mg;->f(Lhy0/d;)Lqz0/a;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    if-nez p1, :cond_c

    .line 158
    .line 159
    invoke-static {p0, v0}, Lwq/f;->l(Lwq/f;Lhy0/d;)V

    .line 160
    .line 161
    .line 162
    invoke-static {v0}, Luz0/b1;->i(Lhy0/d;)Z

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    if-eqz p0, :cond_9

    .line 167
    .line 168
    new-instance p0, Lqz0/d;

    .line 169
    .line 170
    invoke-direct {p0, v0}, Lqz0/d;-><init>(Lhy0/d;)V

    .line 171
    .line 172
    .line 173
    :goto_3
    move-object p1, p0

    .line 174
    goto :goto_4

    .line 175
    :cond_9
    move-object p1, v3

    .line 176
    goto :goto_4

    .line 177
    :cond_a
    invoke-static {p0, v2, p2}, Ljp/mg;->h(Lwq/f;Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    if-nez p0, :cond_b

    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_b
    new-instance p1, Low0/c0;

    .line 185
    .line 186
    const/4 p2, 0x1

    .line 187
    invoke-direct {p1, v2, p2}, Low0/c0;-><init>(Ljava/util/ArrayList;I)V

    .line 188
    .line 189
    .line 190
    invoke-static {v0, p0, p1}, Ljp/mg;->b(Lhy0/d;Ljava/util/ArrayList;Lay0/a;)Lqz0/a;

    .line 191
    .line 192
    .line 193
    move-result-object p1

    .line 194
    if-nez p1, :cond_c

    .line 195
    .line 196
    invoke-static {v0}, Luz0/b1;->i(Lhy0/d;)Z

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    if-eqz p0, :cond_9

    .line 201
    .line 202
    new-instance p0, Lqz0/d;

    .line 203
    .line 204
    invoke-direct {p0, v0}, Lqz0/d;-><init>(Lhy0/d;)V

    .line 205
    .line 206
    .line 207
    goto :goto_3

    .line 208
    :cond_c
    :goto_4
    if-eqz p1, :cond_e

    .line 209
    .line 210
    if-eqz v1, :cond_d

    .line 211
    .line 212
    invoke-static {p1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    return-object p0

    .line 217
    :cond_d
    return-object p1

    .line 218
    :cond_e
    :goto_5
    return-object v3
.end method

.method public static final b(Ld01/t0;)Ld01/t0;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ld01/t0;->d()Ld01/s0;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Le01/c;

    .line 11
    .line 12
    iget-object p0, p0, Ld01/t0;->j:Ld01/v0;

    .line 13
    .line 14
    invoke-virtual {p0}, Ld01/v0;->d()Ld01/d0;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {p0}, Ld01/v0;->b()J

    .line 19
    .line 20
    .line 21
    move-result-wide v3

    .line 22
    invoke-direct {v1, v2, v3, v4}, Le01/c;-><init>(Ld01/d0;J)V

    .line 23
    .line 24
    .line 25
    iput-object v1, v0, Ld01/s0;->g:Ld01/v0;

    .line 26
    .line 27
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
