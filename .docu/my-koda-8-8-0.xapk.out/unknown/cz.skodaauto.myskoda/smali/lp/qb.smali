.class public abstract Llp/qb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvk0/f;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvk0/f;->a:Lvk0/k;

    .line 7
    .line 8
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_4

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    if-eq p0, v0, :cond_3

    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    if-eq p0, v0, :cond_2

    .line 22
    .line 23
    const/4 v0, 0x3

    .line 24
    if-eq p0, v0, :cond_1

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    if-ne p0, v0, :cond_0

    .line 28
    .line 29
    const p0, 0x7f08045e

    .line 30
    .line 31
    .line 32
    return p0

    .line 33
    :cond_0
    new-instance p0, La8/r0;

    .line 34
    .line 35
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    const p0, 0x7f08045c

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :cond_2
    const p0, 0x7f08045a

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :cond_3
    const p0, 0x7f080463

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :cond_4
    const p0, 0x7f080461

    .line 52
    .line 53
    .line 54
    return p0
.end method

.method public static final b(Lmb0/c;)Ljb0/c;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljb0/c;

    .line 7
    .line 8
    iget-object v1, p0, Lmb0/c;->a:Lqr0/q;

    .line 9
    .line 10
    invoke-static {v1}, Llp/qb;->c(Lqr0/q;)Ljb0/l;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object p0, p0, Lmb0/c;->b:Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    invoke-direct {v0, v1, p0}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public static final c(Lqr0/q;)Ljb0/l;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljb0/l;

    .line 7
    .line 8
    iget-wide v1, p0, Lqr0/q;->a:D

    .line 9
    .line 10
    iget-object p0, p0, Lqr0/q;->b:Lqr0/r;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, v1, v2, p0}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public static final d(Lmb0/f;Ljava/lang/String;)Ljb0/g;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "$this$toEntity"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 9
    .line 10
    move-object/from16 v3, p1

    .line 11
    .line 12
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Ljb0/g;

    .line 16
    .line 17
    iget-object v1, v0, Lmb0/f;->a:Lmb0/e;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    iget-object v5, v0, Lmb0/f;->c:Ljava/lang/Boolean;

    .line 24
    .line 25
    iget-object v6, v0, Lmb0/f;->d:Ljava/time/OffsetDateTime;

    .line 26
    .line 27
    iget-object v7, v0, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 28
    .line 29
    iget-object v8, v0, Lmb0/f;->g:Ljava/lang/Boolean;

    .line 30
    .line 31
    iget-object v1, v0, Lmb0/f;->h:Lmb0/m;

    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v9

    .line 37
    iget-object v1, v0, Lmb0/f;->j:Lmb0/i;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v10

    .line 43
    iget-object v1, v0, Lmb0/f;->k:Lmb0/g;

    .line 44
    .line 45
    if-eqz v1, :cond_0

    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const/4 v1, 0x0

    .line 53
    :goto_0
    iget-object v12, v0, Lmb0/f;->l:Ljava/util/List;

    .line 54
    .line 55
    move-object v13, v12

    .line 56
    check-cast v13, Ljava/lang/Iterable;

    .line 57
    .line 58
    new-instance v12, Lim0/b;

    .line 59
    .line 60
    const/16 v14, 0x13

    .line 61
    .line 62
    invoke-direct {v12, v14}, Lim0/b;-><init>(I)V

    .line 63
    .line 64
    .line 65
    const/16 v18, 0x1e

    .line 66
    .line 67
    const-string v14, ","

    .line 68
    .line 69
    const/4 v15, 0x0

    .line 70
    const/16 v16, 0x0

    .line 71
    .line 72
    move-object/from16 v17, v12

    .line 73
    .line 74
    invoke-static/range {v13 .. v18}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v12

    .line 78
    iget-object v13, v0, Lmb0/f;->o:Ljava/time/OffsetDateTime;

    .line 79
    .line 80
    iget-object v14, v0, Lmb0/f;->e:Lqr0/q;

    .line 81
    .line 82
    if-eqz v14, :cond_1

    .line 83
    .line 84
    invoke-static {v14}, Llp/qb;->c(Lqr0/q;)Ljb0/l;

    .line 85
    .line 86
    .line 87
    move-result-object v14

    .line 88
    goto :goto_1

    .line 89
    :cond_1
    const/4 v14, 0x0

    .line 90
    :goto_1
    iget-object v15, v0, Lmb0/f;->b:Lmb0/n;

    .line 91
    .line 92
    new-instance v11, Ljb0/o;

    .line 93
    .line 94
    move-object/from16 v17, v1

    .line 95
    .line 96
    iget-object v1, v15, Lmb0/n;->a:Lmb0/o;

    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    iget-object v15, v15, Lmb0/n;->b:Lmb0/o;

    .line 103
    .line 104
    invoke-virtual {v15}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v15

    .line 108
    invoke-direct {v11, v1, v15}, Ljb0/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    iget-object v1, v0, Lmb0/f;->i:Lmb0/l;

    .line 112
    .line 113
    new-instance v15, Ljb0/e;

    .line 114
    .line 115
    move-object/from16 v18, v2

    .line 116
    .line 117
    iget-object v2, v1, Lmb0/l;->a:Ljava/lang/Boolean;

    .line 118
    .line 119
    iget-object v3, v1, Lmb0/l;->b:Ljava/lang/Boolean;

    .line 120
    .line 121
    move-object/from16 v19, v4

    .line 122
    .line 123
    iget-object v4, v1, Lmb0/l;->c:Ljava/lang/Boolean;

    .line 124
    .line 125
    iget-object v1, v1, Lmb0/l;->d:Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-direct {v15, v2, v3, v4, v1}, Ljb0/e;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 128
    .line 129
    .line 130
    iget-object v1, v0, Lmb0/f;->n:Ljava/util/List;

    .line 131
    .line 132
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    check-cast v1, Lmb0/k;

    .line 137
    .line 138
    if-eqz v1, :cond_3

    .line 139
    .line 140
    new-instance v2, Ljb0/d;

    .line 141
    .line 142
    iget-object v3, v1, Lmb0/k;->a:Ljava/lang/String;

    .line 143
    .line 144
    iget-object v1, v1, Lmb0/k;->b:Lqr0/q;

    .line 145
    .line 146
    if-eqz v1, :cond_2

    .line 147
    .line 148
    invoke-static {v1}, Llp/qb;->c(Lqr0/q;)Ljb0/l;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    goto :goto_2

    .line 153
    :cond_2
    const/4 v1, 0x0

    .line 154
    :goto_2
    invoke-direct {v2, v3, v1}, Ljb0/d;-><init>(Ljava/lang/String;Ljb0/l;)V

    .line 155
    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_3
    const/4 v2, 0x0

    .line 159
    :goto_3
    iget-object v0, v0, Lmb0/f;->p:Lmb0/c;

    .line 160
    .line 161
    if-eqz v0, :cond_4

    .line 162
    .line 163
    invoke-static {v0}, Llp/qb;->b(Lmb0/c;)Ljb0/c;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    move-object/from16 v16, v15

    .line 168
    .line 169
    move-object v15, v11

    .line 170
    move-object/from16 v11, v17

    .line 171
    .line 172
    move-object/from16 v17, v2

    .line 173
    .line 174
    move-object/from16 v2, v18

    .line 175
    .line 176
    move-object/from16 v18, v0

    .line 177
    .line 178
    :goto_4
    move-object/from16 v3, p1

    .line 179
    .line 180
    move-object/from16 v4, v19

    .line 181
    .line 182
    goto :goto_5

    .line 183
    :cond_4
    move-object/from16 v16, v15

    .line 184
    .line 185
    move-object v15, v11

    .line 186
    move-object/from16 v11, v17

    .line 187
    .line 188
    move-object/from16 v17, v2

    .line 189
    .line 190
    move-object/from16 v2, v18

    .line 191
    .line 192
    const/16 v18, 0x0

    .line 193
    .line 194
    goto :goto_4

    .line 195
    :goto_5
    invoke-direct/range {v2 .. v18}, Ljb0/g;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/time/OffsetDateTime;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljb0/l;Ljb0/o;Ljb0/e;Ljb0/d;Ljb0/c;)V

    .line 196
    .line 197
    .line 198
    return-object v2
.end method

.method public static final e(Ljb0/c;)Lmb0/c;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lmb0/c;

    .line 7
    .line 8
    iget-object v1, p0, Ljb0/c;->a:Ljb0/l;

    .line 9
    .line 10
    invoke-static {v1}, Llp/qb;->f(Ljb0/l;)Lqr0/q;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object p0, p0, Ljb0/c;->b:Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    invoke-direct {v0, v1, p0}, Lmb0/c;-><init>(Lqr0/q;Ljava/time/OffsetDateTime;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public static final f(Ljb0/l;)Lqr0/q;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lqr0/q;

    .line 7
    .line 8
    iget-wide v1, p0, Ljb0/l;->a:D

    .line 9
    .line 10
    iget-object p0, p0, Ljb0/l;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {p0}, Lqr0/r;->valueOf(Ljava/lang/String;)Lqr0/r;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, v1, v2, p0}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 17
    .line 18
    .line 19
    return-object v0
.end method
