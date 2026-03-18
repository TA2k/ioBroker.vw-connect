.class public final Lmj0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lti0/a;

.field public final b:Lny/d;


# direct methods
.method public constructor <init>(Lti0/a;Lny/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmj0/e;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lmj0/e;->b:Lny/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lmj0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lmj0/c;

    .line 7
    .line 8
    iget v1, v0, Lmj0/c;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lmj0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lmj0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lmj0/c;-><init>(Lmj0/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lmj0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lmj0/c;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v5, v0, Lmj0/c;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Lmj0/e;->a:Lti0/a;

    .line 63
    .line 64
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Lmj0/a;

    .line 72
    .line 73
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    const-wide/16 v6, 0x2

    .line 78
    .line 79
    invoke-virtual {p0, v6, v7}, Ljava/time/OffsetDateTime;->minusHours(J)Ljava/time/OffsetDateTime;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    const-string v2, "minusHours(...)"

    .line 84
    .line 85
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iput v4, v0, Lmj0/c;->f:I

    .line 89
    .line 90
    iget-object v2, p1, Lmj0/a;->a:Lla/u;

    .line 91
    .line 92
    new-instance v4, Lla/p;

    .line 93
    .line 94
    invoke-direct {v4, p1, p0}, Lla/p;-><init>(Lmj0/a;Ljava/time/OffsetDateTime;)V

    .line 95
    .line 96
    .line 97
    const/4 p0, 0x0

    .line 98
    invoke-static {v0, v2, p0, v5, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-ne p0, v1, :cond_5

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_5
    move-object p0, v3

    .line 106
    :goto_2
    if-ne p0, v1, :cond_6

    .line 107
    .line 108
    :goto_3
    return-object v1

    .line 109
    :cond_6
    return-object v3
.end method

.method public final b(Lrx0/c;)Ljava/io/Serializable;
    .locals 5

    .line 1
    instance-of v0, p1, Lmj0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lmj0/d;

    .line 7
    .line 8
    iget v1, v0, Lmj0/d;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lmj0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lmj0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lmj0/d;-><init>(Lmj0/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lmj0/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lmj0/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lmj0/d;->f:I

    .line 59
    .line 60
    iget-object p0, p0, Lmj0/e;->a:Lti0/a;

    .line 61
    .line 62
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-ne p1, v1, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    :goto_1
    check-cast p1, Lmj0/a;

    .line 70
    .line 71
    iput v3, v0, Lmj0/d;->f:I

    .line 72
    .line 73
    iget-object p0, p1, Lmj0/a;->a:Lla/u;

    .line 74
    .line 75
    new-instance v2, Lmj/g;

    .line 76
    .line 77
    invoke-direct {v2, p1}, Lmj/g;-><init>(Lmj0/a;)V

    .line 78
    .line 79
    .line 80
    const/4 p1, 0x0

    .line 81
    invoke-static {v0, p0, v4, p1, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    if-ne p1, v1, :cond_5

    .line 86
    .line 87
    :goto_2
    return-object v1

    .line 88
    :cond_5
    :goto_3
    check-cast p1, Ljava/lang/Iterable;

    .line 89
    .line 90
    new-instance p0, Ljava/util/ArrayList;

    .line 91
    .line 92
    const/16 v0, 0xa

    .line 93
    .line 94
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 99
    .line 100
    .line 101
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-eqz v0, :cond_e

    .line 110
    .line 111
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    check-cast v0, Lmj0/b;

    .line 116
    .line 117
    const-string v1, "<this>"

    .line 118
    .line 119
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object v1, v0, Lmj0/b;->c:Ljava/lang/String;

    .line 123
    .line 124
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    const/16 v3, 0x44

    .line 129
    .line 130
    if-eq v2, v3, :cond_c

    .line 131
    .line 132
    const/16 v3, 0x45

    .line 133
    .line 134
    if-eq v2, v3, :cond_a

    .line 135
    .line 136
    const/16 v3, 0x49

    .line 137
    .line 138
    if-eq v2, v3, :cond_8

    .line 139
    .line 140
    const/16 v3, 0x57

    .line 141
    .line 142
    if-eq v2, v3, :cond_6

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_6
    const-string v2, "W"

    .line 146
    .line 147
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-nez v1, :cond_7

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_7
    sget-object v1, Lkj0/e;->g:Lkj0/e;

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_8
    const-string v2, "I"

    .line 158
    .line 159
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    if-nez v1, :cond_9

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_9
    sget-object v1, Lkj0/e;->f:Lkj0/e;

    .line 167
    .line 168
    goto :goto_6

    .line 169
    :cond_a
    const-string v2, "E"

    .line 170
    .line 171
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    if-nez v1, :cond_b

    .line 176
    .line 177
    goto :goto_5

    .line 178
    :cond_b
    sget-object v1, Lkj0/e;->h:Lkj0/e;

    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_c
    const-string v2, "D"

    .line 182
    .line 183
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v1

    .line 187
    if-nez v1, :cond_d

    .line 188
    .line 189
    :goto_5
    sget-object v1, Lkj0/e;->d:Lkj0/e;

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_d
    sget-object v1, Lkj0/e;->e:Lkj0/e;

    .line 193
    .line 194
    :goto_6
    iget-object v2, v0, Lmj0/b;->d:Ljava/lang/String;

    .line 195
    .line 196
    iget-object v3, v0, Lmj0/b;->e:Ljava/lang/String;

    .line 197
    .line 198
    iget-object v0, v0, Lmj0/b;->b:Ljava/time/OffsetDateTime;

    .line 199
    .line 200
    new-instance v4, Lkj0/f;

    .line 201
    .line 202
    invoke-direct {v4, v0, v1, v2, v3}, Lkj0/f;-><init>(Ljava/time/OffsetDateTime;Lkj0/e;Ljava/lang/String;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    goto :goto_4

    .line 209
    :cond_e
    return-object p0
.end method
