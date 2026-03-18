.class public final Lj00/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll00/l;


# instance fields
.field public final a:Lrh0/f;

.field public final b:Llx0/q;


# direct methods
.method public constructor <init>(Lrh0/f;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj00/d;->a:Lrh0/f;

    .line 5
    .line 6
    new-instance p1, Lj00/a;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {p1, v0}, Lj00/a;-><init>(I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lj00/d;->b:Llx0/q;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/io/Serializable;
    .locals 8

    .line 1
    instance-of v0, p1, Lj00/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj00/b;

    .line 7
    .line 8
    iget v1, v0, Lj00/b;->f:I

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
    iput v1, v0, Lj00/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj00/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lj00/b;-><init>(Lj00/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lj00/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj00/b;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Lqh0/a;->h:Lqh0/a;

    .line 52
    .line 53
    iput v3, v0, Lj00/b;->f:I

    .line 54
    .line 55
    iget-object v2, p0, Lj00/d;->a:Lrh0/f;

    .line 56
    .line 57
    invoke-virtual {v2, p1, v0}, Lrh0/f;->d(Lqh0/a;Lrx0/c;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 65
    .line 66
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 67
    .line 68
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 69
    .line 70
    .line 71
    :try_start_0
    const-class v1, Ljava/util/Map;

    .line 72
    .line 73
    const/4 v2, 0x2

    .line 74
    new-array v2, v2, [Ljava/lang/reflect/Type;

    .line 75
    .line 76
    const-class v4, Ljava/lang/String;

    .line 77
    .line 78
    const/4 v5, 0x0

    .line 79
    aput-object v4, v2, v5

    .line 80
    .line 81
    const-class v4, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;

    .line 82
    .line 83
    aput-object v4, v2, v3

    .line 84
    .line 85
    invoke-static {v1, v2}, Lcom/squareup/moshi/Types;->d(Ljava/lang/Class;[Ljava/lang/reflect/Type;)Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    iget-object v2, p0, Lj00/d;->b:Llx0/q;

    .line 90
    .line 91
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    check-cast v2, Lcom/squareup/moshi/Moshi;

    .line 96
    .line 97
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    sget-object v4, Lax/b;->a:Ljava/util/Set;

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    invoke-virtual {v2, v1, v4, v5}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-virtual {v1, p1}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    check-cast p1, Ljava/util/Map;

    .line 112
    .line 113
    if-nez p1, :cond_4

    .line 114
    .line 115
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :catchall_0
    move-exception p1

    .line 119
    goto :goto_4

    .line 120
    :cond_4
    :goto_2
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    if-eqz v1, :cond_5

    .line 133
    .line 134
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    check-cast v1, Ljava/util/Map$Entry;

    .line 139
    .line 140
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    check-cast v2, Ljava/lang/String;

    .line 145
    .line 146
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    check-cast v1, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;

    .line 151
    .line 152
    sget-object v4, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 153
    .line 154
    invoke-virtual {v2, v4}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    const-string v4, "toLowerCase(...)"

    .line 159
    .line 160
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    const-string v4, "default"

    .line 164
    .line 165
    invoke-virtual {v2, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v4

    .line 169
    xor-int/2addr v4, v3

    .line 170
    const-string v5, "<this>"

    .line 171
    .line 172
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    new-instance v5, Lm00/a;

    .line 176
    .line 177
    invoke-virtual {v1}, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->getLinkUrl()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    invoke-virtual {v1}, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->getBannerEnabled()Z

    .line 182
    .line 183
    .line 184
    move-result v7

    .line 185
    invoke-virtual {v1}, Lcz/skodaauto/myskoda/feature/connectivitysunset/data/ConnectivitySunsetConfigDto;->getFullScreenEnabled()Z

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    invoke-direct {v5, v6, v4, v7, v1}, Lm00/a;-><init>(Ljava/lang/String;ZZZ)V

    .line 190
    .line 191
    .line 192
    invoke-interface {v0, v2, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_5
    sget-object p1, Llx0/b0;->a:Llx0/b0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 197
    .line 198
    goto :goto_5

    .line 199
    :goto_4
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    :goto_5
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    if-nez p1, :cond_6

    .line 208
    .line 209
    goto :goto_6

    .line 210
    :cond_6
    invoke-static {p0, p1}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 211
    .line 212
    .line 213
    :goto_6
    return-object v0
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lj00/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj00/c;

    .line 7
    .line 8
    iget v1, v0, Lj00/c;->g:I

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
    iput v1, v0, Lj00/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj00/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj00/c;-><init>(Lj00/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj00/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj00/c;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lj00/c;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lj00/c;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lj00/c;->g:I

    .line 56
    .line 57
    invoke-virtual {p0, v0}, Lj00/d;->a(Lrx0/c;)Ljava/io/Serializable;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    if-ne p2, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p2, Ljava/util/Map;

    .line 65
    .line 66
    if-eqz p1, :cond_4

    .line 67
    .line 68
    sget-object p0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 69
    .line 70
    invoke-virtual {p1, p0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    const-string p1, "toLowerCase(...)"

    .line 75
    .line 76
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_4
    const/4 p0, 0x0

    .line 81
    :goto_2
    invoke-interface {p2, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lm00/a;

    .line 86
    .line 87
    if-nez p0, :cond_5

    .line 88
    .line 89
    const-string p0, "default"

    .line 90
    .line 91
    invoke-interface {p2, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    check-cast p0, Lm00/a;

    .line 96
    .line 97
    if-nez p0, :cond_5

    .line 98
    .line 99
    new-instance p0, Lm00/a;

    .line 100
    .line 101
    const-string p1, ""

    .line 102
    .line 103
    const/4 p2, 0x0

    .line 104
    invoke-direct {p0, p1, p2, p2, p2}, Lm00/a;-><init>(Ljava/lang/String;ZZZ)V

    .line 105
    .line 106
    .line 107
    :cond_5
    return-object p0
.end method
