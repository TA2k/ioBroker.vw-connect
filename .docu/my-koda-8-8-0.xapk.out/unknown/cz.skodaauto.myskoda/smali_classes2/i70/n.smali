.class public final Li70/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk70/y;
.implements Lme0/a;


# instance fields
.field public final a:Lve0/u;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/l1;

.field public d:I

.field public final e:Z

.field public final f:Lbn0/f;

.field public final g:Lam0/i;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li70/n;->a:Lve0/u;

    .line 5
    .line 6
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 7
    .line 8
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Li70/n;->b:Lyy0/c2;

    .line 13
    .line 14
    new-instance v1, Lyy0/l1;

    .line 15
    .line 16
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 17
    .line 18
    .line 19
    iput-object v1, p0, Li70/n;->c:Lyy0/l1;

    .line 20
    .line 21
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Ljava/util/Map;

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    iput-boolean v0, p0, Li70/n;->e:Z

    .line 32
    .line 33
    iget-object v0, p1, Lve0/u;->a:Lq6/c;

    .line 34
    .line 35
    iget-object v0, v0, Lq6/c;->a:Lm6/g;

    .line 36
    .line 37
    invoke-interface {v0}, Lm6/g;->getData()Lyy0/i;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    new-instance v1, Lrz/k;

    .line 42
    .line 43
    const/16 v2, 0x8

    .line 44
    .line 45
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    new-instance v1, Lbn0/f;

    .line 53
    .line 54
    const/4 v2, 0x4

    .line 55
    sget-object v3, Lmx0/u;->d:Lmx0/u;

    .line 56
    .line 57
    invoke-direct {v1, v0, v3, p1, v2}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 58
    .line 59
    .line 60
    new-instance v0, Lac/l;

    .line 61
    .line 62
    const/16 v2, 0xe

    .line 63
    .line 64
    invoke-direct {v0, v2, v1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    const-string v1, "remote_trip_statistics_selected_filter"

    .line 68
    .line 69
    const-string v2, ""

    .line 70
    .line 71
    invoke-virtual {p1, v1, v2}, Lve0/u;->j(Ljava/lang/String;Ljava/lang/String;)Lsw0/c;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    new-instance v3, Li70/i;

    .line 76
    .line 77
    const/4 v4, 0x0

    .line 78
    invoke-direct {v3, v1, p0, v4}, Li70/i;-><init>(Lsw0/c;Li70/n;I)V

    .line 79
    .line 80
    .line 81
    new-instance v1, Lal0/y0;

    .line 82
    .line 83
    const/4 v4, 0x3

    .line 84
    const/16 v5, 0x9

    .line 85
    .line 86
    const/4 v6, 0x0

    .line 87
    invoke-direct {v1, v4, v6, v5}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 88
    .line 89
    .line 90
    new-instance v4, Lbn0/f;

    .line 91
    .line 92
    const/4 v5, 0x5

    .line 93
    invoke-direct {v4, v0, v3, v1, v5}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    iput-object v4, p0, Li70/n;->f:Lbn0/f;

    .line 97
    .line 98
    const-string v0, "remote_trip_statistics_selected_interval"

    .line 99
    .line 100
    invoke-virtual {p1, v0, v2}, Lve0/u;->j(Ljava/lang/String;Ljava/lang/String;)Lsw0/c;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    new-instance v0, Li70/i;

    .line 105
    .line 106
    const/4 v1, 0x1

    .line 107
    invoke-direct {v0, p1, p0, v1}, Li70/i;-><init>(Lsw0/c;Li70/n;I)V

    .line 108
    .line 109
    .line 110
    new-instance p1, Lam0/i;

    .line 111
    .line 112
    const/16 v1, 0x9

    .line 113
    .line 114
    invoke-direct {p1, v0, v1}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 115
    .line 116
    .line 117
    iput-object p1, p0, Li70/n;->g:Lam0/i;

    .line 118
    .line 119
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Li70/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Li70/d;

    .line 7
    .line 8
    iget v1, v0, Li70/d;->f:I

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
    iput v1, v0, Li70/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li70/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Li70/d;-><init>(Li70/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Li70/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li70/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    iget-object v6, p0, Li70/n;->a:Lve0/u;

    .line 35
    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Li70/n;->b()V

    .line 68
    .line 69
    .line 70
    iput v5, v0, Li70/d;->f:I

    .line 71
    .line 72
    const-string p0, "remote_trip_statistics_filters"

    .line 73
    .line 74
    invoke-virtual {v6, p0, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    if-ne p0, v1, :cond_5

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_5
    :goto_1
    iput v4, v0, Li70/d;->f:I

    .line 82
    .line 83
    const-string p0, "remote_trip_statistics_selected_filter"

    .line 84
    .line 85
    invoke-virtual {v6, p0, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v1, :cond_6

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_6
    :goto_2
    iput v3, v0, Li70/d;->f:I

    .line 93
    .line 94
    const-string p0, "remote_trip_statistics_selected_interval"

    .line 95
    .line 96
    invoke-virtual {v6, p0, v0}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v1, :cond_7

    .line 101
    .line 102
    :goto_3
    return-object v1

    .line 103
    :cond_7
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object p0, p0, Li70/n;->b:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 8
    .line 9
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final c(Ll70/w;ILne0/s;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p4, Li70/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Li70/k;

    .line 7
    .line 8
    iget v1, v0, Li70/k;->j:I

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
    iput v1, v0, Li70/k;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li70/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Li70/k;-><init>(Li70/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Li70/k;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li70/k;->j:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto/16 :goto_5

    .line 44
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
    iget p1, v0, Li70/k;->g:I

    .line 54
    .line 55
    iget p2, v0, Li70/k;->f:I

    .line 56
    .line 57
    iget p3, v0, Li70/k;->e:I

    .line 58
    .line 59
    iget-object v2, v0, Li70/k;->d:Ll70/p;

    .line 60
    .line 61
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move v7, p3

    .line 65
    move p3, p2

    .line 66
    move p2, v7

    .line 67
    goto :goto_2

    .line 68
    :cond_3
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iput p2, p0, Li70/n;->d:I

    .line 72
    .line 73
    iget-object p4, p0, Li70/n;->b:Lyy0/c2;

    .line 74
    .line 75
    invoke-virtual {p4}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Ljava/util/Map;

    .line 80
    .line 81
    invoke-static {v2}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    new-instance v6, Ll70/y;

    .line 86
    .line 87
    invoke-direct {v6, p1, p2}, Ll70/y;-><init>(Ll70/w;I)V

    .line 88
    .line 89
    .line 90
    invoke-interface {v2, v6, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    invoke-virtual {p4, v5, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    instance-of p1, p3, Lne0/e;

    .line 100
    .line 101
    if-eqz p1, :cond_4

    .line 102
    .line 103
    check-cast p3, Lne0/e;

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_4
    move-object p3, v5

    .line 107
    :goto_1
    if-eqz p3, :cond_7

    .line 108
    .line 109
    iget-object p1, p3, Lne0/e;->a:Ljava/lang/Object;

    .line 110
    .line 111
    move-object v2, p1

    .line 112
    check-cast v2, Ll70/p;

    .line 113
    .line 114
    iget-object p1, v2, Ll70/p;->j:Ll70/a0;

    .line 115
    .line 116
    invoke-static {p1}, Llp/dd;->b(Ll70/a0;)Ljava/util/List;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    iput-object v2, v0, Li70/k;->d:Ll70/p;

    .line 121
    .line 122
    iput p2, v0, Li70/k;->e:I

    .line 123
    .line 124
    const/4 p3, 0x0

    .line 125
    iput p3, v0, Li70/k;->f:I

    .line 126
    .line 127
    iput p3, v0, Li70/k;->g:I

    .line 128
    .line 129
    iput v4, v0, Li70/k;->j:I

    .line 130
    .line 131
    invoke-virtual {p0, p1, v0}, Li70/n;->d(Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p4

    .line 135
    if-ne p4, v1, :cond_5

    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_5
    move p1, p3

    .line 139
    :goto_2
    check-cast p4, Ljava/lang/Boolean;

    .line 140
    .line 141
    invoke-virtual {p4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 142
    .line 143
    .line 144
    move-result p4

    .line 145
    if-eqz p4, :cond_7

    .line 146
    .line 147
    iget-object p4, v2, Ll70/p;->j:Ll70/a0;

    .line 148
    .line 149
    invoke-static {p4}, Llp/dd;->b(Ll70/a0;)Ljava/util/List;

    .line 150
    .line 151
    .line 152
    move-result-object p4

    .line 153
    check-cast p4, Ljava/lang/Iterable;

    .line 154
    .line 155
    new-instance v2, Ljava/util/ArrayList;

    .line 156
    .line 157
    const/16 v4, 0xa

    .line 158
    .line 159
    invoke-static {p4, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 164
    .line 165
    .line 166
    invoke-interface {p4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 167
    .line 168
    .line 169
    move-result-object p4

    .line 170
    :goto_3
    invoke-interface {p4}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v4

    .line 174
    if-eqz v4, :cond_6

    .line 175
    .line 176
    invoke-interface {p4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    check-cast v4, Ll70/q;

    .line 181
    .line 182
    invoke-virtual {v4}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v4

    .line 186
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_6
    invoke-static {v2}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 191
    .line 192
    .line 193
    move-result-object p4

    .line 194
    iput-object v5, v0, Li70/k;->d:Ll70/p;

    .line 195
    .line 196
    iput p2, v0, Li70/k;->e:I

    .line 197
    .line 198
    iput p3, v0, Li70/k;->f:I

    .line 199
    .line 200
    iput p1, v0, Li70/k;->g:I

    .line 201
    .line 202
    iput v3, v0, Li70/k;->j:I

    .line 203
    .line 204
    iget-object p0, p0, Li70/n;->a:Lve0/u;

    .line 205
    .line 206
    const-string p1, "remote_trip_statistics_filters"

    .line 207
    .line 208
    invoke-virtual {p0, p1, p4, v0}, Lve0/u;->o(Ljava/lang/String;Ljava/util/Set;Lrx0/c;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    if-ne p0, v1, :cond_7

    .line 213
    .line 214
    :goto_4
    return-object v1

    .line 215
    :cond_7
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object p0
.end method

.method public final d(Ljava/util/List;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Li70/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Li70/l;

    .line 7
    .line 8
    iget v1, v0, Li70/l;->g:I

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
    iput v1, v0, Li70/l;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li70/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Li70/l;-><init>(Li70/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Li70/l;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li70/l;->g:I

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
    iget-object p0, v0, Li70/l;->d:Ljava/util/List;

    .line 37
    .line 38
    move-object p1, p0

    .line 39
    check-cast p1, Ljava/util/List;

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move-object p2, p1

    .line 57
    check-cast p2, Ljava/util/List;

    .line 58
    .line 59
    iput-object p2, v0, Li70/l;->d:Ljava/util/List;

    .line 60
    .line 61
    iput v3, v0, Li70/l;->g:I

    .line 62
    .line 63
    iget-object p0, p0, Li70/n;->a:Lve0/u;

    .line 64
    .line 65
    const-string p2, "remote_trip_statistics_filters"

    .line 66
    .line 67
    invoke-virtual {p0, p2, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-ne p2, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    :goto_1
    check-cast p2, Ljava/util/Set;

    .line 75
    .line 76
    if-nez p2, :cond_4

    .line 77
    .line 78
    sget-object p2, Lmx0/u;->d:Lmx0/u;

    .line 79
    .line 80
    :cond_4
    check-cast p1, Ljava/lang/Iterable;

    .line 81
    .line 82
    new-instance p0, Ljava/util/ArrayList;

    .line 83
    .line 84
    const/16 v0, 0xa

    .line 85
    .line 86
    invoke-static {p1, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    invoke-direct {p0, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    if-eqz v0, :cond_5

    .line 102
    .line 103
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    check-cast v0, Ll70/q;

    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_5
    invoke-static {p0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Ljava/util/Collection;

    .line 122
    .line 123
    invoke-interface {p2, p0}, Ljava/util/Set;->containsAll(Ljava/util/Collection;)Z

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    xor-int/2addr p0, v3

    .line 128
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0
.end method
