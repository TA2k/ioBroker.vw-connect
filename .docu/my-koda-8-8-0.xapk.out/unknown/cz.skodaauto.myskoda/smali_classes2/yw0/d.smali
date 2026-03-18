.class public abstract Lyw0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public b:I

.field public c:Z

.field public d:Lj51/i;

.field private volatile synthetic interceptors$delegate:Ljava/lang/Object;


# direct methods
.method public varargs constructor <init>([Lj51/i;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lvw0/d;

    .line 5
    .line 6
    invoke-direct {v0}, Lvw0/d;-><init>()V

    .line 7
    .line 8
    .line 9
    array-length v0, p1

    .line 10
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-static {p1}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 19
    .line 20
    const/4 p1, 0x0

    .line 21
    iput-object p1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    invoke-interface {p3}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/util/List;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-nez v1, :cond_9

    .line 11
    .line 12
    iget v1, p0, Lyw0/d;->b:I

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 19
    .line 20
    iput-object v1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 21
    .line 22
    iput-boolean v3, p0, Lyw0/d;->c:Z

    .line 23
    .line 24
    iput-object v4, p0, Lyw0/d;->d:Lj51/i;

    .line 25
    .line 26
    goto/16 :goto_7

    .line 27
    .line 28
    :cond_0
    iget-object v5, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 29
    .line 30
    if-ne v1, v2, :cond_4

    .line 31
    .line 32
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-ltz v1, :cond_4

    .line 37
    .line 38
    move v6, v3

    .line 39
    :goto_0
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    instance-of v8, v7, Lyw0/c;

    .line 44
    .line 45
    if-eqz v8, :cond_1

    .line 46
    .line 47
    check-cast v7, Lyw0/c;

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move-object v7, v4

    .line 51
    :goto_1
    if-nez v7, :cond_2

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    iget-object v8, v7, Lyw0/c;->c:Ljava/util/List;

    .line 55
    .line 56
    invoke-interface {v8}, Ljava/util/List;->isEmpty()Z

    .line 57
    .line 58
    .line 59
    move-result v8

    .line 60
    if-nez v8, :cond_3

    .line 61
    .line 62
    iget-object v1, v7, Lyw0/c;->c:Ljava/util/List;

    .line 63
    .line 64
    iput-boolean v2, v7, Lyw0/c;->d:Z

    .line 65
    .line 66
    iput-object v1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 67
    .line 68
    iput-boolean v3, p0, Lyw0/d;->c:Z

    .line 69
    .line 70
    iget-object v1, v7, Lyw0/c;->a:Lj51/i;

    .line 71
    .line 72
    iput-object v1, p0, Lyw0/d;->d:Lj51/i;

    .line 73
    .line 74
    goto :goto_7

    .line 75
    :cond_3
    :goto_2
    if-eq v6, v1, :cond_4

    .line 76
    .line 77
    add-int/lit8 v6, v6, 0x1

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_4
    new-instance v1, Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 83
    .line 84
    .line 85
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 86
    .line 87
    .line 88
    move-result v6

    .line 89
    if-ltz v6, :cond_8

    .line 90
    .line 91
    move v7, v3

    .line 92
    :goto_3
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    instance-of v9, v8, Lyw0/c;

    .line 97
    .line 98
    if-eqz v9, :cond_5

    .line 99
    .line 100
    check-cast v8, Lyw0/c;

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_5
    move-object v8, v4

    .line 104
    :goto_4
    if-nez v8, :cond_6

    .line 105
    .line 106
    goto :goto_6

    .line 107
    :cond_6
    iget-object v8, v8, Lyw0/c;->c:Ljava/util/List;

    .line 108
    .line 109
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 110
    .line 111
    .line 112
    move-result v9

    .line 113
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 114
    .line 115
    .line 116
    move-result v10

    .line 117
    add-int/2addr v10, v9

    .line 118
    invoke-virtual {v1, v10}, Ljava/util/ArrayList;->ensureCapacity(I)V

    .line 119
    .line 120
    .line 121
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 122
    .line 123
    .line 124
    move-result v9

    .line 125
    move v10, v3

    .line 126
    :goto_5
    if-ge v10, v9, :cond_7

    .line 127
    .line 128
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v11

    .line 132
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    add-int/lit8 v10, v10, 0x1

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_7
    :goto_6
    if-eq v7, v6, :cond_8

    .line 139
    .line 140
    add-int/lit8 v7, v7, 0x1

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_8
    iput-object v1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 144
    .line 145
    iput-boolean v3, p0, Lyw0/d;->c:Z

    .line 146
    .line 147
    iput-object v4, p0, Lyw0/d;->d:Lj51/i;

    .line 148
    .line 149
    :cond_9
    :goto_7
    iput-boolean v2, p0, Lyw0/d;->c:Z

    .line 150
    .line 151
    iget-object v1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v1, Ljava/util/List;

    .line 154
    .line 155
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p0}, Lyw0/d;->d()Z

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    const-string v2, "context"

    .line 163
    .line 164
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    const-string v2, "subject"

    .line 168
    .line 169
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    const-string v2, "coroutineContext"

    .line 173
    .line 174
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    sget-boolean v2, Lyw0/f;->a:Z

    .line 178
    .line 179
    if-nez v2, :cond_b

    .line 180
    .line 181
    if-eqz p0, :cond_a

    .line 182
    .line 183
    goto :goto_8

    .line 184
    :cond_a
    new-instance p0, Lyw0/l;

    .line 185
    .line 186
    invoke-direct {p0, p2, p1, v1}, Lyw0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/List;)V

    .line 187
    .line 188
    .line 189
    goto :goto_9

    .line 190
    :cond_b
    :goto_8
    new-instance p0, Lyw0/b;

    .line 191
    .line 192
    invoke-direct {p0, p1, v1, p2, v0}, Lyw0/b;-><init>(Ljava/lang/Object;Ljava/util/List;Ljava/lang/Object;Lpx0/g;)V

    .line 193
    .line 194
    .line 195
    :goto_9
    invoke-virtual {p0, p2, p3}, Lyw0/e;->a(Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    return-object p0
.end method

.method public final b(Lj51/i;)Lyw0/c;
    .locals 4

    .line 1
    iget-object p0, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-ge v1, v0, :cond_2

    .line 9
    .line 10
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-ne v2, p1, :cond_0

    .line 15
    .line 16
    new-instance v0, Lyw0/c;

    .line 17
    .line 18
    sget-object v2, Lyw0/i;->a:Lyw0/i;

    .line 19
    .line 20
    invoke-direct {v0, p1, v2}, Lyw0/c;-><init>(Lj51/i;Lcp0/r;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v1, v0}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_0
    instance-of v3, v2, Lyw0/c;

    .line 28
    .line 29
    if-eqz v3, :cond_1

    .line 30
    .line 31
    check-cast v2, Lyw0/c;

    .line 32
    .line 33
    iget-object v3, v2, Lyw0/c;->a:Lj51/i;

    .line 34
    .line 35
    if-ne v3, p1, :cond_1

    .line 36
    .line 37
    return-object v2

    .line 38
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    const/4 p0, 0x0

    .line 42
    return-object p0
.end method

.method public final c(Lj51/i;)I
    .locals 4

    .line 1
    iget-object p0, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-ge v1, v0, :cond_2

    .line 9
    .line 10
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-eq v2, p1, :cond_1

    .line 15
    .line 16
    instance-of v3, v2, Lyw0/c;

    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    check-cast v2, Lyw0/c;

    .line 21
    .line 22
    iget-object v2, v2, Lyw0/c;->a:Lj51/i;

    .line 23
    .line 24
    if-ne v2, p1, :cond_0

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    :goto_1
    return v1

    .line 31
    :cond_2
    const/4 p0, -0x1

    .line 32
    return p0
.end method

.method public abstract d()Z
.end method

.method public final e(Lj51/i;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    :goto_0
    if-ge v2, v0, :cond_2

    .line 10
    .line 11
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    if-eq v3, p1, :cond_1

    .line 16
    .line 17
    instance-of v4, v3, Lyw0/c;

    .line 18
    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    check-cast v3, Lyw0/c;

    .line 22
    .line 23
    iget-object v3, v3, Lyw0/c;->a:Lj51/i;

    .line 24
    .line 25
    if-ne v3, p1, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    :goto_1
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_2
    return v1
.end method

.method public final f(Lj51/i;Lay0/o;)V
    .locals 5

    .line 1
    const-string v0, "phase"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Lyw0/d;->b(Lj51/i;)Lyw0/c;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_7

    .line 11
    .line 12
    iget-object v1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Ljava/util/List;

    .line 15
    .line 16
    iget-object v2, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/4 v3, 0x0

    .line 23
    if-nez v2, :cond_5

    .line 24
    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    iget-boolean v2, p0, Lyw0/d;->c:Z

    .line 29
    .line 30
    if-nez v2, :cond_5

    .line 31
    .line 32
    instance-of v2, v1, Ljava/util/List;

    .line 33
    .line 34
    if-eqz v2, :cond_5

    .line 35
    .line 36
    instance-of v2, v1, Lby0/a;

    .line 37
    .line 38
    if-eqz v2, :cond_1

    .line 39
    .line 40
    instance-of v2, v1, Lby0/c;

    .line 41
    .line 42
    if-eqz v2, :cond_5

    .line 43
    .line 44
    :cond_1
    iget-object v2, p0, Lyw0/d;->d:Lj51/i;

    .line 45
    .line 46
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    if-eqz v2, :cond_2

    .line 51
    .line 52
    invoke-interface {v1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    iget-object v2, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 57
    .line 58
    invoke-static {v2}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-nez v2, :cond_3

    .line 67
    .line 68
    invoke-virtual {p0, p1}, Lyw0/d;->c(Lj51/i;)I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    iget-object v4, p0, Lyw0/d;->a:Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-static {v4}, Ljp/k1;->h(Ljava/util/List;)I

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    if-ne v2, v4, :cond_5

    .line 79
    .line 80
    :cond_3
    invoke-virtual {p0, p1}, Lyw0/d;->b(Lj51/i;)Lyw0/c;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-boolean v0, p1, Lyw0/c;->d:Z

    .line 88
    .line 89
    if-eqz v0, :cond_4

    .line 90
    .line 91
    iget-object v0, p1, Lyw0/c;->c:Ljava/util/List;

    .line 92
    .line 93
    check-cast v0, Ljava/util/Collection;

    .line 94
    .line 95
    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    iput-object v0, p1, Lyw0/c;->c:Ljava/util/List;

    .line 100
    .line 101
    iput-boolean v3, p1, Lyw0/c;->d:Z

    .line 102
    .line 103
    :cond_4
    iget-object p1, p1, Lyw0/c;->c:Ljava/util/List;

    .line 104
    .line 105
    invoke-interface {p1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    invoke-interface {v1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    :goto_0
    iget p1, p0, Lyw0/d;->b:I

    .line 112
    .line 113
    add-int/lit8 p1, p1, 0x1

    .line 114
    .line 115
    iput p1, p0, Lyw0/d;->b:I

    .line 116
    .line 117
    return-void

    .line 118
    :cond_5
    :goto_1
    iget-boolean p1, v0, Lyw0/c;->d:Z

    .line 119
    .line 120
    if-eqz p1, :cond_6

    .line 121
    .line 122
    iget-object p1, v0, Lyw0/c;->c:Ljava/util/List;

    .line 123
    .line 124
    check-cast p1, Ljava/util/Collection;

    .line 125
    .line 126
    invoke-static {p1}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    iput-object p1, v0, Lyw0/c;->c:Ljava/util/List;

    .line 131
    .line 132
    iput-boolean v3, v0, Lyw0/c;->d:Z

    .line 133
    .line 134
    :cond_6
    iget-object p1, v0, Lyw0/c;->c:Ljava/util/List;

    .line 135
    .line 136
    invoke-interface {p1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    iget p1, p0, Lyw0/d;->b:I

    .line 140
    .line 141
    add-int/lit8 p1, p1, 0x1

    .line 142
    .line 143
    iput p1, p0, Lyw0/d;->b:I

    .line 144
    .line 145
    const/4 p1, 0x0

    .line 146
    iput-object p1, p0, Lyw0/d;->interceptors$delegate:Ljava/lang/Object;

    .line 147
    .line 148
    iput-boolean v3, p0, Lyw0/d;->c:Z

    .line 149
    .line 150
    iput-object p1, p0, Lyw0/d;->d:Lj51/i;

    .line 151
    .line 152
    return-void

    .line 153
    :cond_7
    new-instance p0, Lt11/a;

    .line 154
    .line 155
    new-instance p2, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    const-string v0, "Phase "

    .line 158
    .line 159
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    const-string p1, " was not registered for this pipeline"

    .line 166
    .line 167
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    invoke-direct {p0, p1}, Lt11/a;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw p0
.end method
