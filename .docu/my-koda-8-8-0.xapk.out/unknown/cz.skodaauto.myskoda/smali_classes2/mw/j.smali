.class public final Lmw/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Ljava/util/ArrayList;

.field public final c:I

.field public final d:D

.field public final e:D

.field public final f:D

.field public final g:D

.field public final h:Lrw/b;


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 12

    .line 1
    const-string v0, "series"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lrw/b;->b:Lrw/b;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    move-object v1, p1

    .line 12
    check-cast v1, Ljava/util/Collection;

    .line 13
    .line 14
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_4

    .line 19
    .line 20
    check-cast p1, Ljava/lang/Iterable;

    .line 21
    .line 22
    new-instance v1, Ljava/util/ArrayList;

    .line 23
    .line 24
    const/16 v2, 0xa

    .line 25
    .line 26
    invoke-static {p1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Ljava/util/List;

    .line 48
    .line 49
    move-object v3, v2

    .line 50
    check-cast v3, Ljava/util/Collection;

    .line 51
    .line 52
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-nez v3, :cond_0

    .line 57
    .line 58
    check-cast v2, Ljava/lang/Iterable;

    .line 59
    .line 60
    new-instance v3, La5/f;

    .line 61
    .line 62
    const/16 v4, 0x19

    .line 63
    .line 64
    invoke-direct {v3, v4}, La5/f;-><init>(I)V

    .line 65
    .line 66
    .line 67
    invoke-static {v2, v3}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 76
    .line 77
    const-string p1, "Series can\u2019t be empty."

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :cond_1
    iput-object v1, p0, Lmw/j;->b:Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-static {v1}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p0, Lmw/j;->a:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v1

    .line 99
    check-cast v1, Ljava/util/List;

    .line 100
    .line 101
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Lmw/i;

    .line 106
    .line 107
    iget-wide v2, v2, Lmw/i;->a:D

    .line 108
    .line 109
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    check-cast v1, Lmw/i;

    .line 114
    .line 115
    iget-wide v4, v1, Lmw/i;->a:D

    .line 116
    .line 117
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-eqz v1, :cond_2

    .line 122
    .line 123
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    check-cast v1, Ljava/util/List;

    .line 128
    .line 129
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    check-cast v6, Lmw/i;

    .line 134
    .line 135
    iget-wide v6, v6, Lmw/i;->a:D

    .line 136
    .line 137
    invoke-static {v1}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    check-cast v1, Lmw/i;

    .line 142
    .line 143
    iget-wide v8, v1, Lmw/i;->a:D

    .line 144
    .line 145
    invoke-static {v2, v3, v6, v7}, Ljava/lang/Math;->min(DD)D

    .line 146
    .line 147
    .line 148
    move-result-wide v2

    .line 149
    invoke-static {v4, v5, v8, v9}, Ljava/lang/Math;->max(DD)D

    .line 150
    .line 151
    .line 152
    move-result-wide v4

    .line 153
    goto :goto_1

    .line 154
    :cond_2
    iget-object p1, p0, Lmw/j;->a:Ljava/util/ArrayList;

    .line 155
    .line 156
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    check-cast v1, Lmw/i;

    .line 165
    .line 166
    iget-wide v6, v1, Lmw/i;->b:D

    .line 167
    .line 168
    move-wide v8, v6

    .line 169
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    if-eqz v1, :cond_3

    .line 174
    .line 175
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    check-cast v1, Lmw/i;

    .line 180
    .line 181
    iget-wide v10, v1, Lmw/i;->b:D

    .line 182
    .line 183
    invoke-static {v6, v7, v10, v11}, Ljava/lang/Math;->min(DD)D

    .line 184
    .line 185
    .line 186
    move-result-wide v6

    .line 187
    invoke-static {v8, v9, v10, v11}, Ljava/lang/Math;->max(DD)D

    .line 188
    .line 189
    .line 190
    move-result-wide v8

    .line 191
    goto :goto_2

    .line 192
    :cond_3
    iget-object p1, p0, Lmw/j;->b:Ljava/util/ArrayList;

    .line 193
    .line 194
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 195
    .line 196
    .line 197
    move-result p1

    .line 198
    iput p1, p0, Lmw/j;->c:I

    .line 199
    .line 200
    iput-wide v2, p0, Lmw/j;->d:D

    .line 201
    .line 202
    iput-wide v4, p0, Lmw/j;->e:D

    .line 203
    .line 204
    iput-wide v6, p0, Lmw/j;->f:D

    .line 205
    .line 206
    iput-wide v8, p0, Lmw/j;->g:D

    .line 207
    .line 208
    iput-object v0, p0, Lmw/j;->h:Lrw/b;

    .line 209
    .line 210
    return-void

    .line 211
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 212
    .line 213
    const-string p1, "At least one series should be added."

    .line 214
    .line 215
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lmw/j;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lmw/j;

    .line 8
    .line 9
    iget-object v0, p1, Lmw/j;->b:Ljava/util/ArrayList;

    .line 10
    .line 11
    iget-object v1, p0, Lmw/j;->b:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget v0, p0, Lmw/j;->c:I

    .line 20
    .line 21
    iget v1, p1, Lmw/j;->c:I

    .line 22
    .line 23
    if-ne v0, v1, :cond_0

    .line 24
    .line 25
    iget-wide v0, p0, Lmw/j;->d:D

    .line 26
    .line 27
    iget-wide v2, p1, Lmw/j;->d:D

    .line 28
    .line 29
    cmpg-double v0, v0, v2

    .line 30
    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    iget-wide v0, p0, Lmw/j;->e:D

    .line 34
    .line 35
    iget-wide v2, p1, Lmw/j;->e:D

    .line 36
    .line 37
    cmpg-double v0, v0, v2

    .line 38
    .line 39
    if-nez v0, :cond_0

    .line 40
    .line 41
    iget-wide v0, p0, Lmw/j;->f:D

    .line 42
    .line 43
    iget-wide v2, p1, Lmw/j;->f:D

    .line 44
    .line 45
    cmpg-double v0, v0, v2

    .line 46
    .line 47
    if-nez v0, :cond_0

    .line 48
    .line 49
    iget-wide v0, p0, Lmw/j;->g:D

    .line 50
    .line 51
    iget-wide v2, p1, Lmw/j;->g:D

    .line 52
    .line 53
    cmpg-double v0, v0, v2

    .line 54
    .line 55
    if-nez v0, :cond_0

    .line 56
    .line 57
    iget-object p0, p0, Lmw/j;->h:Lrw/b;

    .line 58
    .line 59
    iget-object p1, p1, Lmw/j;->h:Lrw/b;

    .line 60
    .line 61
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_0

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    const/4 p0, 0x0

    .line 69
    return p0

    .line 70
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 71
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lmw/j;->b:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Lmw/j;->c:I

    .line 11
    .line 12
    add-int/2addr v0, v2

    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-wide v2, p0, Lmw/j;->d:D

    .line 15
    .line 16
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-wide v2, p0, Lmw/j;->e:D

    .line 21
    .line 22
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-wide v2, p0, Lmw/j;->f:D

    .line 27
    .line 28
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-wide v2, p0, Lmw/j;->g:D

    .line 33
    .line 34
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget-object p0, p0, Lmw/j;->h:Lrw/b;

    .line 39
    .line 40
    iget-object p0, p0, Lrw/b;->a:Ljava/util/LinkedHashMap;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    add-int/2addr p0, v0

    .line 47
    return p0
.end method
