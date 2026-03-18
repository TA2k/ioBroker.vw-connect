.class public final Lsy0/d;
.super Lmx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Lsy0/c;

.field public e:Luy0/b;

.field public f:Lsy0/j;

.field public g:Ljava/lang/Object;

.field public h:I

.field public i:I


# direct methods
.method public constructor <init>(Lsy0/c;)V
    .locals 1

    .line 1
    const-string v0, "map"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/util/AbstractMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lsy0/d;->d:Lsy0/c;

    .line 10
    .line 11
    new-instance v0, Luy0/b;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lsy0/d;->e:Luy0/b;

    .line 17
    .line 18
    iget-object v0, p1, Lsy0/c;->d:Lsy0/j;

    .line 19
    .line 20
    iput-object v0, p0, Lsy0/d;->f:Lsy0/j;

    .line 21
    .line 22
    invoke-virtual {p1}, Lsy0/c;->c()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    iput p1, p0, Lsy0/d;->i:I

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lsy0/f;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p0}, Lsy0/f;-><init>(ILsy0/d;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final b()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lsy0/f;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1, p0}, Lsy0/f;-><init>(ILsy0/d;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lsy0/d;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final clear()V
    .locals 2

    .line 1
    const-string v0, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>"

    .line 2
    .line 3
    sget-object v1, Lsy0/j;->e:Lsy0/j;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v1}, Lsy0/d;->e(Lsy0/j;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p0, v0}, Lsy0/d;->f(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lsy0/d;->f:Lsy0/j;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v1, v0

    .line 12
    :goto_0
    invoke-virtual {p0, v1, p1, v0}, Lsy0/j;->d(ILjava/lang/Object;I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final d()Ljava/util/Collection;
    .locals 2

    .line 1
    new-instance v0, Lnx0/h;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p0, v1}, Lnx0/h;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final e(Lsy0/j;)V
    .locals 1

    .line 1
    const-string v0, "value"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lsy0/d;->f:Lsy0/j;

    .line 7
    .line 8
    if-eq p1, v0, :cond_0

    .line 9
    .line 10
    iput-object p1, p0, Lsy0/d;->f:Lsy0/j;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iput-object p1, p0, Lsy0/d;->d:Lsy0/c;

    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ljava/util/Map;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    invoke-virtual {p0}, Lsy0/d;->c()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    move-object v3, p1

    .line 16
    check-cast v3, Ljava/util/Map;

    .line 17
    .line 18
    invoke-interface {v3}, Ljava/util/Map;->size()I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    if-eq v1, v4, :cond_2

    .line 23
    .line 24
    return v2

    .line 25
    :cond_2
    instance-of v1, v3, Lsy0/c;

    .line 26
    .line 27
    if-eqz v1, :cond_3

    .line 28
    .line 29
    iget-object p0, p0, Lsy0/d;->f:Lsy0/j;

    .line 30
    .line 31
    check-cast p1, Lsy0/c;

    .line 32
    .line 33
    iget-object p1, p1, Lsy0/c;->d:Lsy0/j;

    .line 34
    .line 35
    sget-object v0, Lsy0/b;->g:Lsy0/b;

    .line 36
    .line 37
    invoke-virtual {p0, p1, v0}, Lsy0/j;->g(Lsy0/j;Lay0/n;)Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0

    .line 42
    :cond_3
    instance-of v1, v3, Lsy0/d;

    .line 43
    .line 44
    if-eqz v1, :cond_4

    .line 45
    .line 46
    iget-object p0, p0, Lsy0/d;->f:Lsy0/j;

    .line 47
    .line 48
    check-cast p1, Lsy0/d;

    .line 49
    .line 50
    iget-object p1, p1, Lsy0/d;->f:Lsy0/j;

    .line 51
    .line 52
    sget-object v0, Lsy0/b;->h:Lsy0/b;

    .line 53
    .line 54
    invoke-virtual {p0, p1, v0}, Lsy0/j;->g(Lsy0/j;Lay0/n;)Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    return p0

    .line 59
    :cond_4
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    invoke-interface {v3}, Ljava/util/Map;->size()I

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-ne p1, v1, :cond_a

    .line 68
    .line 69
    invoke-interface {v3}, Ljava/util/Map;->isEmpty()Z

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    if-eqz p1, :cond_5

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_5
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    :cond_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_9

    .line 89
    .line 90
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, Ljava/util/Map$Entry;

    .line 95
    .line 96
    const-string v3, "element"

    .line 97
    .line 98
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-interface {p0, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    if-eqz v3, :cond_7

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    invoke-virtual {v3, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    goto :goto_0

    .line 120
    :cond_7
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    if-nez v3, :cond_8

    .line 125
    .line 126
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-interface {p0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_8

    .line 135
    .line 136
    move v1, v0

    .line 137
    goto :goto_0

    .line 138
    :cond_8
    move v1, v2

    .line 139
    :goto_0
    if-nez v1, :cond_6

    .line 140
    .line 141
    return v2

    .line 142
    :cond_9
    :goto_1
    return v0

    .line 143
    :cond_a
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 144
    .line 145
    const-string p1, "Failed requirement."

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0
.end method

.method public final f(I)V
    .locals 0

    .line 1
    iput p1, p0, Lsy0/d;->i:I

    .line 2
    .line 3
    iget p1, p0, Lsy0/d;->h:I

    .line 4
    .line 5
    add-int/lit8 p1, p1, 0x1

    .line 6
    .line 7
    iput p1, p0, Lsy0/d;->h:I

    .line 8
    .line 9
    return-void
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lsy0/d;->f:Lsy0/j;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v1, v0

    .line 12
    :goto_0
    invoke-virtual {p0, v1, p1, v0}, Lsy0/j;->h(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lsy0/d;->g:Ljava/lang/Object;

    .line 3
    .line 4
    iget-object v1, p0, Lsy0/d;->f:Lsy0/j;

    .line 5
    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    move v2, v0

    .line 13
    goto :goto_1

    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    goto :goto_0

    .line 16
    :goto_1
    const/4 v5, 0x0

    .line 17
    move-object v6, p0

    .line 18
    move-object v3, p1

    .line 19
    move-object v4, p2

    .line 20
    invoke-virtual/range {v1 .. v6}, Lsy0/j;->m(ILjava/lang/Object;Ljava/lang/Object;ILsy0/d;)Lsy0/j;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v6, p0}, Lsy0/d;->e(Lsy0/j;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, v6, Lsy0/d;->g:Ljava/lang/Object;

    .line 28
    .line 29
    return-object p0
.end method

.method public final putAll(Ljava/util/Map;)V
    .locals 6

    .line 1
    const-string v0, "from"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    goto :goto_3

    .line 13
    :cond_0
    instance-of v0, p1, Lsy0/c;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lsy0/c;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move-object v0, v1

    .line 23
    :goto_0
    if-nez v0, :cond_3

    .line 24
    .line 25
    instance-of v0, p1, Lsy0/d;

    .line 26
    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    move-object v0, p1

    .line 30
    check-cast v0, Lsy0/d;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_2
    move-object v0, v1

    .line 34
    :goto_1
    if-eqz v0, :cond_4

    .line 35
    .line 36
    iget-object v1, v0, Lsy0/d;->d:Lsy0/c;

    .line 37
    .line 38
    if-nez v1, :cond_4

    .line 39
    .line 40
    new-instance v1, Lsy0/c;

    .line 41
    .line 42
    iget-object v2, v0, Lsy0/d;->f:Lsy0/j;

    .line 43
    .line 44
    invoke-virtual {v0}, Lsy0/d;->c()I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    invoke-direct {v1, v2, v3}, Lsy0/c;-><init>(Lsy0/j;I)V

    .line 49
    .line 50
    .line 51
    iput-object v1, v0, Lsy0/d;->d:Lsy0/c;

    .line 52
    .line 53
    new-instance v2, Luy0/b;

    .line 54
    .line 55
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    iput-object v2, v0, Lsy0/d;->e:Luy0/b;

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    move-object v1, v0

    .line 62
    :cond_4
    :goto_2
    if-eqz v1, :cond_6

    .line 63
    .line 64
    new-instance p1, Luy0/a;

    .line 65
    .line 66
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 67
    .line 68
    .line 69
    const/4 v0, 0x0

    .line 70
    iput v0, p1, Luy0/a;->a:I

    .line 71
    .line 72
    iget v2, p0, Lsy0/d;->i:I

    .line 73
    .line 74
    iget-object v3, p0, Lsy0/d;->f:Lsy0/j;

    .line 75
    .line 76
    iget-object v4, v1, Lsy0/c;->d:Lsy0/j;

    .line 77
    .line 78
    const-string v5, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>"

    .line 79
    .line 80
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v3, v4, v0, p1, p0}, Lsy0/j;->n(Lsy0/j;ILuy0/a;Lsy0/d;)Lsy0/j;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-virtual {p0, v0}, Lsy0/d;->e(Lsy0/j;)V

    .line 88
    .line 89
    .line 90
    iget v0, v1, Lsy0/c;->e:I

    .line 91
    .line 92
    add-int/2addr v0, v2

    .line 93
    iget p1, p1, Luy0/a;->a:I

    .line 94
    .line 95
    sub-int/2addr v0, p1

    .line 96
    if-eq v2, v0, :cond_5

    .line 97
    .line 98
    invoke-virtual {p0, v0}, Lsy0/d;->f(I)V

    .line 99
    .line 100
    .line 101
    :cond_5
    :goto_3
    return-void

    .line 102
    :cond_6
    invoke-super {p0, p1}, Ljava/util/AbstractMap;->putAll(Ljava/util/Map;)V

    .line 103
    .line 104
    .line 105
    return-void
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    const/4 v0, 0x0

    .line 4
    iput-object v0, p0, Lsy0/d;->g:Ljava/lang/Object;

    .line 5
    iget-object v0, p0, Lsy0/d;->f:Lsy0/j;

    const/4 v1, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result v2

    goto :goto_0

    :cond_0
    move v2, v1

    :goto_0
    invoke-virtual {v0, v2, p1, v1, p0}, Lsy0/j;->o(ILjava/lang/Object;ILsy0/d;)Lsy0/j;

    move-result-object p1

    if-nez p1, :cond_1

    const-string p1, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>"

    sget-object v0, Lsy0/j;->e:Lsy0/j;

    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    move-object p1, v0

    :cond_1
    invoke-virtual {p0, p1}, Lsy0/d;->e(Lsy0/j;)V

    .line 6
    iget-object p0, p0, Lsy0/d;->g:Ljava/lang/Object;

    return-object p0
.end method

.method public final remove(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 8

    .line 1
    invoke-virtual {p0}, Lsy0/d;->c()I

    move-result v0

    .line 2
    iget-object v1, p0, Lsy0/d;->f:Lsy0/j;

    const/4 v7, 0x0

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result v2

    goto :goto_0

    :cond_0
    move v2, v7

    :goto_0
    const/4 v5, 0x0

    move-object v6, p0

    move-object v3, p1

    move-object v4, p2

    invoke-virtual/range {v1 .. v6}, Lsy0/j;->p(ILjava/lang/Object;Ljava/lang/Object;ILsy0/d;)Lsy0/j;

    move-result-object p0

    if-nez p0, :cond_1

    const-string p0, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>"

    sget-object p1, Lsy0/j;->e:Lsy0/j;

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    move-object p0, p1

    :cond_1
    invoke-virtual {v6, p0}, Lsy0/d;->e(Lsy0/j;)V

    .line 3
    invoke-virtual {v6}, Lsy0/d;->c()I

    move-result p0

    if-eq v0, p0, :cond_2

    const/4 p0, 0x1

    return p0

    :cond_2
    return v7
.end method
