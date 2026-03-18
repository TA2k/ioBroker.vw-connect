.class public final Lt2/f;
.super Lmx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Ls2/b;

.field public e:Lq2/i;

.field public f:Ljava/lang/Object;

.field public g:I

.field public h:I

.field public i:Lt2/g;


# direct methods
.method public constructor <init>(Lt2/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractMap;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ls2/b;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lt2/f;->d:Ls2/b;

    .line 10
    .line 11
    iget-object v0, p1, Lq2/b;->d:Lq2/i;

    .line 12
    .line 13
    iput-object v0, p0, Lt2/f;->e:Lq2/i;

    .line 14
    .line 15
    iget v0, p1, Lq2/b;->e:I

    .line 16
    .line 17
    iput v0, p0, Lt2/f;->h:I

    .line 18
    .line 19
    iput-object p1, p0, Lt2/f;->i:Lt2/g;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lq2/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p0}, Lq2/e;-><init>(ILt2/f;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final b()Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Lq2/e;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1, p0}, Lq2/e;-><init>(ILt2/f;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lt2/f;->h:I

    .line 2
    .line 3
    return p0
.end method

.method public final clear()V
    .locals 1

    .line 1
    sget-object v0, Lq2/i;->e:Lq2/i;

    .line 2
    .line 3
    iput-object v0, p0, Lt2/f;->e:Lq2/i;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lt2/f;->i(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final bridge containsKey(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/s1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Ll2/s1;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lt2/f;->f(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final bridge containsValue(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/w2;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Ll2/w2;

    .line 8
    .line 9
    invoke-super {p0, p1}, Ljava/util/AbstractMap;->containsValue(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final d()Ljava/util/Collection;
    .locals 2

    .line 1
    new-instance v0, Lnx0/h;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p0, v1}, Lnx0/h;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final e()Lt2/g;
    .locals 3

    .line 1
    iget-object v0, p0, Lt2/f;->e:Lq2/i;

    .line 2
    .line 3
    iget-object v1, p0, Lt2/f;->i:Lt2/g;

    .line 4
    .line 5
    iget-object v2, v1, Lq2/b;->d:Lq2/i;

    .line 6
    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance v0, Ls2/b;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lt2/f;->d:Ls2/b;

    .line 16
    .line 17
    new-instance v1, Lt2/g;

    .line 18
    .line 19
    iget-object v0, p0, Lt2/f;->e:Lq2/i;

    .line 20
    .line 21
    invoke-virtual {p0}, Lt2/f;->c()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    invoke-direct {v1, v0, v2}, Lq2/b;-><init>(Lq2/i;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iput-object v1, p0, Lt2/f;->i:Lt2/g;

    .line 29
    .line 30
    return-object v1
.end method

.method public final f(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lt2/f;->e:Lq2/i;

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
    invoke-virtual {p0, v1, p1, v0}, Lq2/i;->d(ILjava/lang/Object;I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object p0, p0, Lt2/f;->e:Lq2/i;

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
    invoke-virtual {p0, v1, p1, v0}, Lq2/i;->g(ILjava/lang/Object;I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public final bridge get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/s1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    check-cast p1, Ll2/s1;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lt2/f;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ll2/w2;

    .line 14
    .line 15
    return-object p0
.end method

.method public final bridge getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    instance-of v0, p1, Ll2/s1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-object p2

    .line 6
    :cond_0
    check-cast p1, Ll2/s1;

    .line 7
    .line 8
    check-cast p2, Ll2/w2;

    .line 9
    .line 10
    invoke-super {p0, p1, p2}, Ljava/util/AbstractMap;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ll2/w2;

    .line 15
    .line 16
    return-object p0
.end method

.method public final h(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lt2/f;->f:Ljava/lang/Object;

    .line 3
    .line 4
    iget-object v0, p0, Lt2/f;->e:Lq2/i;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v2, v1

    .line 15
    :goto_0
    invoke-virtual {v0, v2, p1, v1, p0}, Lq2/i;->n(ILjava/lang/Object;ILt2/f;)Lq2/i;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    sget-object p1, Lq2/i;->e:Lq2/i;

    .line 22
    .line 23
    :cond_1
    iput-object p1, p0, Lt2/f;->e:Lq2/i;

    .line 24
    .line 25
    iget-object p0, p0, Lt2/f;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object p0
.end method

.method public final i(I)V
    .locals 0

    .line 1
    iput p1, p0, Lt2/f;->h:I

    .line 2
    .line 3
    iget p1, p0, Lt2/f;->g:I

    .line 4
    .line 5
    add-int/lit8 p1, p1, 0x1

    .line 6
    .line 7
    iput p1, p0, Lt2/f;->g:I

    .line 8
    .line 9
    return-void
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lt2/f;->f:Ljava/lang/Object;

    .line 3
    .line 4
    iget-object v1, p0, Lt2/f;->e:Lq2/i;

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
    invoke-virtual/range {v1 .. v6}, Lq2/i;->l(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    iput-object p0, v6, Lt2/f;->e:Lq2/i;

    .line 25
    .line 26
    iget-object p0, v6, Lt2/f;->f:Ljava/lang/Object;

    .line 27
    .line 28
    return-object p0
.end method

.method public final putAll(Ljava/util/Map;)V
    .locals 6

    .line 1
    instance-of v0, p1, Lq2/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object v0, p1

    .line 7
    check-cast v0, Lq2/b;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move-object v0, v1

    .line 11
    :goto_0
    if-nez v0, :cond_2

    .line 12
    .line 13
    instance-of v0, p1, Lt2/f;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    move-object v0, p1

    .line 18
    check-cast v0, Lt2/f;

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object v0, v1

    .line 22
    :goto_1
    if-eqz v0, :cond_3

    .line 23
    .line 24
    invoke-virtual {v0}, Lt2/f;->e()Lt2/g;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move-object v1, v0

    .line 30
    :cond_3
    :goto_2
    if-eqz v1, :cond_5

    .line 31
    .line 32
    new-instance p1, Ls2/a;

    .line 33
    .line 34
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 35
    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    iput v0, p1, Ls2/a;->a:I

    .line 39
    .line 40
    iget v2, p0, Lt2/f;->h:I

    .line 41
    .line 42
    iget-object v3, p0, Lt2/f;->e:Lq2/i;

    .line 43
    .line 44
    iget-object v4, v1, Lq2/b;->d:Lq2/i;

    .line 45
    .line 46
    const-string v5, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder, V of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.PersistentHashMapBuilder>"

    .line 47
    .line 48
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v3, v4, v0, p1, p0}, Lq2/i;->m(Lq2/i;ILs2/a;Lt2/f;)Lq2/i;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iput-object v0, p0, Lt2/f;->e:Lq2/i;

    .line 56
    .line 57
    iget v0, v1, Lq2/b;->e:I

    .line 58
    .line 59
    add-int/2addr v0, v2

    .line 60
    iget p1, p1, Ls2/a;->a:I

    .line 61
    .line 62
    sub-int/2addr v0, p1

    .line 63
    if-eq v2, v0, :cond_4

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lt2/f;->i(I)V

    .line 66
    .line 67
    .line 68
    :cond_4
    return-void

    .line 69
    :cond_5
    invoke-super {p0, p1}, Ljava/util/AbstractMap;->putAll(Ljava/util/Map;)V

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final bridge remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 4
    instance-of v0, p1, Ll2/s1;

    if-nez v0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    check-cast p1, Ll2/s1;

    .line 5
    invoke-virtual {p0, p1}, Lt2/f;->h(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ll2/w2;

    return-object p0
.end method

.method public final remove(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 8

    .line 1
    invoke-virtual {p0}, Lt2/f;->c()I

    move-result v0

    .line 2
    iget-object v1, p0, Lt2/f;->e:Lq2/i;

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

    invoke-virtual/range {v1 .. v6}, Lq2/i;->o(ILjava/lang/Object;Ljava/lang/Object;ILt2/f;)Lq2/i;

    move-result-object p0

    if-nez p0, :cond_1

    sget-object p0, Lq2/i;->e:Lq2/i;

    :cond_1
    iput-object p0, v6, Lt2/f;->e:Lq2/i;

    .line 3
    invoke-virtual {v6}, Lt2/f;->c()I

    move-result p0

    if-eq v0, p0, :cond_2

    const/4 p0, 0x1

    return p0

    :cond_2
    return v7
.end method
