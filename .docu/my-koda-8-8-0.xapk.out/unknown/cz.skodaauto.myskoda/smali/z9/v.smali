.class public Lz9/v;
.super Lz9/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lby0/a;


# static fields
.field public static final synthetic j:I


# instance fields
.field public final i:Lca/m;


# direct methods
.method public constructor <init>(Lz9/x;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lz9/u;-><init>(Lz9/j0;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Lca/m;

    .line 5
    .line 6
    invoke-direct {p1, p0}, Lca/m;-><init>(Lz9/v;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lz9/v;->i:Lca/m;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    if-eqz p1, :cond_4

    .line 5
    .line 6
    instance-of v0, p1, Lz9/v;

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_1
    invoke-super {p0, p1}, Lz9/u;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_4

    .line 16
    .line 17
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 18
    .line 19
    iget-object v0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Landroidx/collection/b1;

    .line 22
    .line 23
    invoke-virtual {v0}, Landroidx/collection/b1;->f()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    check-cast p1, Lz9/v;

    .line 28
    .line 29
    iget-object p1, p1, Lz9/v;->i:Lca/m;

    .line 30
    .line 31
    iget-object v1, p1, Lca/m;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v1, Landroidx/collection/b1;

    .line 34
    .line 35
    invoke-virtual {v1}, Landroidx/collection/b1;->f()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-ne v0, v1, :cond_4

    .line 40
    .line 41
    iget v0, p0, Lca/m;->d:I

    .line 42
    .line 43
    iget v1, p1, Lca/m;->d:I

    .line 44
    .line 45
    if-ne v0, v1, :cond_4

    .line 46
    .line 47
    iget-object p0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Landroidx/collection/b1;

    .line 50
    .line 51
    const-string v0, "<this>"

    .line 52
    .line 53
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    new-instance v0, Landroidx/collection/d1;

    .line 57
    .line 58
    const/4 v1, 0x0

    .line 59
    invoke-direct {v0, p0, v1}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    invoke-static {v0}, Lky0/l;->b(Ljava/util/Iterator;)Lky0/j;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lky0/a;

    .line 67
    .line 68
    invoke-virtual {p0}, Lky0/a;->iterator()Ljava/util/Iterator;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-eqz v0, :cond_3

    .line 77
    .line 78
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    check-cast v0, Lz9/u;

    .line 83
    .line 84
    iget-object v1, p1, Lca/m;->f:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v1, Landroidx/collection/b1;

    .line 87
    .line 88
    iget-object v2, v0, Lz9/u;->e:Lca/j;

    .line 89
    .line 90
    iget v2, v2, Lca/j;->a:I

    .line 91
    .line 92
    invoke-virtual {v1, v2}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-virtual {v0, v1}, Lz9/u;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-nez v0, :cond_2

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 104
    return p0

    .line 105
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 106
    return p0
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 2
    .line 3
    iget v0, p0, Lca/m;->d:I

    .line 4
    .line 5
    iget-object p0, p0, Lca/m;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/collection/b1;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/collection/b1;->f()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x0

    .line 14
    :goto_0
    if-ge v2, v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0, v2}, Landroidx/collection/b1;->d(I)I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-virtual {p0, v2}, Landroidx/collection/b1;->h(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Lz9/u;

    .line 25
    .line 26
    mul-int/lit8 v0, v0, 0x1f

    .line 27
    .line 28
    add-int/2addr v0, v3

    .line 29
    mul-int/lit8 v0, v0, 0x1f

    .line 30
    .line 31
    invoke-virtual {v4}, Lz9/u;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    add-int/2addr v0, v3

    .line 36
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v0, Lca/l;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lca/l;-><init>(Lca/m;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public final m(Lrn/i;)Lz9/t;
    .locals 3

    .line 1
    invoke-super {p0, p1}, Lz9/u;->m(Lrn/i;)Lz9/t;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Lca/m;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lz9/v;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {p0, v0, p1, v2, v1}, Lca/m;->k(Lz9/t;Lrn/i;ZLz9/u;)Lz9/t;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public final n(Lrn/i;Lz9/u;)Lz9/t;
    .locals 2

    .line 1
    invoke-super {p0, p1}, Lz9/u;->m(Lrn/i;)Lz9/t;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-virtual {p0, v0, p1, v1, p2}, Lca/m;->k(Lz9/t;Lrn/i;ZLz9/u;)Lz9/t;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final o(Ljava/lang/String;ZLz9/u;)Lz9/t;
    .locals 6

    .line 1
    const-string v0, "route"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lca/m;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lz9/v;

    .line 14
    .line 15
    iget-object v0, p0, Lz9/u;->e:Lca/j;

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Lca/j;->h(Ljava/lang/String;)Lz9/t;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lz9/v;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    :cond_0
    :goto_0
    move-object v3, v2

    .line 31
    check-cast v3, Lca/l;

    .line 32
    .line 33
    invoke-virtual {v3}, Lca/l;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    const/4 v5, 0x0

    .line 38
    if-eqz v4, :cond_3

    .line 39
    .line 40
    invoke-virtual {v3}, Lca/l;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    check-cast v3, Lz9/u;

    .line 45
    .line 46
    invoke-static {v3, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-eqz v4, :cond_1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    instance-of v4, v3, Lz9/v;

    .line 54
    .line 55
    if-eqz v4, :cond_2

    .line 56
    .line 57
    check-cast v3, Lz9/v;

    .line 58
    .line 59
    const/4 v4, 0x0

    .line 60
    invoke-virtual {v3, p1, v4, p0}, Lz9/v;->o(Ljava/lang/String;ZLz9/u;)Lz9/t;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    goto :goto_1

    .line 65
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    iget-object v3, v3, Lz9/u;->e:Lca/j;

    .line 69
    .line 70
    invoke-virtual {v3, p1}, Lca/j;->h(Ljava/lang/String;)Lz9/t;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    :goto_1
    if-eqz v5, :cond_0

    .line 75
    .line 76
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_3
    invoke-static {v1}, Lmx0/q;->V(Ljava/lang/Iterable;)Ljava/lang/Comparable;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    check-cast v1, Lz9/t;

    .line 85
    .line 86
    iget-object v2, p0, Lz9/u;->f:Lz9/v;

    .line 87
    .line 88
    if-eqz v2, :cond_4

    .line 89
    .line 90
    if-eqz p2, :cond_4

    .line 91
    .line 92
    invoke-virtual {v2, p3}, Lz9/v;->equals(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result p2

    .line 96
    if-nez p2, :cond_4

    .line 97
    .line 98
    const/4 p2, 0x1

    .line 99
    invoke-virtual {v2, p1, p2, p0}, Lz9/v;->o(Ljava/lang/String;ZLz9/u;)Lz9/t;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    :cond_4
    filled-new-array {v0, v1, v5}, [Lz9/t;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-static {p0}, Lmx0/q;->V(Ljava/lang/Iterable;)Ljava/lang/Comparable;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p0, Lz9/t;

    .line 116
    .line 117
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lz9/u;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lz9/v;->i:Lca/m;

    .line 14
    .line 15
    iget-object v1, p0, Lca/m;->h:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v2, 0x1

    .line 32
    invoke-virtual {p0, v1, v2}, Lca/m;->e(Ljava/lang/String;Z)Lz9/u;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 38
    :goto_1
    if-nez v1, :cond_2

    .line 39
    .line 40
    iget v1, p0, Lca/m;->d:I

    .line 41
    .line 42
    invoke-virtual {p0, v1}, Lca/m;->d(I)Lz9/u;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    :cond_2
    const-string v2, " startDestination="

    .line 47
    .line 48
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    if-nez v1, :cond_5

    .line 52
    .line 53
    iget-object v1, p0, Lca/m;->h:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v1, Ljava/lang/String;

    .line 56
    .line 57
    if-eqz v1, :cond_3

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    iget-object v1, p0, Lca/m;->g:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v1, Ljava/lang/String;

    .line 66
    .line 67
    if-eqz v1, :cond_4

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    new-instance v1, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    const-string v2, "0x"

    .line 76
    .line 77
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget p0, p0, Lca/m;->d:I

    .line 81
    .line 82
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_5
    const-string p0, "{"

    .line 98
    .line 99
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1}, Lz9/u;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string p0, "}"

    .line 110
    .line 111
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    :goto_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    const-string v0, "toString(...)"

    .line 119
    .line 120
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    return-object p0
.end method
