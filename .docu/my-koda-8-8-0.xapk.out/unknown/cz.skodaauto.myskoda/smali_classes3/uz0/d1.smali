.class public Luz0/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lsz0/g;
.implements Luz0/l;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Luz0/c0;

.field public final c:I

.field public d:I

.field public final e:[Ljava/lang/String;

.field public final f:[Ljava/util/List;

.field public g:Ljava/util/ArrayList;

.field public final h:[Z

.field public i:Ljava/lang/Object;

.field public final j:Ljava/lang/Object;

.field public final k:Ljava/lang/Object;

.field public final l:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;Luz0/c0;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luz0/d1;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Luz0/d1;->b:Luz0/c0;

    .line 7
    .line 8
    iput p3, p0, Luz0/d1;->c:I

    .line 9
    .line 10
    const/4 p1, -0x1

    .line 11
    iput p1, p0, Luz0/d1;->d:I

    .line 12
    .line 13
    new-array p1, p3, [Ljava/lang/String;

    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    :goto_0
    if-ge p2, p3, :cond_0

    .line 17
    .line 18
    const-string v0, "[UNINITIALIZED]"

    .line 19
    .line 20
    aput-object v0, p1, p2

    .line 21
    .line 22
    add-int/lit8 p2, p2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iput-object p1, p0, Luz0/d1;->e:[Ljava/lang/String;

    .line 26
    .line 27
    iget p1, p0, Luz0/d1;->c:I

    .line 28
    .line 29
    new-array p2, p1, [Ljava/util/List;

    .line 30
    .line 31
    iput-object p2, p0, Luz0/d1;->f:[Ljava/util/List;

    .line 32
    .line 33
    new-array p1, p1, [Z

    .line 34
    .line 35
    iput-object p1, p0, Luz0/d1;->h:[Z

    .line 36
    .line 37
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    .line 38
    .line 39
    iput-object p1, p0, Luz0/d1;->i:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p1, Llx0/j;->e:Llx0/j;

    .line 42
    .line 43
    new-instance p2, Luz0/c1;

    .line 44
    .line 45
    const/4 p3, 0x0

    .line 46
    invoke-direct {p2, p0, p3}, Luz0/c1;-><init>(Luz0/d1;I)V

    .line 47
    .line 48
    .line 49
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    iput-object p2, p0, Luz0/d1;->j:Ljava/lang/Object;

    .line 54
    .line 55
    new-instance p2, Luz0/c1;

    .line 56
    .line 57
    const/4 p3, 0x1

    .line 58
    invoke-direct {p2, p0, p3}, Luz0/c1;-><init>(Luz0/d1;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    iput-object p2, p0, Luz0/d1;->k:Ljava/lang/Object;

    .line 66
    .line 67
    new-instance p2, Luz0/c1;

    .line 68
    .line 69
    const/4 p3, 0x2

    .line 70
    invoke-direct {p2, p0, p3}, Luz0/c1;-><init>(Luz0/d1;I)V

    .line 71
    .line 72
    .line 73
    invoke-static {p1, p2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    iput-object p1, p0, Luz0/d1;->l:Ljava/lang/Object;

    .line 78
    .line 79
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Set;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final c(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Luz0/d1;->i:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/lang/Integer;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, -0x3

    .line 22
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget p0, p0, Luz0/d1;->c:I

    .line 2
    .line 3
    return p0
.end method

.method public final e(I)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->e:[Ljava/lang/String;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_2

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Luz0/d1;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_1
    move-object v0, p1

    .line 12
    check-cast v0, Lsz0/g;

    .line 13
    .line 14
    invoke-interface {v0}, Lsz0/g;->h()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    iget-object v3, p0, Luz0/d1;->a:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-nez v2, :cond_2

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_2
    check-cast p1, Luz0/d1;

    .line 28
    .line 29
    iget-object v2, p0, Luz0/d1;->k:Ljava/lang/Object;

    .line 30
    .line 31
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, [Lsz0/g;

    .line 36
    .line 37
    iget-object p1, p1, Luz0/d1;->k:Ljava/lang/Object;

    .line 38
    .line 39
    invoke-interface {p1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, [Lsz0/g;

    .line 44
    .line 45
    invoke-static {v2, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-nez p1, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    invoke-interface {v0}, Lsz0/g;->d()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    iget v2, p0, Luz0/d1;->c:I

    .line 57
    .line 58
    if-eq v2, p1, :cond_4

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_4
    move p1, v1

    .line 62
    :goto_0
    if-ge p1, v2, :cond_7

    .line 63
    .line 64
    invoke-interface {p0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    invoke-interface {v3}, Lsz0/g;->h()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    invoke-interface {v0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    invoke-interface {v4}, Lsz0/g;->h()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-nez v3, :cond_5

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_5
    invoke-interface {p0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-interface {v3}, Lsz0/g;->getKind()Lkp/y8;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-interface {v0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    invoke-interface {v4}, Lsz0/g;->getKind()Lkp/y8;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    if-nez v3, :cond_6

    .line 108
    .line 109
    :goto_1
    return v1

    .line 110
    :cond_6
    add-int/lit8 p1, p1, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_7
    :goto_2
    const/4 p0, 0x1

    .line 114
    return p0
.end method

.method public final f(I)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->f:[Ljava/util/List;

    .line 2
    .line 3
    aget-object p0, p0, p1

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 8
    .line 9
    :cond_0
    return-object p0
.end method

.method public g(I)Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->j:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, [Lqz0/a;

    .line 8
    .line 9
    aget-object p0, p0, p1

    .line 10
    .line 11
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->g:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    :cond_0
    return-object p0
.end method

.method public getKind()Lkp/y8;
    .locals 0

    .line 1
    sget-object p0, Lsz0/k;->b:Lsz0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->l:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final i(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/d1;->h:[Z

    .line 2
    .line 3
    aget-boolean p0, p0, p1

    .line 4
    .line 5
    return p0
.end method

.method public isInline()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final j(Ljava/lang/String;Z)V
    .locals 4

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Luz0/d1;->d:I

    .line 7
    .line 8
    add-int/lit8 v0, v0, 0x1

    .line 9
    .line 10
    iput v0, p0, Luz0/d1;->d:I

    .line 11
    .line 12
    iget-object v1, p0, Luz0/d1;->e:[Ljava/lang/String;

    .line 13
    .line 14
    aput-object p1, v1, v0

    .line 15
    .line 16
    iget-object p1, p0, Luz0/d1;->h:[Z

    .line 17
    .line 18
    aput-boolean p2, p1, v0

    .line 19
    .line 20
    iget-object p1, p0, Luz0/d1;->f:[Ljava/util/List;

    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    aput-object p2, p1, v0

    .line 24
    .line 25
    iget p1, p0, Luz0/d1;->c:I

    .line 26
    .line 27
    add-int/lit8 p1, p1, -0x1

    .line 28
    .line 29
    if-ne v0, p1, :cond_1

    .line 30
    .line 31
    new-instance p1, Ljava/util/HashMap;

    .line 32
    .line 33
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    array-length p2, v1

    .line 37
    const/4 v0, 0x0

    .line 38
    :goto_0
    if-ge v0, p2, :cond_0

    .line 39
    .line 40
    aget-object v2, v1, v0

    .line 41
    .line 42
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    invoke-virtual {p1, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    add-int/lit8 v0, v0, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    iput-object p1, p0, Luz0/d1;->i:Ljava/lang/Object;

    .line 53
    .line 54
    :cond_1
    return-void
.end method

.method public final k(Ljava/lang/annotation/Annotation;)V
    .locals 2

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Luz0/d1;->g:Ljava/util/ArrayList;

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/util/ArrayList;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Luz0/d1;->g:Ljava/util/ArrayList;

    .line 17
    .line 18
    :cond_0
    iget-object p0, p0, Luz0/d1;->g:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Luz0/b1;->n(Lsz0/g;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
