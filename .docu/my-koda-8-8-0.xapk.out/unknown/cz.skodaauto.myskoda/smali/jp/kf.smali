.class public abstract Ljp/kf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a()Ljava/util/ArrayList;
    .locals 4

    .line 1
    sget-object v0, Lje/y;->f:Lsx0/b;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Landroidx/collection/d1;

    .line 15
    .line 16
    const/4 v3, 0x6

    .line 17
    invoke-direct {v2, v0, v3}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    :goto_0
    invoke-virtual {v2}, Landroidx/collection/d1;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {v2}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lje/y;

    .line 31
    .line 32
    new-instance v3, Lje/z;

    .line 33
    .line 34
    invoke-direct {v3, v0}, Lje/z;-><init>(Lje/y;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    return-object v1
.end method

.method public static final b()Ljava/util/ArrayList;
    .locals 4

    .line 1
    sget-object v0, Lje/m0;->f:Lsx0/b;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Landroidx/collection/d1;

    .line 15
    .line 16
    const/4 v3, 0x6

    .line 17
    invoke-direct {v2, v0, v3}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    :goto_0
    invoke-virtual {v2}, Landroidx/collection/d1;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-virtual {v2}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Lje/m0;

    .line 31
    .line 32
    new-instance v3, Lje/n0;

    .line 33
    .line 34
    invoke-direct {v3, v0}, Lje/n0;-><init>(Lje/m0;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    return-object v1
.end method

.method public static final c(Lqe/e;)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lqe/e;->c:Ljava/util/Map;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    check-cast p0, Ljava/lang/Iterable;

    .line 12
    .line 13
    invoke-static {p0}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    if-nez p0, :cond_1

    .line 20
    .line 21
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 22
    .line 23
    :cond_1
    return-object p0
.end method

.method public static final d(Lje/r;)Lje/r;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Lje/r;->Companion:Lje/q;

    .line 4
    .line 5
    const-string v0, "<this>"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance p0, Lje/r;

    .line 11
    .line 12
    invoke-direct {p0}, Lje/r;-><init>()V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-object p0
.end method

.method public static final e(Ll2/b1;Lqe/a;Ljava/util/List;)V
    .locals 5

    .line 1
    const-string v0, "season"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "days"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lqe/d;

    .line 16
    .line 17
    iget-object v0, v0, Lqe/d;->c:Ljava/util/Map;

    .line 18
    .line 19
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lqe/e;

    .line 24
    .line 25
    if-eqz v0, :cond_3

    .line 26
    .line 27
    iget-object v0, v0, Lqe/e;->c:Ljava/util/Map;

    .line 28
    .line 29
    if-eqz v0, :cond_3

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    if-eqz v0, :cond_3

    .line 36
    .line 37
    check-cast v0, Ljava/lang/Iterable;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Ljava/util/List;

    .line 54
    .line 55
    move-object v2, p2

    .line 56
    check-cast v2, Ljava/lang/Iterable;

    .line 57
    .line 58
    instance-of v3, v2, Ljava/util/Collection;

    .line 59
    .line 60
    if-eqz v3, :cond_1

    .line 61
    .line 62
    move-object v3, v2

    .line 63
    check-cast v3, Ljava/util/Collection;

    .line 64
    .line 65
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    if-eqz v3, :cond_1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    :cond_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-eqz v3, :cond_0

    .line 81
    .line 82
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Lje/z;

    .line 87
    .line 88
    move-object v4, v1

    .line 89
    check-cast v4, Ljava/lang/Iterable;

    .line 90
    .line 91
    invoke-static {v4}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-interface {v4, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    if-eqz v3, :cond_2

    .line 100
    .line 101
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    check-cast v2, Lqe/d;

    .line 106
    .line 107
    invoke-virtual {v2, p1}, Lqe/d;->b(Lqe/a;)Lqe/e;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    iget-object v2, v2, Lqe/e;->c:Ljava/util/Map;

    .line 112
    .line 113
    invoke-interface {v2, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_3
    return-void
.end method

.method public static final f(Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;)Lg40/w0;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lg40/w0;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;->getId()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {p0}, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;->getType()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v0, "CREDIT"

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    sget-object v0, Lg40/x0;->d:Lg40/x0;

    .line 28
    .line 29
    :goto_0
    move-object v3, v0

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    const-string v0, "DEBIT"

    .line 32
    .line 33
    invoke-virtual {v3, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    sget-object v0, Lg40/x0;->e:Lg40/x0;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    sget-object v0, Lg40/x0;->f:Lg40/x0;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :goto_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;->getName()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-virtual {p0}, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;->getPointsAmount()I

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    invoke-virtual {p0}, Lcz/myskoda/api/bff_loyalty_program/v2/TransactionDto;->getTimestamp()Ljava/time/OffsetDateTime;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    invoke-direct/range {v1 .. v6}, Lg40/w0;-><init>(Ljava/lang/String;Lg40/x0;Ljava/lang/String;ILjava/time/OffsetDateTime;)V

    .line 58
    .line 59
    .line 60
    return-object v1
.end method

.method public static final g(Lje/n0;Lje/n0;)Ljava/util/List;
    .locals 4

    .line 1
    if-eqz p0, :cond_3

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    goto :goto_2

    .line 6
    :cond_0
    sget-object v0, Lje/m0;->f:Lsx0/b;

    .line 7
    .line 8
    iget-object p0, p0, Lje/n0;->a:Lje/m0;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    iget-object p1, p1, Lje/n0;->a:Lje/m0;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    const/4 v1, 0x1

    .line 21
    if-gt p0, p1, :cond_1

    .line 22
    .line 23
    new-instance v2, Lgy0/j;

    .line 24
    .line 25
    invoke-direct {v2, p0, p1, v1}, Lgy0/h;-><init>(III)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v2}, Lmx0/q;->l0(Ljava/util/List;Lgy0/j;)Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-virtual {v0}, Lmx0/a;->c()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    invoke-static {p0, v2}, Lkp/r9;->m(II)Lgy0/j;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {v0, p0}, Lmx0/q;->l0(Ljava/util/List;Lgy0/j;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    check-cast p0, Ljava/util/Collection;

    .line 46
    .line 47
    new-instance v2, Lgy0/j;

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    invoke-direct {v2, v3, p1, v1}, Lgy0/h;-><init>(III)V

    .line 51
    .line 52
    .line 53
    invoke-static {v0, v2}, Lmx0/q;->l0(Ljava/util/List;Lgy0/j;)Ljava/util/List;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    check-cast p1, Ljava/lang/Iterable;

    .line 58
    .line 59
    invoke-static {p1, p0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    :goto_0
    check-cast p0, Ljava/lang/Iterable;

    .line 64
    .line 65
    new-instance p1, Ljava/util/ArrayList;

    .line 66
    .line 67
    const/16 v0, 0xa

    .line 68
    .line 69
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_2

    .line 85
    .line 86
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    check-cast v0, Lje/m0;

    .line 91
    .line 92
    new-instance v1, Lje/n0;

    .line 93
    .line 94
    invoke-direct {v1, v0}, Lje/n0;-><init>(Lje/m0;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_2
    return-object p1

    .line 102
    :cond_3
    :goto_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 103
    .line 104
    return-object p0
.end method

.method public static final h(Ll2/b1;Lqe/a;Ljava/util/List;Ljava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "season"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "days"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "hoursSlots"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0, p1, p2}, Ljp/kf;->e(Ll2/b1;Lqe/a;Ljava/util/List;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lqe/d;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lqe/d;->b(Lqe/a;)Lqe/e;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    iget-object p0, p0, Lqe/e;->c:Ljava/util/Map;

    .line 30
    .line 31
    invoke-interface {p0, p2, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    return-void
.end method
