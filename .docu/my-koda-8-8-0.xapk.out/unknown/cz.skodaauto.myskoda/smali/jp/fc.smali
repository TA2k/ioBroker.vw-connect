.class public abstract Ljp/fc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(J)Lao0/c;
    .locals 8

    .line 1
    new-instance v0, Lao0/c;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {v1, v2}, Ljava/time/LocalTime;->of(II)Ljava/time/LocalTime;

    .line 7
    .line 8
    .line 9
    move-result-object v4

    .line 10
    const-string v1, "of(...)"

    .line 11
    .line 12
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v5, Lao0/f;->d:Lao0/f;

    .line 16
    .line 17
    sget-object v1, Ljava/time/DayOfWeek;->MONDAY:Ljava/time/DayOfWeek;

    .line 18
    .line 19
    invoke-static {v1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    const/4 v7, 0x0

    .line 24
    const/4 v3, 0x1

    .line 25
    move-wide v1, p0

    .line 26
    invoke-direct/range {v0 .. v7}, Lao0/c;-><init>(JZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;Z)V

    .line 27
    .line 28
    .line 29
    return-object v0
.end method

.method public static final b(Lc00/n1;Lij0/a;)Lc00/n1;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "stringResource"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    new-array v3, v2, [Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Ljj0/f;

    .line 19
    .line 20
    const v4, 0x7f120099

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v9

    .line 27
    const-wide/16 v6, 0x1

    .line 28
    .line 29
    invoke-static {v6, v7, v1}, Ljp/fc;->g(JLij0/a;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v8

    .line 33
    new-instance v5, Lc00/m1;

    .line 34
    .line 35
    const/4 v14, 0x1

    .line 36
    const/4 v15, 0x0

    .line 37
    const/4 v13, 0x0

    .line 38
    move-object v10, v9

    .line 39
    move-object v11, v9

    .line 40
    move-object v12, v9

    .line 41
    invoke-direct/range {v5 .. v15}, Lc00/m1;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZ)V

    .line 42
    .line 43
    .line 44
    new-array v2, v2, [Ljava/lang/Object;

    .line 45
    .line 46
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v10

    .line 50
    const-wide/16 v7, 0x2

    .line 51
    .line 52
    invoke-static {v7, v8, v1}, Ljp/fc;->g(JLij0/a;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    new-instance v6, Lc00/m1;

    .line 57
    .line 58
    const/4 v15, 0x1

    .line 59
    const/16 v16, 0x0

    .line 60
    .line 61
    const/4 v14, 0x0

    .line 62
    move-object v11, v10

    .line 63
    move-object v12, v10

    .line 64
    move-object v13, v10

    .line 65
    invoke-direct/range {v6 .. v16}, Lc00/m1;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZ)V

    .line 66
    .line 67
    .line 68
    filled-new-array {v5, v6}, [Lc00/m1;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    const/4 v2, 0x1

    .line 77
    const/16 v3, 0x8

    .line 78
    .line 79
    invoke-static {v0, v2, v1, v3}, Lc00/n1;->a(Lc00/n1;ZLjava/util/List;I)Lc00/n1;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    return-object v0
.end method

.method public static final g(JLij0/a;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "$this$name"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x1

    .line 7
    .line 8
    invoke-static {p0, p1, v0, v1}, Lao0/d;->a(JJ)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    new-array p0, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p2, Ljj0/f;

    .line 18
    .line 19
    const p1, 0x7f12008d

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    const-wide/16 v2, 0x2

    .line 28
    .line 29
    invoke-static {p0, p1, v2, v3}, Lao0/d;->a(JJ)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    new-array p0, v1, [Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p2, Ljj0/f;

    .line 38
    .line 39
    const p1, 0x7f12008e

    .line 40
    .line 41
    .line 42
    invoke-virtual {p2, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :cond_1
    const-wide/16 v2, 0x3

    .line 48
    .line 49
    invoke-static {p0, p1, v2, v3}, Lao0/d;->a(JJ)Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-eqz p0, :cond_2

    .line 54
    .line 55
    new-array p0, v1, [Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p2, Ljj0/f;

    .line 58
    .line 59
    const p1, 0x7f12008f

    .line 60
    .line 61
    .line 62
    invoke-virtual {p2, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :cond_2
    const-string p0, ""

    .line 68
    .line 69
    return-object p0
.end method

.method public static final h(Lc00/m1;Lij0/a;)Lc00/m1;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    new-array v1, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Ljj0/f;

    .line 15
    .line 16
    const v2, 0x7f120092

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    const/16 v1, 0x9f

    .line 24
    .line 25
    invoke-static {p0, p1, v0, v1}, Lc00/m1;->a(Lc00/m1;Ljava/lang/String;ZI)Lc00/m1;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static final i(Lc00/n1;Ljava/util/List;Lqr0/q;Lij0/a;Z)Lc00/n1;
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    move-object/from16 v3, p0

    .line 8
    .line 9
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v2, "timers"

    .line 13
    .line 14
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v2, "stringResource"

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    move-object v2, v0

    .line 23
    check-cast v2, Ljava/lang/Iterable;

    .line 24
    .line 25
    new-instance v3, Ljava/util/ArrayList;

    .line 26
    .line 27
    const/16 v4, 0xa

    .line 28
    .line 29
    invoke-static {v2, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    const/4 v5, 0x1

    .line 45
    const/4 v6, 0x0

    .line 46
    if-eqz v4, :cond_1

    .line 47
    .line 48
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    check-cast v4, Lao0/c;

    .line 53
    .line 54
    iget-wide v8, v4, Lao0/c;->a:J

    .line 55
    .line 56
    invoke-static {v8, v9, v1}, Ljp/fc;->g(JLij0/a;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v10

    .line 60
    iget-object v7, v4, Lao0/c;->c:Ljava/time/LocalTime;

    .line 61
    .line 62
    invoke-static {v7}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v11

    .line 66
    if-eqz p2, :cond_0

    .line 67
    .line 68
    invoke-static/range {p2 .. p3}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    :goto_1
    move-object v12, v6

    .line 73
    goto :goto_2

    .line 74
    :cond_0
    new-array v6, v6, [Ljava/lang/Object;

    .line 75
    .line 76
    move-object v7, v1

    .line 77
    check-cast v7, Ljj0/f;

    .line 78
    .line 79
    const v12, 0x7f120099

    .line 80
    .line 81
    .line 82
    invoke-virtual {v7, v12, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    goto :goto_1

    .line 87
    :goto_2
    invoke-static {v4, v1}, Ljp/ab;->b(Lao0/c;Lij0/a;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v13

    .line 91
    iget-boolean v4, v4, Lao0/c;->b:Z

    .line 92
    .line 93
    xor-int/lit8 v17, p4, 0x1

    .line 94
    .line 95
    new-instance v7, Lc00/m1;

    .line 96
    .line 97
    const/4 v14, 0x0

    .line 98
    const/4 v15, 0x0

    .line 99
    move/from16 v16, v4

    .line 100
    .line 101
    invoke-direct/range {v7 .. v17}, Lc00/m1;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZ)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_1
    new-instance v1, Lc00/n1;

    .line 109
    .line 110
    invoke-direct {v1, v5, v6, v3, v0}, Lc00/n1;-><init>(ZZLjava/util/List;Ljava/util/List;)V

    .line 111
    .line 112
    .line 113
    return-object v1
.end method


# virtual methods
.method public abstract c(Ljava/lang/Class;Ljava/lang/reflect/Field;)Ljava/lang/reflect/Method;
.end method

.method public abstract d(Ljava/lang/Class;)Ljava/lang/reflect/Constructor;
.end method

.method public abstract e(Ljava/lang/Class;)[Ljava/lang/String;
.end method

.method public abstract f(Ljava/lang/Class;)Z
.end method
