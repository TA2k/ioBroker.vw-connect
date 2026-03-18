.class public interface abstract Lt3/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public a(Lt3/t;Ljava/util/List;I)I
    .locals 14

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    check-cast v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface/range {p2 .. p2}, Ljava/util/Collection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    check-cast v5, Ljava/util/List;

    .line 27
    .line 28
    new-instance v6, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    move-object v7, v5

    .line 38
    check-cast v7, Ljava/util/Collection;

    .line 39
    .line 40
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    move v8, v3

    .line 45
    :goto_1
    if-ge v8, v7, :cond_0

    .line 46
    .line 47
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v9

    .line 51
    check-cast v9, Lt3/p0;

    .line 52
    .line 53
    new-instance v10, Lt3/l;

    .line 54
    .line 55
    sget-object v11, Lt3/u;->d:Lt3/u;

    .line 56
    .line 57
    sget-object v12, Lt3/v;->d:Lt3/v;

    .line 58
    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-direct {v10, v9, v11, v12, v13}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    add-int/lit8 v8, v8, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    add-int/lit8 v4, v4, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    const/4 v1, 0x7

    .line 76
    move/from16 v2, p3

    .line 77
    .line 78
    invoke-static {v3, v2, v1}, Lt4/b;->b(III)J

    .line 79
    .line 80
    .line 81
    move-result-wide v1

    .line 82
    new-instance v3, Lt3/x;

    .line 83
    .line 84
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-direct {v3, p1, v4}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 89
    .line 90
    .line 91
    invoke-interface {p0, v3, v0, v1, v2}, Lt3/v0;->b(Lt3/s0;Ljava/util/List;J)Lt3/r0;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-interface {p0}, Lt3/r0;->o()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    return p0
.end method

.method public abstract b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
.end method

.method public c(Lt3/t;Ljava/util/List;I)I
    .locals 14

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    check-cast v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface/range {p2 .. p2}, Ljava/util/Collection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    check-cast v5, Ljava/util/List;

    .line 27
    .line 28
    new-instance v6, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    move-object v7, v5

    .line 38
    check-cast v7, Ljava/util/Collection;

    .line 39
    .line 40
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    move v8, v3

    .line 45
    :goto_1
    if-ge v8, v7, :cond_0

    .line 46
    .line 47
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v9

    .line 51
    check-cast v9, Lt3/p0;

    .line 52
    .line 53
    new-instance v10, Lt3/l;

    .line 54
    .line 55
    sget-object v11, Lt3/u;->e:Lt3/u;

    .line 56
    .line 57
    sget-object v12, Lt3/v;->e:Lt3/v;

    .line 58
    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-direct {v10, v9, v11, v12, v13}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    add-int/lit8 v8, v8, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    add-int/lit8 v4, v4, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    const/16 v1, 0xd

    .line 76
    .line 77
    move/from16 v2, p3

    .line 78
    .line 79
    invoke-static {v2, v3, v1}, Lt4/b;->b(III)J

    .line 80
    .line 81
    .line 82
    move-result-wide v1

    .line 83
    new-instance v3, Lt3/x;

    .line 84
    .line 85
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    invoke-direct {v3, p1, v4}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 90
    .line 91
    .line 92
    invoke-interface {p0, v3, v0, v1, v2}, Lt3/v0;->b(Lt3/s0;Ljava/util/List;J)Lt3/r0;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-interface {p0}, Lt3/r0;->m()I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    return p0
.end method

.method public d(Lt3/t;Ljava/util/List;I)I
    .locals 14

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    check-cast v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface/range {p2 .. p2}, Ljava/util/Collection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    check-cast v5, Ljava/util/List;

    .line 27
    .line 28
    new-instance v6, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    move-object v7, v5

    .line 38
    check-cast v7, Ljava/util/Collection;

    .line 39
    .line 40
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    move v8, v3

    .line 45
    :goto_1
    if-ge v8, v7, :cond_0

    .line 46
    .line 47
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v9

    .line 51
    check-cast v9, Lt3/p0;

    .line 52
    .line 53
    new-instance v10, Lt3/l;

    .line 54
    .line 55
    sget-object v11, Lt3/u;->d:Lt3/u;

    .line 56
    .line 57
    sget-object v12, Lt3/v;->e:Lt3/v;

    .line 58
    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-direct {v10, v9, v11, v12, v13}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    add-int/lit8 v8, v8, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    add-int/lit8 v4, v4, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    const/16 v1, 0xd

    .line 76
    .line 77
    move/from16 v2, p3

    .line 78
    .line 79
    invoke-static {v2, v3, v1}, Lt4/b;->b(III)J

    .line 80
    .line 81
    .line 82
    move-result-wide v1

    .line 83
    new-instance v3, Lt3/x;

    .line 84
    .line 85
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    invoke-direct {v3, p1, v4}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 90
    .line 91
    .line 92
    invoke-interface {p0, v3, v0, v1, v2}, Lt3/v0;->b(Lt3/s0;Ljava/util/List;J)Lt3/r0;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-interface {p0}, Lt3/r0;->m()I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    return p0
.end method

.method public e(Lt3/t;Ljava/util/List;I)I
    .locals 14

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    check-cast v1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface/range {p2 .. p2}, Ljava/util/Collection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v3

    .line 20
    :goto_0
    if-ge v4, v2, :cond_1

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    check-cast v5, Ljava/util/List;

    .line 27
    .line 28
    new-instance v6, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    move-object v7, v5

    .line 38
    check-cast v7, Ljava/util/Collection;

    .line 39
    .line 40
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    move v8, v3

    .line 45
    :goto_1
    if-ge v8, v7, :cond_0

    .line 46
    .line 47
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v9

    .line 51
    check-cast v9, Lt3/p0;

    .line 52
    .line 53
    new-instance v10, Lt3/l;

    .line 54
    .line 55
    sget-object v11, Lt3/u;->e:Lt3/u;

    .line 56
    .line 57
    sget-object v12, Lt3/v;->d:Lt3/v;

    .line 58
    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-direct {v10, v9, v11, v12, v13}, Lt3/l;-><init>(Lt3/p0;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    add-int/lit8 v8, v8, 0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_0
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    add-int/lit8 v4, v4, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    const/4 v1, 0x7

    .line 76
    move/from16 v2, p3

    .line 77
    .line 78
    invoke-static {v3, v2, v1}, Lt4/b;->b(III)J

    .line 79
    .line 80
    .line 81
    move-result-wide v1

    .line 82
    new-instance v3, Lt3/x;

    .line 83
    .line 84
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    invoke-direct {v3, p1, v4}, Lt3/x;-><init>(Lt3/t;Lt4/m;)V

    .line 89
    .line 90
    .line 91
    invoke-interface {p0, v3, v0, v1, v2}, Lt3/v0;->b(Lt3/s0;Ljava/util/List;J)Lt3/r0;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    invoke-interface {p0}, Lt3/r0;->o()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    return p0
.end method
