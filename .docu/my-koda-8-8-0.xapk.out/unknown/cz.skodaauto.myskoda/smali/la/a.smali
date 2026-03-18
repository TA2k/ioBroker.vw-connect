.class public abstract Lla/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public b:Z


# direct methods
.method public static final a(Lla/r;Lua/a;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lla/r;->d:Lka/u;

    .line 2
    .line 3
    const-string v1, "PRAGMA user_version = "

    .line 4
    .line 5
    iget-object v2, p0, Lla/r;->c:Lla/b;

    .line 6
    .line 7
    iget-object v3, v2, Lla/b;->g:Lla/t;

    .line 8
    .line 9
    sget-object v4, Lla/t;->f:Lla/t;

    .line 10
    .line 11
    if-ne v3, v4, :cond_0

    .line 12
    .line 13
    const-string v3, "PRAGMA journal_mode = WAL"

    .line 14
    .line 15
    invoke-static {p1, v3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const-string v3, "PRAGMA journal_mode = TRUNCATE"

    .line 20
    .line 21
    invoke-static {p1, v3}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :goto_0
    iget-object v2, v2, Lla/b;->g:Lla/t;

    .line 25
    .line 26
    if-ne v2, v4, :cond_1

    .line 27
    .line 28
    const-string v2, "PRAGMA synchronous = NORMAL"

    .line 29
    .line 30
    invoke-static {p1, v2}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const-string v2, "PRAGMA synchronous = FULL"

    .line 35
    .line 36
    invoke-static {p1, v2}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    :goto_1
    invoke-static {p1}, Lla/a;->b(Lua/a;)V

    .line 40
    .line 41
    .line 42
    const-string v2, "PRAGMA user_version"

    .line 43
    .line 44
    invoke-interface {p1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    :try_start_0
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 49
    .line 50
    .line 51
    const/4 v3, 0x0

    .line 52
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 53
    .line 54
    .line 55
    move-result-wide v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 56
    long-to-int v3, v3

    .line 57
    const/4 v4, 0x0

    .line 58
    invoke-static {v2, v4}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 59
    .line 60
    .line 61
    iget v2, v0, Lka/u;->a:I

    .line 62
    .line 63
    if-eq v3, v2, :cond_5

    .line 64
    .line 65
    const-string v2, "BEGIN EXCLUSIVE TRANSACTION"

    .line 66
    .line 67
    invoke-static {p1, v2}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    if-nez v3, :cond_2

    .line 71
    .line 72
    :try_start_1
    invoke-virtual {p0, p1}, Lla/a;->c(Lua/a;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :catchall_0
    move-exception v0

    .line 77
    goto :goto_3

    .line 78
    :cond_2
    iget v2, v0, Lka/u;->a:I

    .line 79
    .line 80
    invoke-virtual {p0, p1, v3, v2}, Lla/a;->d(Lua/a;II)V

    .line 81
    .line 82
    .line 83
    :goto_2
    new-instance v2, Ljava/lang/StringBuilder;

    .line 84
    .line 85
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget v0, v0, Lka/u;->a:I

    .line 89
    .line 90
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    sget-object v0, Llx0/b0;->a:Llx0/b0;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :goto_3
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    :goto_4
    instance-of v1, v0, Llx0/n;

    .line 108
    .line 109
    if-nez v1, :cond_3

    .line 110
    .line 111
    move-object v1, v0

    .line 112
    check-cast v1, Llx0/b0;

    .line 113
    .line 114
    const-string v1, "END TRANSACTION"

    .line 115
    .line 116
    invoke-static {p1, v1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    :cond_3
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    if-nez v0, :cond_4

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_4
    const-string p0, "ROLLBACK TRANSACTION"

    .line 127
    .line 128
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw v0

    .line 132
    :cond_5
    :goto_5
    invoke-virtual {p0, p1}, Lla/a;->e(Lua/a;)V

    .line 133
    .line 134
    .line 135
    return-void

    .line 136
    :catchall_1
    move-exception p0

    .line 137
    :try_start_2
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 138
    :catchall_2
    move-exception p1

    .line 139
    invoke-static {v2, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    throw p1
.end method

.method public static b(Lua/a;)V
    .locals 5

    .line 1
    const-string v0, "PRAGMA busy_timeout"

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :try_start_0
    invoke-interface {v0}, Lua/c;->s0()Z

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-interface {v0, v1}, Lua/c;->getLong(I)J

    .line 12
    .line 13
    .line 14
    move-result-wide v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-static {v0, v3}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    const-wide/16 v3, 0xbb8

    .line 20
    .line 21
    cmp-long v0, v1, v3

    .line 22
    .line 23
    if-gez v0, :cond_0

    .line 24
    .line 25
    const-string v0, "PRAGMA busy_timeout = 3000"

    .line 26
    .line 27
    invoke-static {p0, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 33
    :catchall_1
    move-exception v1

    .line 34
    invoke-static {v0, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    throw v1
.end method


# virtual methods
.method public final c(Lua/a;)V
    .locals 7

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "SELECT count(*) FROM sqlite_master WHERE name != \'android_metadata\'"

    .line 7
    .line 8
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :try_start_0
    invoke-interface {v0}, Lua/c;->s0()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    invoke-interface {v0, v2}, Lua/c;->getLong(I)J

    .line 20
    .line 21
    .line 22
    move-result-wide v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    const-wide/16 v5, 0x0

    .line 24
    .line 25
    cmp-long v1, v3, v5

    .line 26
    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_3

    .line 33
    :cond_0
    :goto_0
    const/4 v1, 0x0

    .line 34
    invoke-static {v0, v1}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    move-object v0, p0

    .line 38
    check-cast v0, Lla/r;

    .line 39
    .line 40
    iget-object v1, v0, Lla/r;->d:Lka/u;

    .line 41
    .line 42
    invoke-virtual {v1, p1}, Lka/u;->a(Lua/a;)V

    .line 43
    .line 44
    .line 45
    if-nez v2, :cond_2

    .line 46
    .line 47
    invoke-virtual {v1, p1}, Lka/u;->v(Lua/a;)Lco/a;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    iget-boolean v3, v2, Lco/a;->b:Z

    .line 52
    .line 53
    if-eqz v3, :cond_1

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    new-instance p1, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v0, "Pre-packaged database has an invalid schema: "

    .line 61
    .line 62
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v0, v2, Lco/a;->c:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :cond_2
    :goto_1
    invoke-virtual {p0, p1}, Lla/a;->f(Lua/a;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1, p1}, Lka/u;->r(Lua/a;)V

    .line 86
    .line 87
    .line 88
    iget-object p0, v0, Lla/r;->e:Ljava/util/List;

    .line 89
    .line 90
    check-cast p0, Ljava/lang/Iterable;

    .line 91
    .line 92
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    :cond_3
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-eqz v0, :cond_4

    .line 101
    .line 102
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    check-cast v0, Lfb/a;

    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    instance-of v0, p1, Lxa/a;

    .line 112
    .line 113
    if-eqz v0, :cond_3

    .line 114
    .line 115
    move-object v0, p1

    .line 116
    check-cast v0, Lxa/a;

    .line 117
    .line 118
    iget-object v0, v0, Lxa/a;->d:Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 119
    .line 120
    const-string v1, "db"

    .line 121
    .line 122
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_4
    return-void

    .line 127
    :goto_3
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 128
    :catchall_1
    move-exception p1

    .line 129
    invoke-static {v0, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 130
    .line 131
    .line 132
    throw p1
.end method

.method public final d(Lua/a;II)V
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "connection"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v3, p0

    .line 13
    .line 14
    check-cast v3, Lla/r;

    .line 15
    .line 16
    iget-object v4, v3, Lla/r;->c:Lla/b;

    .line 17
    .line 18
    iget-object v5, v4, Lla/b;->d:Lfb/k;

    .line 19
    .line 20
    const-string v6, "<this>"

    .line 21
    .line 22
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v5, v5, Lfb/k;->a:Ljava/util/LinkedHashMap;

    .line 26
    .line 27
    if-ne v1, v2, :cond_0

    .line 28
    .line 29
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 30
    .line 31
    goto/16 :goto_7

    .line 32
    .line 33
    :cond_0
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x1

    .line 35
    if-le v2, v1, :cond_1

    .line 36
    .line 37
    move v8, v7

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    move v8, v6

    .line 40
    :goto_0
    new-instance v9, Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 43
    .line 44
    .line 45
    move v10, v1

    .line 46
    :cond_2
    if-eqz v8, :cond_3

    .line 47
    .line 48
    if-ge v10, v2, :cond_b

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_3
    if-le v10, v2, :cond_b

    .line 52
    .line 53
    :goto_1
    const/4 v11, 0x0

    .line 54
    if-eqz v8, :cond_5

    .line 55
    .line 56
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 57
    .line 58
    .line 59
    move-result-object v12

    .line 60
    invoke-virtual {v5, v12}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v12

    .line 64
    check-cast v12, Ljava/util/TreeMap;

    .line 65
    .line 66
    if-nez v12, :cond_4

    .line 67
    .line 68
    :goto_2
    move-object v14, v11

    .line 69
    goto :goto_3

    .line 70
    :cond_4
    invoke-virtual {v12}, Ljava/util/TreeMap;->descendingKeySet()Ljava/util/NavigableSet;

    .line 71
    .line 72
    .line 73
    move-result-object v13

    .line 74
    new-instance v14, Llx0/l;

    .line 75
    .line 76
    invoke-direct {v14, v12, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_5
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 81
    .line 82
    .line 83
    move-result-object v12

    .line 84
    invoke-virtual {v5, v12}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v12

    .line 88
    check-cast v12, Ljava/util/TreeMap;

    .line 89
    .line 90
    if-nez v12, :cond_6

    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_6
    invoke-virtual {v12}, Ljava/util/TreeMap;->keySet()Ljava/util/Set;

    .line 94
    .line 95
    .line 96
    move-result-object v13

    .line 97
    new-instance v14, Llx0/l;

    .line 98
    .line 99
    invoke-direct {v14, v12, v13}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :goto_3
    if-nez v14, :cond_7

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_7
    iget-object v12, v14, Llx0/l;->d:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v12, Ljava/util/Map;

    .line 108
    .line 109
    iget-object v13, v14, Llx0/l;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v13, Ljava/lang/Iterable;

    .line 112
    .line 113
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 114
    .line 115
    .line 116
    move-result-object v13

    .line 117
    :cond_8
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 118
    .line 119
    .line 120
    move-result v14

    .line 121
    if-eqz v14, :cond_a

    .line 122
    .line 123
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v14

    .line 127
    check-cast v14, Ljava/lang/Number;

    .line 128
    .line 129
    invoke-virtual {v14}, Ljava/lang/Number;->intValue()I

    .line 130
    .line 131
    .line 132
    move-result v14

    .line 133
    if-eqz v8, :cond_9

    .line 134
    .line 135
    add-int/lit8 v15, v10, 0x1

    .line 136
    .line 137
    if-gt v15, v14, :cond_8

    .line 138
    .line 139
    if-gt v14, v2, :cond_8

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_9
    if-gt v2, v14, :cond_8

    .line 143
    .line 144
    if-ge v14, v10, :cond_8

    .line 145
    .line 146
    :goto_4
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v10

    .line 150
    invoke-interface {v12, v10}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v10

    .line 154
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move v12, v7

    .line 161
    move v10, v14

    .line 162
    goto :goto_5

    .line 163
    :cond_a
    move v12, v6

    .line 164
    :goto_5
    if-nez v12, :cond_2

    .line 165
    .line 166
    :goto_6
    move-object v5, v11

    .line 167
    goto :goto_7

    .line 168
    :cond_b
    move-object v5, v9

    .line 169
    :goto_7
    iget-object v6, v3, Lla/r;->d:Lka/u;

    .line 170
    .line 171
    if-eqz v5, :cond_e

    .line 172
    .line 173
    invoke-virtual {v6, v0}, Lka/u;->u(Lua/a;)V

    .line 174
    .line 175
    .line 176
    check-cast v5, Ljava/lang/Iterable;

    .line 177
    .line 178
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    if-eqz v2, :cond_c

    .line 187
    .line 188
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v2

    .line 192
    check-cast v2, Loa/b;

    .line 193
    .line 194
    invoke-virtual {v2, v0}, Loa/b;->b(Lua/a;)V

    .line 195
    .line 196
    .line 197
    goto :goto_8

    .line 198
    :cond_c
    invoke-virtual {v6, v0}, Lka/u;->v(Lua/a;)Lco/a;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    iget-boolean v2, v1, Lco/a;->b:Z

    .line 203
    .line 204
    if-eqz v2, :cond_d

    .line 205
    .line 206
    invoke-virtual {v6, v0}, Lka/u;->t(Lua/a;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual/range {p0 .. p1}, Lla/a;->f(Lua/a;)V

    .line 210
    .line 211
    .line 212
    return-void

    .line 213
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 214
    .line 215
    new-instance v2, Ljava/lang/StringBuilder;

    .line 216
    .line 217
    const-string v3, "Migration didn\'t properly handle: "

    .line 218
    .line 219
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 220
    .line 221
    .line 222
    iget-object v1, v1, Lco/a;->c:Ljava/lang/String;

    .line 223
    .line 224
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 225
    .line 226
    .line 227
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    throw v0

    .line 239
    :cond_e
    const-string v5, "<this>"

    .line 240
    .line 241
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    const/4 v5, 0x0

    .line 245
    if-le v1, v2, :cond_f

    .line 246
    .line 247
    iget-boolean v7, v4, Lla/b;->l:Z

    .line 248
    .line 249
    if-eqz v7, :cond_f

    .line 250
    .line 251
    goto :goto_9

    .line 252
    :cond_f
    iget-object v7, v4, Lla/b;->m:Ljava/util/Set;

    .line 253
    .line 254
    iget-boolean v8, v4, Lla/b;->k:Z

    .line 255
    .line 256
    if-eqz v8, :cond_11

    .line 257
    .line 258
    if-eqz v7, :cond_10

    .line 259
    .line 260
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 261
    .line 262
    .line 263
    move-result-object v8

    .line 264
    invoke-interface {v7, v8}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v7

    .line 268
    if-nez v7, :cond_11

    .line 269
    .line 270
    :cond_10
    const/4 v5, 0x1

    .line 271
    :cond_11
    :goto_9
    if-nez v5, :cond_1a

    .line 272
    .line 273
    iget-boolean v1, v4, Lla/b;->s:Z

    .line 274
    .line 275
    if-eqz v1, :cond_16

    .line 276
    .line 277
    const-string v1, "SELECT name, type FROM sqlite_master WHERE type = \'table\' OR type = \'view\'"

    .line 278
    .line 279
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    :try_start_0
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 284
    .line 285
    .line 286
    move-result-object v2

    .line 287
    :cond_12
    :goto_a
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 288
    .line 289
    .line 290
    move-result v4

    .line 291
    const/4 v5, 0x0

    .line 292
    if-eqz v4, :cond_14

    .line 293
    .line 294
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v4

    .line 298
    const-string v7, "sqlite_"

    .line 299
    .line 300
    invoke-static {v4, v7, v5}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 301
    .line 302
    .line 303
    move-result v5

    .line 304
    if-nez v5, :cond_12

    .line 305
    .line 306
    const-string v5, "android_metadata"

    .line 307
    .line 308
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    move-result v5

    .line 312
    if-eqz v5, :cond_13

    .line 313
    .line 314
    goto :goto_a

    .line 315
    :cond_13
    const/4 v5, 0x1

    .line 316
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v5

    .line 320
    const-string v7, "view"

    .line 321
    .line 322
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 323
    .line 324
    .line 325
    move-result v5

    .line 326
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 327
    .line 328
    .line 329
    move-result-object v5

    .line 330
    new-instance v7, Llx0/l;

    .line 331
    .line 332
    invoke-direct {v7, v4, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v2, v7}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    goto :goto_a

    .line 339
    :catchall_0
    move-exception v0

    .line 340
    move-object v2, v0

    .line 341
    goto :goto_c

    .line 342
    :cond_14
    invoke-static {v2}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 343
    .line 344
    .line 345
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 346
    const/4 v4, 0x0

    .line 347
    invoke-static {v1, v4}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v2, v5}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    :goto_b
    move-object v2, v1

    .line 355
    check-cast v2, Lnx0/a;

    .line 356
    .line 357
    invoke-virtual {v2}, Lnx0/a;->hasNext()Z

    .line 358
    .line 359
    .line 360
    move-result v4

    .line 361
    if-eqz v4, :cond_17

    .line 362
    .line 363
    invoke-virtual {v2}, Lnx0/a;->next()Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v2

    .line 367
    check-cast v2, Llx0/l;

    .line 368
    .line 369
    iget-object v4, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast v4, Ljava/lang/String;

    .line 372
    .line 373
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 374
    .line 375
    check-cast v2, Ljava/lang/Boolean;

    .line 376
    .line 377
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 378
    .line 379
    .line 380
    move-result v2

    .line 381
    const/16 v5, 0x60

    .line 382
    .line 383
    if-eqz v2, :cond_15

    .line 384
    .line 385
    new-instance v2, Ljava/lang/StringBuilder;

    .line 386
    .line 387
    const-string v7, "DROP VIEW IF EXISTS `"

    .line 388
    .line 389
    invoke-direct {v2, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 390
    .line 391
    .line 392
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 393
    .line 394
    .line 395
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 396
    .line 397
    .line 398
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v2

    .line 402
    invoke-static {v0, v2}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 403
    .line 404
    .line 405
    goto :goto_b

    .line 406
    :cond_15
    new-instance v2, Ljava/lang/StringBuilder;

    .line 407
    .line 408
    const-string v7, "DROP TABLE IF EXISTS `"

    .line 409
    .line 410
    invoke-direct {v2, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 411
    .line 412
    .line 413
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 414
    .line 415
    .line 416
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 417
    .line 418
    .line 419
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v2

    .line 423
    invoke-static {v0, v2}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 424
    .line 425
    .line 426
    goto :goto_b

    .line 427
    :goto_c
    :try_start_1
    throw v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 428
    :catchall_1
    move-exception v0

    .line 429
    invoke-static {v1, v2}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 430
    .line 431
    .line 432
    throw v0

    .line 433
    :cond_16
    invoke-virtual {v6, v0}, Lka/u;->c(Lua/a;)V

    .line 434
    .line 435
    .line 436
    :cond_17
    iget-object v1, v3, Lla/r;->e:Ljava/util/List;

    .line 437
    .line 438
    check-cast v1, Ljava/lang/Iterable;

    .line 439
    .line 440
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 441
    .line 442
    .line 443
    move-result-object v1

    .line 444
    :cond_18
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 445
    .line 446
    .line 447
    move-result v2

    .line 448
    if-eqz v2, :cond_19

    .line 449
    .line 450
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v2

    .line 454
    check-cast v2, Lfb/a;

    .line 455
    .line 456
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 457
    .line 458
    .line 459
    instance-of v2, v0, Lxa/a;

    .line 460
    .line 461
    if-eqz v2, :cond_18

    .line 462
    .line 463
    move-object v2, v0

    .line 464
    check-cast v2, Lxa/a;

    .line 465
    .line 466
    iget-object v2, v2, Lxa/a;->d:Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 467
    .line 468
    const-string v3, "db"

    .line 469
    .line 470
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 471
    .line 472
    .line 473
    goto :goto_d

    .line 474
    :cond_19
    invoke-virtual {v6, v0}, Lka/u;->a(Lua/a;)V

    .line 475
    .line 476
    .line 477
    return-void

    .line 478
    :cond_1a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 479
    .line 480
    new-instance v3, Ljava/lang/StringBuilder;

    .line 481
    .line 482
    const-string v4, "A migration from "

    .line 483
    .line 484
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 488
    .line 489
    .line 490
    const-string v1, " to "

    .line 491
    .line 492
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 493
    .line 494
    .line 495
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 496
    .line 497
    .line 498
    const-string v1, " was required but not found. Please provide the necessary Migration path via RoomDatabase.Builder.addMigration(...) or allow for destructive migrations via one of the RoomDatabase.Builder.fallbackToDestructiveMigration* functions."

    .line 499
    .line 500
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 501
    .line 502
    .line 503
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 504
    .line 505
    .line 506
    move-result-object v1

    .line 507
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 508
    .line 509
    .line 510
    move-result-object v1

    .line 511
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    throw v0
.end method

.method public final e(Lua/a;)V
    .locals 9

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "Pre-packaged database has an invalid schema: "

    .line 7
    .line 8
    const-string v1, "SELECT 1 FROM sqlite_master WHERE type = \'table\' AND name = \'room_master_table\'"

    .line 9
    .line 10
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :try_start_0
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x1

    .line 19
    const/4 v4, 0x0

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 23
    .line 24
    .line 25
    move-result-wide v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    const-wide/16 v7, 0x0

    .line 27
    .line 28
    cmp-long v2, v5, v7

    .line 29
    .line 30
    if-eqz v2, :cond_0

    .line 31
    .line 32
    move v2, v3

    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto/16 :goto_7

    .line 36
    .line 37
    :cond_0
    move v2, v4

    .line 38
    :goto_0
    const/4 v5, 0x0

    .line 39
    invoke-static {v1, v5}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 40
    .line 41
    .line 42
    if-eqz v2, :cond_3

    .line 43
    .line 44
    const-string v0, "SELECT identity_hash FROM room_master_table WHERE id = 42 LIMIT 1"

    .line 45
    .line 46
    invoke-interface {p1, v0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    :try_start_1
    invoke-interface {v0}, Lua/c;->s0()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_1

    .line 55
    .line 56
    invoke-interface {v0, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 60
    goto :goto_1

    .line 61
    :catchall_1
    move-exception p0

    .line 62
    goto :goto_2

    .line 63
    :cond_1
    move-object v1, v5

    .line 64
    :goto_1
    invoke-static {v0, v5}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 65
    .line 66
    .line 67
    move-object v0, p0

    .line 68
    check-cast v0, Lla/r;

    .line 69
    .line 70
    iget-object v0, v0, Lla/r;->d:Lka/u;

    .line 71
    .line 72
    iget-object v2, v0, Lka/u;->b:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v2, Ljava/lang/String;

    .line 75
    .line 76
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-nez v2, :cond_6

    .line 81
    .line 82
    iget-object v2, v0, Lka/u;->c:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v2, Ljava/lang/String;

    .line 85
    .line 86
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-eqz v2, :cond_2

    .line 91
    .line 92
    goto/16 :goto_5

    .line 93
    .line 94
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    new-instance p1, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    const-string v2, "Room cannot verify the data integrity. Looks like you\'ve changed schema but forgot to update the version number. You can simply fix this by increasing the version number. Expected identity hash: "

    .line 99
    .line 100
    invoke-direct {p1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    iget-object v0, v0, Lka/u;->b:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v0, Ljava/lang/String;

    .line 106
    .line 107
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    const-string v0, ", found: "

    .line 111
    .line 112
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :goto_2
    :try_start_2
    throw p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 131
    :catchall_2
    move-exception p1

    .line 132
    invoke-static {v0, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 133
    .line 134
    .line 135
    throw p1

    .line 136
    :cond_3
    const-string v1, "BEGIN EXCLUSIVE TRANSACTION"

    .line 137
    .line 138
    invoke-static {p1, v1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    :try_start_3
    move-object v1, p0

    .line 142
    check-cast v1, Lla/r;

    .line 143
    .line 144
    iget-object v1, v1, Lla/r;->d:Lka/u;

    .line 145
    .line 146
    invoke-virtual {v1, p1}, Lka/u;->v(Lua/a;)Lco/a;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    iget-boolean v2, v1, Lco/a;->b:Z

    .line 151
    .line 152
    if-eqz v2, :cond_4

    .line 153
    .line 154
    move-object v0, p0

    .line 155
    check-cast v0, Lla/r;

    .line 156
    .line 157
    iget-object v0, v0, Lla/r;->d:Lka/u;

    .line 158
    .line 159
    invoke-virtual {v0, p1}, Lka/u;->t(Lua/a;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {p0, p1}, Lla/a;->f(Lua/a;)V

    .line 163
    .line 164
    .line 165
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :catchall_3
    move-exception v0

    .line 169
    goto :goto_3

    .line 170
    :cond_4
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    new-instance v4, Ljava/lang/StringBuilder;

    .line 173
    .line 174
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    iget-object v0, v1, Lco/a;->c:Ljava/lang/String;

    .line 178
    .line 179
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 180
    .line 181
    .line 182
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-direct {v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 194
    :goto_3
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    :goto_4
    instance-of v1, v0, Llx0/n;

    .line 199
    .line 200
    if-nez v1, :cond_5

    .line 201
    .line 202
    move-object v1, v0

    .line 203
    check-cast v1, Llx0/b0;

    .line 204
    .line 205
    const-string v1, "END TRANSACTION"

    .line 206
    .line 207
    invoke-static {p1, v1}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    :cond_5
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    if-nez v0, :cond_9

    .line 215
    .line 216
    :cond_6
    :goto_5
    move-object v0, p0

    .line 217
    check-cast v0, Lla/r;

    .line 218
    .line 219
    iget-object v1, v0, Lla/r;->d:Lka/u;

    .line 220
    .line 221
    invoke-virtual {v1, p1}, Lka/u;->s(Lua/a;)V

    .line 222
    .line 223
    .line 224
    iget-object v0, v0, Lla/r;->e:Ljava/util/List;

    .line 225
    .line 226
    check-cast v0, Ljava/lang/Iterable;

    .line 227
    .line 228
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    :cond_7
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    if-eqz v1, :cond_8

    .line 237
    .line 238
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    check-cast v1, Lfb/a;

    .line 243
    .line 244
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 245
    .line 246
    .line 247
    instance-of v2, p1, Lxa/a;

    .line 248
    .line 249
    if-eqz v2, :cond_7

    .line 250
    .line 251
    move-object v2, p1

    .line 252
    check-cast v2, Lxa/a;

    .line 253
    .line 254
    iget-object v2, v2, Lxa/a;->d:Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 255
    .line 256
    iget v4, v1, Lfb/a;->a:I

    .line 257
    .line 258
    packed-switch v4, :pswitch_data_0

    .line 259
    .line 260
    .line 261
    const-string v4, "db"

    .line 262
    .line 263
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    iget-object v1, v1, Lfb/a;->b:Ljava/lang/Object;

    .line 267
    .line 268
    check-cast v1, Lla/p;

    .line 269
    .line 270
    invoke-virtual {v1, v2}, Lla/p;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    goto :goto_6

    .line 274
    :pswitch_0
    const-string v4, "db"

    .line 275
    .line 276
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 277
    .line 278
    .line 279
    invoke-interface {v2}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransaction()V

    .line 280
    .line 281
    .line 282
    :try_start_4
    new-instance v4, Ljava/lang/StringBuilder;

    .line 283
    .line 284
    const-string v5, "DELETE FROM workspec WHERE state IN (2, 3, 5) AND (last_enqueue_time + minimum_retention_duration) < "

    .line 285
    .line 286
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    iget-object v1, v1, Lfb/a;->b:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v1, Leb/j;

    .line 292
    .line 293
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 294
    .line 295
    .line 296
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 297
    .line 298
    .line 299
    move-result-wide v5

    .line 300
    sget-wide v7, Lfb/p;->a:J

    .line 301
    .line 302
    sub-long/2addr v5, v7

    .line 303
    invoke-virtual {v4, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    const-string v1, " AND (SELECT COUNT(*)=0 FROM dependency WHERE     prerequisite_id=id AND     work_spec_id NOT IN         (SELECT id FROM workspec WHERE state IN (2, 3, 5)))"

    .line 307
    .line 308
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 309
    .line 310
    .line 311
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    invoke-interface {v2, v1}, Landroidx/sqlite/db/SupportSQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    invoke-interface {v2}, Landroidx/sqlite/db/SupportSQLiteDatabase;->setTransactionSuccessful()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 319
    .line 320
    .line 321
    invoke-interface {v2}, Landroidx/sqlite/db/SupportSQLiteDatabase;->endTransaction()V

    .line 322
    .line 323
    .line 324
    goto :goto_6

    .line 325
    :catchall_4
    move-exception p0

    .line 326
    invoke-interface {v2}, Landroidx/sqlite/db/SupportSQLiteDatabase;->endTransaction()V

    .line 327
    .line 328
    .line 329
    throw p0

    .line 330
    :cond_8
    iput-boolean v3, p0, Lla/a;->a:Z

    .line 331
    .line 332
    return-void

    .line 333
    :cond_9
    const-string p0, "ROLLBACK TRANSACTION"

    .line 334
    .line 335
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    throw v0

    .line 339
    :goto_7
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 340
    :catchall_5
    move-exception p1

    .line 341
    invoke-static {v1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 342
    .line 343
    .line 344
    throw p1

    .line 345
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(Lua/a;)V
    .locals 2

    .line 1
    const-string v0, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    .line 2
    .line 3
    invoke-static {p1, v0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Lla/r;

    .line 7
    .line 8
    iget-object p0, p0, Lla/r;->d:Lka/u;

    .line 9
    .line 10
    iget-object p0, p0, Lka/u;->b:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/lang/String;

    .line 13
    .line 14
    const-string v0, "hash"

    .line 15
    .line 16
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    new-instance v0, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v1, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'"

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p0, "\')"

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p1, p0}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method
