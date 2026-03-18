.class public final Lu01/k0;
.super Lu01/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:Lu01/y;


# instance fields
.field public final f:Lu01/y;

.field public final g:Lu01/k;

.field public final h:Ljava/util/LinkedHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lu01/y;->e:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "/"

    .line 4
    .line 5
    invoke-static {v0}, Lrb0/a;->a(Ljava/lang/String;)Lu01/y;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lu01/k0;->i:Lu01/y;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Lu01/y;Lu01/k;Ljava/util/LinkedHashMap;)V
    .locals 1

    .line 1
    const-string v0, "fileSystem"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu01/k0;->f:Lu01/y;

    .line 10
    .line 11
    iput-object p2, p0, Lu01/k0;->g:Lu01/k;

    .line 12
    .line 13
    iput-object p3, p0, Lu01/k0;->h:Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final B(Lu01/y;)Lu01/t;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "not implemented yet!"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final E(Lu01/y;Z)Lu01/f0;
    .locals 0

    .line 1
    const-string p0, "file"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/io/IOException;

    .line 7
    .line 8
    const-string p1, "zip file systems are read-only"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final H(Lu01/y;)Lu01/h0;
    .locals 7

    .line 1
    const-string v0, "file"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lu01/k0;->i:Lu01/y;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-static {v0, p1, v1}, Lv01/c;->b(Lu01/y;Lu01/y;Z)Lu01/y;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget-object v2, p0, Lu01/k0;->h:Ljava/util/LinkedHashMap;

    .line 17
    .line 18
    invoke-virtual {v2, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Lv01/i;

    .line 23
    .line 24
    if-eqz v0, :cond_3

    .line 25
    .line 26
    iget-wide v2, v0, Lv01/i;->f:J

    .line 27
    .line 28
    iget-object p1, p0, Lu01/k0;->g:Lu01/k;

    .line 29
    .line 30
    iget-object p0, p0, Lu01/k0;->f:Lu01/y;

    .line 31
    .line 32
    invoke-virtual {p1, p0}, Lu01/k;->B(Lu01/y;)Lu01/t;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    const/4 p1, 0x0

    .line 37
    :try_start_0
    iget-wide v4, v0, Lv01/i;->h:J

    .line 38
    .line 39
    invoke-virtual {p0, v4, v5}, Lu01/t;->a(J)Lu01/j;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    invoke-static {v4}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 44
    .line 45
    .line 46
    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 47
    :try_start_1
    invoke-virtual {p0}, Lu01/t;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    .line 49
    .line 50
    move-object p0, p1

    .line 51
    goto :goto_1

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto :goto_1

    .line 54
    :catchall_1
    move-exception v4

    .line 55
    if-eqz p0, :cond_0

    .line 56
    .line 57
    :try_start_2
    invoke-virtual {p0}, Lu01/t;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :catchall_2
    move-exception p0

    .line 62
    invoke-static {v4, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    :cond_0
    :goto_0
    move-object p0, v4

    .line 66
    move-object v4, p1

    .line 67
    :goto_1
    if-nez p0, :cond_2

    .line 68
    .line 69
    const-string p0, "<this>"

    .line 70
    .line 71
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {v4, p1}, Lv01/b;->h(Lu01/b0;Lv01/i;)Lv01/i;

    .line 75
    .line 76
    .line 77
    iget p0, v0, Lv01/i;->g:I

    .line 78
    .line 79
    if-nez p0, :cond_1

    .line 80
    .line 81
    new-instance p0, Lv01/f;

    .line 82
    .line 83
    invoke-direct {p0, v4, v2, v3, v1}, Lv01/f;-><init>(Lu01/h0;JZ)V

    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_1
    new-instance p0, Lu01/r;

    .line 88
    .line 89
    new-instance p1, Lv01/f;

    .line 90
    .line 91
    iget-wide v5, v0, Lv01/i;->e:J

    .line 92
    .line 93
    invoke-direct {p1, v4, v5, v6, v1}, Lv01/f;-><init>(Lu01/h0;JZ)V

    .line 94
    .line 95
    .line 96
    new-instance v0, Ljava/util/zip/Inflater;

    .line 97
    .line 98
    invoke-direct {v0, v1}, Ljava/util/zip/Inflater;-><init>(Z)V

    .line 99
    .line 100
    .line 101
    invoke-static {p1}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-direct {p0, p1, v0}, Lu01/r;-><init>(Lu01/b0;Ljava/util/zip/Inflater;)V

    .line 106
    .line 107
    .line 108
    new-instance p1, Lv01/f;

    .line 109
    .line 110
    const/4 v0, 0x0

    .line 111
    invoke-direct {p1, p0, v2, v3, v0}, Lv01/f;-><init>(Lu01/h0;JZ)V

    .line 112
    .line 113
    .line 114
    move-object p0, p1

    .line 115
    :goto_2
    return-object p0

    .line 116
    :cond_2
    throw p0

    .line 117
    :cond_3
    new-instance p0, Ljava/io/FileNotFoundException;

    .line 118
    .line 119
    new-instance v0, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    const-string v1, "no such file: "

    .line 122
    .line 123
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-direct {p0, p1}, Ljava/io/FileNotFoundException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p0
.end method

.method public final a(Lu01/y;)Lu01/f0;
    .locals 0

    .line 1
    const-string p0, "file"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/io/IOException;

    .line 7
    .line 8
    const-string p1, "zip file systems are read-only"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final b(Lu01/y;Lu01/y;)V
    .locals 0

    .line 1
    const-string p0, "source"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "target"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Ljava/io/IOException;

    .line 12
    .line 13
    const-string p1, "zip file systems are read-only"

    .line 14
    .line 15
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public final f(Lu01/y;)V
    .locals 0

    .line 1
    const-string p0, "dir"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/io/IOException;

    .line 7
    .line 8
    const-string p1, "zip file systems are read-only"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final g(Lu01/y;)V
    .locals 0

    .line 1
    const-string p0, "path"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/io/IOException;

    .line 7
    .line 8
    const-string p1, "zip file systems are read-only"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final k(Lu01/y;)Ljava/util/List;
    .locals 2

    .line 1
    sget-object v0, Lu01/k0;->i:Lu01/y;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-static {v0, p1, v1}, Lv01/c;->b(Lu01/y;Lu01/y;Z)Lu01/y;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lu01/k0;->h:Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lv01/i;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lv01/i;->q:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-static {p0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 29
    .line 30
    new-instance v0, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v1, "not a directory: "

    .line 33
    .line 34
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0
.end method

.method public final q(Lu01/y;)Li5/f;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "path"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object v2, Lu01/k0;->i:Lu01/y;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-static {v2, v1, v3}, Lv01/c;->b(Lu01/y;Lu01/y;Z)Lu01/y;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iget-object v2, v0, Lu01/k0;->h:Ljava/util/LinkedHashMap;

    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lv01/i;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    return-object v2

    .line 32
    :cond_0
    iget-wide v4, v1, Lv01/i;->h:J

    .line 33
    .line 34
    const-wide/16 v6, -0x1

    .line 35
    .line 36
    cmp-long v6, v4, v6

    .line 37
    .line 38
    if-eqz v6, :cond_4

    .line 39
    .line 40
    iget-object v6, v0, Lu01/k0;->g:Lu01/k;

    .line 41
    .line 42
    iget-object v0, v0, Lu01/k0;->f:Lu01/y;

    .line 43
    .line 44
    invoke-virtual {v6, v0}, Lu01/k;->B(Lu01/y;)Lu01/t;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    :try_start_0
    invoke-virtual {v6, v4, v5}, Lu01/t;->a(J)Lu01/j;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 53
    .line 54
    .line 55
    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_4

    .line 56
    :try_start_1
    invoke-static {v4, v1}, Lv01/b;->h(Lu01/b0;Lv01/i;)Lv01/i;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 61
    .line 62
    .line 63
    :try_start_2
    invoke-virtual {v4}, Lu01/b0;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 64
    .line 65
    .line 66
    move-object v0, v2

    .line 67
    goto :goto_1

    .line 68
    :catchall_0
    move-exception v0

    .line 69
    goto :goto_1

    .line 70
    :catchall_1
    move-exception v0

    .line 71
    move-object v1, v0

    .line 72
    :try_start_3
    invoke-virtual {v4}, Lu01/b0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :catchall_2
    move-exception v0

    .line 77
    :try_start_4
    invoke-static {v1, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 78
    .line 79
    .line 80
    :goto_0
    move-object v0, v1

    .line 81
    move-object v1, v2

    .line 82
    :goto_1
    if-nez v0, :cond_1

    .line 83
    .line 84
    :try_start_5
    invoke-virtual {v6}, Lu01/t;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 85
    .line 86
    .line 87
    move-object v0, v2

    .line 88
    goto :goto_3

    .line 89
    :catchall_3
    move-exception v0

    .line 90
    goto :goto_3

    .line 91
    :cond_1
    :try_start_6
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 92
    :catchall_4
    move-exception v0

    .line 93
    move-object v1, v0

    .line 94
    if-eqz v6, :cond_2

    .line 95
    .line 96
    :try_start_7
    invoke-virtual {v6}, Lu01/t;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 97
    .line 98
    .line 99
    goto :goto_2

    .line 100
    :catchall_5
    move-exception v0

    .line 101
    invoke-static {v1, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 102
    .line 103
    .line 104
    :cond_2
    :goto_2
    move-object v0, v1

    .line 105
    move-object v1, v2

    .line 106
    :goto_3
    if-nez v0, :cond_3

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_3
    throw v0

    .line 110
    :cond_4
    :goto_4
    new-instance v4, Li5/f;

    .line 111
    .line 112
    iget-boolean v6, v1, Lv01/i;->b:Z

    .line 113
    .line 114
    xor-int/lit8 v5, v6, 0x1

    .line 115
    .line 116
    if-eqz v6, :cond_5

    .line 117
    .line 118
    move-object v8, v2

    .line 119
    goto :goto_5

    .line 120
    :cond_5
    iget-wide v7, v1, Lv01/i;->f:J

    .line 121
    .line 122
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    move-object v8, v0

    .line 127
    :goto_5
    iget-object v0, v1, Lv01/i;->m:Ljava/lang/Long;

    .line 128
    .line 129
    const-wide v9, 0xa9730b66800L

    .line 130
    .line 131
    .line 132
    .line 133
    .line 134
    const/16 v7, 0x2710

    .line 135
    .line 136
    const-wide/16 v11, 0x3e8

    .line 137
    .line 138
    if-eqz v0, :cond_6

    .line 139
    .line 140
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 141
    .line 142
    .line 143
    move-result-wide v13

    .line 144
    move v15, v3

    .line 145
    int-to-long v2, v7

    .line 146
    div-long/2addr v13, v2

    .line 147
    sub-long/2addr v13, v9

    .line 148
    invoke-static {v13, v14}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    goto :goto_6

    .line 153
    :cond_6
    move v15, v3

    .line 154
    iget-object v0, v1, Lv01/i;->p:Ljava/lang/Integer;

    .line 155
    .line 156
    if-eqz v0, :cond_7

    .line 157
    .line 158
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    int-to-long v2, v0

    .line 163
    mul-long/2addr v2, v11

    .line 164
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    goto :goto_6

    .line 169
    :cond_7
    const/4 v0, 0x0

    .line 170
    :goto_6
    iget-object v2, v1, Lv01/i;->k:Ljava/lang/Long;

    .line 171
    .line 172
    if-eqz v2, :cond_8

    .line 173
    .line 174
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 175
    .line 176
    .line 177
    move-result-wide v2

    .line 178
    int-to-long v13, v7

    .line 179
    div-long/2addr v2, v13

    .line 180
    sub-long/2addr v2, v9

    .line 181
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    :goto_7
    move-wide/from16 v23, v9

    .line 186
    .line 187
    :goto_8
    move-object v10, v2

    .line 188
    goto :goto_9

    .line 189
    :cond_8
    iget-object v2, v1, Lv01/i;->n:Ljava/lang/Integer;

    .line 190
    .line 191
    if-eqz v2, :cond_9

    .line 192
    .line 193
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 194
    .line 195
    .line 196
    move-result v2

    .line 197
    int-to-long v2, v2

    .line 198
    mul-long/2addr v2, v11

    .line 199
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    goto :goto_7

    .line 204
    :cond_9
    iget v2, v1, Lv01/i;->j:I

    .line 205
    .line 206
    const/4 v3, -0x1

    .line 207
    if-eq v2, v3, :cond_a

    .line 208
    .line 209
    iget v13, v1, Lv01/i;->i:I

    .line 210
    .line 211
    if-ne v2, v3, :cond_b

    .line 212
    .line 213
    :cond_a
    move-wide/from16 v23, v9

    .line 214
    .line 215
    const/4 v10, 0x0

    .line 216
    goto :goto_9

    .line 217
    :cond_b
    shr-int/lit8 v3, v13, 0x9

    .line 218
    .line 219
    and-int/lit8 v3, v3, 0x7f

    .line 220
    .line 221
    add-int/lit16 v3, v3, 0x7bc

    .line 222
    .line 223
    shr-int/lit8 v14, v13, 0x5

    .line 224
    .line 225
    and-int/lit8 v14, v14, 0xf

    .line 226
    .line 227
    and-int/lit8 v19, v13, 0x1f

    .line 228
    .line 229
    shr-int/lit8 v13, v2, 0xb

    .line 230
    .line 231
    and-int/lit8 v20, v13, 0x1f

    .line 232
    .line 233
    shr-int/lit8 v13, v2, 0x5

    .line 234
    .line 235
    and-int/lit8 v21, v13, 0x3f

    .line 236
    .line 237
    and-int/lit8 v2, v2, 0x1f

    .line 238
    .line 239
    shl-int/lit8 v22, v2, 0x1

    .line 240
    .line 241
    new-instance v2, Ljava/util/GregorianCalendar;

    .line 242
    .line 243
    invoke-direct {v2}, Ljava/util/GregorianCalendar;-><init>()V

    .line 244
    .line 245
    .line 246
    const/16 v13, 0xe

    .line 247
    .line 248
    move-wide/from16 v23, v9

    .line 249
    .line 250
    const/4 v9, 0x0

    .line 251
    invoke-virtual {v2, v13, v9}, Ljava/util/Calendar;->set(II)V

    .line 252
    .line 253
    .line 254
    add-int/lit8 v18, v14, -0x1

    .line 255
    .line 256
    move-object/from16 v16, v2

    .line 257
    .line 258
    move/from16 v17, v3

    .line 259
    .line 260
    invoke-virtual/range {v16 .. v22}, Ljava/util/Calendar;->set(IIIIII)V

    .line 261
    .line 262
    .line 263
    invoke-virtual/range {v16 .. v16}, Ljava/util/Calendar;->getTime()Ljava/util/Date;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    invoke-virtual {v2}, Ljava/util/Date;->getTime()J

    .line 268
    .line 269
    .line 270
    move-result-wide v2

    .line 271
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    goto :goto_8

    .line 276
    :goto_9
    iget-object v2, v1, Lv01/i;->l:Ljava/lang/Long;

    .line 277
    .line 278
    if-eqz v2, :cond_c

    .line 279
    .line 280
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 281
    .line 282
    .line 283
    move-result-wide v1

    .line 284
    int-to-long v11, v7

    .line 285
    div-long/2addr v1, v11

    .line 286
    sub-long v1, v1, v23

    .line 287
    .line 288
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    :goto_a
    move-object v11, v2

    .line 293
    goto :goto_b

    .line 294
    :cond_c
    iget-object v1, v1, Lv01/i;->o:Ljava/lang/Integer;

    .line 295
    .line 296
    if-eqz v1, :cond_d

    .line 297
    .line 298
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 299
    .line 300
    .line 301
    move-result v1

    .line 302
    int-to-long v1, v1

    .line 303
    mul-long/2addr v1, v11

    .line 304
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 305
    .line 306
    .line 307
    move-result-object v2

    .line 308
    goto :goto_a

    .line 309
    :cond_d
    const/4 v11, 0x0

    .line 310
    :goto_b
    const/4 v7, 0x0

    .line 311
    move-object v9, v0

    .line 312
    invoke-direct/range {v4 .. v11}, Li5/f;-><init>(ZZLu01/y;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;)V

    .line 313
    .line 314
    .line 315
    return-object v4
.end method
