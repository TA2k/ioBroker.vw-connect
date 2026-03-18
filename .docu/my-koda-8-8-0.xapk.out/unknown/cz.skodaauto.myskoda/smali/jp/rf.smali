.class public abstract Ljp/rf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lql0/g;
    .locals 10

    .line 1
    and-int/lit8 v0, p5, 0x10

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    move-object v6, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move-object v6, p4

    .line 9
    :goto_0
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 10
    .line 11
    const-string v0, "Custom error exception"

    .line 12
    .line 13
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "stringResource"

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lne0/c;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    const/16 v5, 0x1e

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 29
    .line 30
    .line 31
    const/4 v8, 0x0

    .line 32
    const/16 v9, 0x40

    .line 33
    .line 34
    const/4 v7, 0x1

    .line 35
    move-object v2, p0

    .line 36
    move-object v3, p1

    .line 37
    move-object v4, p2

    .line 38
    move-object v5, p3

    .line 39
    move-object v1, v0

    .line 40
    invoke-static/range {v1 .. v9}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    return-object v0
.end method

.method public static d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;
    .locals 11

    .line 1
    and-int/lit8 v0, p8, 0x10

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    move-object v10, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move-object/from16 v10, p5

    .line 9
    .line 10
    :goto_0
    and-int/lit8 v0, p8, 0x20

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    move/from16 v0, p6

    .line 17
    .line 18
    :goto_1
    and-int/lit8 v2, p8, 0x40

    .line 19
    .line 20
    if-eqz v2, :cond_2

    .line 21
    .line 22
    new-instance v2, Lql0/a;

    .line 23
    .line 24
    invoke-direct {v2, v1}, Lql0/a;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    move-object v3, v2

    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move-object/from16 v3, p7

    .line 30
    .line 31
    :goto_2
    const-string v2, "<this>"

    .line 32
    .line 33
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v2, "stringResource"

    .line 37
    .line 38
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    new-instance v2, Lql0/g;

    .line 42
    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    iget-object v4, p0, Lne0/c;->c:Lne0/a;

    .line 46
    .line 47
    if-eqz v4, :cond_3

    .line 48
    .line 49
    iget-object v1, v4, Lne0/a;->d:Ljava/lang/String;

    .line 50
    .line 51
    :cond_3
    move-object v4, v1

    .line 52
    const-string v1, ""

    .line 53
    .line 54
    if-eqz v0, :cond_4

    .line 55
    .line 56
    iget-wide v5, p0, Lne0/c;->d:J

    .line 57
    .line 58
    invoke-static {v5, v6}, Lzo/e;->c(J)Ljava/time/OffsetDateTime;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    invoke-static {v5}, Lvo/a;->l(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    goto :goto_3

    .line 67
    :cond_4
    move-object v5, v1

    .line 68
    :goto_3
    if-eqz v0, :cond_5

    .line 69
    .line 70
    const-string v0, "8.8.0"

    .line 71
    .line 72
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast p1, Ljj0/f;

    .line 77
    .line 78
    const v1, 0x7f1202b6

    .line 79
    .line 80
    .line 81
    invoke-virtual {p1, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    :cond_5
    move-object v7, p2

    .line 86
    move-object v8, p3

    .line 87
    move-object v9, p4

    .line 88
    move-object v6, v1

    .line 89
    invoke-direct/range {v2 .. v10}, Lql0/g;-><init>(Lql0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    new-instance p1, La60/a;

    .line 93
    .line 94
    const/4 p2, 0x1

    .line 95
    invoke-direct {p1, p0, p2}, La60/a;-><init>(Lne0/c;I)V

    .line 96
    .line 97
    .line 98
    invoke-static {p0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 99
    .line 100
    .line 101
    return-object v2
.end method

.method public static final e(Lne0/c;Lij0/a;)Lql0/g;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v1, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v2, Lql0/g;

    .line 12
    .line 13
    iget-object v1, p0, Lne0/c;->e:Lne0/b;

    .line 14
    .line 15
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    if-eq v0, v1, :cond_1

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    if-ne v0, v1, :cond_0

    .line 29
    .line 30
    sget-object v0, Lql0/c;->a:Lql0/c;

    .line 31
    .line 32
    :goto_0
    move-object v3, v0

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    new-instance p0, La8/r0;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    sget-object v0, Lql0/d;->a:Lql0/d;

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    sget-object v0, Lql0/b;->a:Lql0/b;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :goto_1
    iget-object v0, p0, Lne0/c;->c:Lne0/a;

    .line 47
    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    iget-object v0, v0, Lne0/a;->d:Ljava/lang/String;

    .line 51
    .line 52
    :goto_2
    move-object v4, v0

    .line 53
    goto :goto_3

    .line 54
    :cond_3
    const/4 v0, 0x0

    .line 55
    goto :goto_2

    .line 56
    :goto_3
    iget-wide v0, p0, Lne0/c;->d:J

    .line 57
    .line 58
    invoke-static {v0, v1}, Lzo/e;->c(J)Ljava/time/OffsetDateTime;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-static {v0}, Lvo/a;->l(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    const-string v0, "8.8.0"

    .line 67
    .line 68
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    check-cast p1, Ljj0/f;

    .line 73
    .line 74
    const v1, 0x7f1202b6

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    const/4 v9, 0x0

    .line 82
    const/16 v10, 0xf0

    .line 83
    .line 84
    const/4 v7, 0x0

    .line 85
    const/4 v8, 0x0

    .line 86
    invoke-direct/range {v2 .. v10}, Lql0/g;-><init>(Lql0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    .line 87
    .line 88
    .line 89
    new-instance p1, La60/a;

    .line 90
    .line 91
    const/4 v0, 0x1

    .line 92
    invoke-direct {p1, p0, v0}, La60/a;-><init>(Lne0/c;I)V

    .line 93
    .line 94
    .line 95
    invoke-static {p0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 96
    .line 97
    .line 98
    return-object v2
.end method


# virtual methods
.method public abstract b(Z)V
.end method

.method public abstract c(Z)V
.end method
