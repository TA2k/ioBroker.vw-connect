.class public final Lr11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lr11/y;

.field public final b:Lr11/w;

.field public final c:Ljp/u1;

.field public final d:Ln11/f;


# direct methods
.method public constructor <init>(Lr11/y;Lr11/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lr11/b;->a:Lr11/y;

    .line 3
    iput-object p2, p0, Lr11/b;->b:Lr11/w;

    const/4 p1, 0x0

    .line 4
    iput-object p1, p0, Lr11/b;->c:Ljp/u1;

    .line 5
    iput-object p1, p0, Lr11/b;->d:Ln11/f;

    return-void
.end method

.method public constructor <init>(Lr11/y;Lr11/w;Ljp/u1;Ln11/f;)V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lr11/b;->a:Lr11/y;

    .line 8
    iput-object p2, p0, Lr11/b;->b:Lr11/w;

    .line 9
    iput-object p3, p0, Lr11/b;->c:Ljp/u1;

    .line 10
    iput-object p4, p0, Lr11/b;->d:Ln11/f;

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Ln11/l;
    .locals 5

    .line 1
    iget-object v0, p0, Lr11/b;->b:Lr11/w;

    .line 2
    .line 3
    if-eqz v0, :cond_6

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v1}, Lr11/b;->d(Ljp/u1;)Ljp/u1;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljp/u1;->I()Ljp/u1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance v2, Lr11/s;

    .line 15
    .line 16
    invoke-direct {v2, p0}, Lr11/s;-><init>(Ljp/u1;)V

    .line 17
    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-interface {v0, v2, p1, v3}, Lr11/w;->d(Lr11/s;Ljava/lang/CharSequence;I)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-ltz v0, :cond_4

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-lt v0, v3, :cond_5

    .line 31
    .line 32
    invoke-virtual {v2, p1}, Lr11/s;->b(Ljava/lang/CharSequence;)J

    .line 33
    .line 34
    .line 35
    move-result-wide v3

    .line 36
    iget-object p1, v2, Lr11/s;->e:Ljava/lang/Integer;

    .line 37
    .line 38
    if-eqz p1, :cond_2

    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    sget-object v0, Ln11/f;->e:Ln11/n;

    .line 45
    .line 46
    const v0, -0x5265bff

    .line 47
    .line 48
    .line 49
    if-lt p1, v0, :cond_1

    .line 50
    .line 51
    const v0, 0x5265bff

    .line 52
    .line 53
    .line 54
    if-gt p1, v0, :cond_1

    .line 55
    .line 56
    invoke-static {p1}, Ln11/f;->q(I)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    if-nez p1, :cond_0

    .line 61
    .line 62
    sget-object p1, Ln11/f;->e:Ln11/n;

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    new-instance v2, Ls11/g;

    .line 66
    .line 67
    invoke-direct {v2, v0, v1, p1, p1}, Ls11/g;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 68
    .line 69
    .line 70
    move-object p1, v2

    .line 71
    :goto_0
    invoke-virtual {p0, p1}, Ljp/u1;->J(Ln11/f;)Ljp/u1;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    goto :goto_1

    .line 76
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 77
    .line 78
    const-string v0, "Millis out of range: "

    .line 79
    .line 80
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_2
    iget-object p1, v2, Lr11/s;->d:Ln11/f;

    .line 89
    .line 90
    if-eqz p1, :cond_3

    .line 91
    .line 92
    invoke-virtual {p0, p1}, Ljp/u1;->J(Ln11/f;)Ljp/u1;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    :cond_3
    :goto_1
    new-instance p1, Ln11/l;

    .line 97
    .line 98
    invoke-direct {p1, v3, v4, p0}, Ln11/l;-><init>(JLjp/u1;)V

    .line 99
    .line 100
    .line 101
    return-object p1

    .line 102
    :cond_4
    not-int v0, v0

    .line 103
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 104
    .line 105
    invoke-static {v0, p1}, Lr11/u;->c(ILjava/lang/String;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw p0

    .line 113
    :cond_6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 114
    .line 115
    const-string p1, "Parsing not supported"

    .line 116
    .line 117
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0
.end method

.method public final b(Lo11/a;)Ljava/lang/String;
    .locals 13

    .line 1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v0, "Printing not supported"

    .line 4
    .line 5
    move-object v2, v0

    .line 6
    iget-object v0, p0, Lr11/b;->a:Lr11/y;

    .line 7
    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    invoke-interface {v0}, Lr11/y;->e()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 15
    .line 16
    .line 17
    :try_start_0
    sget-object v3, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 18
    .line 19
    invoke-virtual {p1}, Lo11/a;->b()J

    .line 20
    .line 21
    .line 22
    move-result-wide v3

    .line 23
    invoke-virtual {p1}, Lo11/a;->a()Ljp/u1;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    if-nez p1, :cond_0

    .line 28
    .line 29
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    :cond_0
    if-eqz v0, :cond_2

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lr11/b;->d(Ljp/u1;)Ljp/u1;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {p0}, Ljp/u1;->m()Ln11/f;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {p1, v3, v4}, Ln11/f;->i(J)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    int-to-long v5, v2

    .line 48
    add-long v7, v3, v5

    .line 49
    .line 50
    xor-long v9, v3, v7

    .line 51
    .line 52
    const-wide/16 v11, 0x0

    .line 53
    .line 54
    cmp-long v9, v9, v11

    .line 55
    .line 56
    if-gez v9, :cond_1

    .line 57
    .line 58
    xor-long/2addr v5, v3

    .line 59
    cmp-long v5, v5, v11

    .line 60
    .line 61
    if-ltz v5, :cond_1

    .line 62
    .line 63
    sget-object p1, Ln11/f;->e:Ln11/n;

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    move v5, v2

    .line 67
    move-wide v2, v3

    .line 68
    :goto_0
    move-object v6, p1

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    move v5, v2

    .line 71
    move-wide v2, v7

    .line 72
    goto :goto_0

    .line 73
    :goto_1
    invoke-virtual {p0}, Ljp/u1;->I()Ljp/u1;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    const/4 v7, 0x0

    .line 78
    invoke-interface/range {v0 .. v7}, Lr11/y;->b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 83
    .line 84
    invoke-direct {p0, v2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 88
    :catch_0
    :goto_2
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :cond_3
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 94
    .line 95
    invoke-direct {p0, v2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0
.end method

.method public final c(Lo11/b;)Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Printing not supported"

    .line 4
    .line 5
    iget-object p0, p0, Lr11/b;->a:Lr11/y;

    .line 6
    .line 7
    if-eqz p0, :cond_2

    .line 8
    .line 9
    invoke-interface {p0}, Lr11/y;->e()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 14
    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    :try_start_0
    invoke-interface {p0, v0, p1, v1}, Lr11/y;->c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    const-string p1, "The partial must not be null"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 34
    .line 35
    invoke-direct {p0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    :catch_0
    :goto_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 45
    .line 46
    invoke-direct {p0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0
.end method

.method public final d(Ljp/u1;)Ljp/u1;
    .locals 1

    .line 1
    sget-object v0, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    :cond_0
    iget-object v0, p0, Lr11/b;->c:Ljp/u1;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    move-object p1, v0

    .line 14
    :cond_1
    iget-object p0, p0, Lr11/b;->d:Ln11/f;

    .line 15
    .line 16
    if-eqz p0, :cond_2

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ljp/u1;->J(Ln11/f;)Ljp/u1;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_2
    return-object p1
.end method

.method public final e()Lr11/b;
    .locals 4

    .line 1
    sget-object v0, Ln11/f;->e:Ln11/n;

    .line 2
    .line 3
    iget-object v1, p0, Lr11/b;->d:Ln11/f;

    .line 4
    .line 5
    if-ne v1, v0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v1, Lr11/b;

    .line 9
    .line 10
    iget-object v2, p0, Lr11/b;->b:Lr11/w;

    .line 11
    .line 12
    iget-object v3, p0, Lr11/b;->c:Ljp/u1;

    .line 13
    .line 14
    iget-object p0, p0, Lr11/b;->a:Lr11/y;

    .line 15
    .line 16
    invoke-direct {v1, p0, v2, v3, v0}, Lr11/b;-><init>(Lr11/y;Lr11/w;Ljp/u1;Ln11/f;)V

    .line 17
    .line 18
    .line 19
    return-object v1
.end method
