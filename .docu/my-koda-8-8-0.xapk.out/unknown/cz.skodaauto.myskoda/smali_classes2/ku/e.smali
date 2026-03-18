.class public final synthetic Lku/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lku/e;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lku/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lku/e;->a:Lku/e;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "com.google.firebase.sessions.settings.SessionConfigs"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "sessionsEnabled"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "sessionSamplingRate"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "sessionTimeoutSeconds"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "cacheDurationSeconds"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "cacheUpdatedTimeSeconds"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Lku/e;->descriptor:Lsz0/g;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 6

    .line 1
    sget-object p0, Luz0/g;->a:Luz0/g;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Luz0/u;->a:Luz0/u;

    .line 8
    .line 9
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sget-object v1, Luz0/k0;->a:Luz0/k0;

    .line 14
    .line 15
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    sget-object v3, Luz0/q0;->a:Luz0/q0;

    .line 24
    .line 25
    invoke-static {v3}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    const/4 v4, 0x5

    .line 30
    new-array v4, v4, [Lqz0/a;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    aput-object p0, v4, v5

    .line 34
    .line 35
    const/4 p0, 0x1

    .line 36
    aput-object v0, v4, p0

    .line 37
    .line 38
    const/4 p0, 0x2

    .line 39
    aput-object v2, v4, p0

    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    aput-object v1, v4, p0

    .line 43
    .line 44
    const/4 p0, 0x4

    .line 45
    aput-object v3, v4, p0

    .line 46
    .line 47
    return-object v4
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object p0, Lku/e;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v4, v1

    .line 11
    move-object v5, v2

    .line 12
    move-object v6, v5

    .line 13
    move-object v7, v6

    .line 14
    move-object v8, v7

    .line 15
    move-object v9, v8

    .line 16
    move v2, v0

    .line 17
    :goto_0
    if-eqz v2, :cond_6

    .line 18
    .line 19
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v10, -0x1

    .line 24
    if-eq v3, v10, :cond_5

    .line 25
    .line 26
    if-eqz v3, :cond_4

    .line 27
    .line 28
    if-eq v3, v0, :cond_3

    .line 29
    .line 30
    const/4 v10, 0x2

    .line 31
    if-eq v3, v10, :cond_2

    .line 32
    .line 33
    const/4 v10, 0x3

    .line 34
    if-eq v3, v10, :cond_1

    .line 35
    .line 36
    const/4 v10, 0x4

    .line 37
    if-ne v3, v10, :cond_0

    .line 38
    .line 39
    sget-object v3, Luz0/q0;->a:Luz0/q0;

    .line 40
    .line 41
    invoke-interface {p1, p0, v10, v3, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    move-object v9, v3

    .line 46
    check-cast v9, Ljava/lang/Long;

    .line 47
    .line 48
    or-int/lit8 v4, v4, 0x10

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    new-instance p0, Lqz0/k;

    .line 52
    .line 53
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_1
    sget-object v3, Luz0/k0;->a:Luz0/k0;

    .line 58
    .line 59
    invoke-interface {p1, p0, v10, v3, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    move-object v8, v3

    .line 64
    check-cast v8, Ljava/lang/Integer;

    .line 65
    .line 66
    or-int/lit8 v4, v4, 0x8

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    sget-object v3, Luz0/k0;->a:Luz0/k0;

    .line 70
    .line 71
    invoke-interface {p1, p0, v10, v3, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    move-object v7, v3

    .line 76
    check-cast v7, Ljava/lang/Integer;

    .line 77
    .line 78
    or-int/lit8 v4, v4, 0x4

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_3
    sget-object v3, Luz0/u;->a:Luz0/u;

    .line 82
    .line 83
    invoke-interface {p1, p0, v0, v3, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    move-object v6, v3

    .line 88
    check-cast v6, Ljava/lang/Double;

    .line 89
    .line 90
    or-int/lit8 v4, v4, 0x2

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_4
    sget-object v3, Luz0/g;->a:Luz0/g;

    .line 94
    .line 95
    invoke-interface {p1, p0, v1, v3, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    move-object v5, v3

    .line 100
    check-cast v5, Ljava/lang/Boolean;

    .line 101
    .line 102
    or-int/lit8 v4, v4, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_5
    move v2, v1

    .line 106
    goto :goto_0

    .line 107
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 108
    .line 109
    .line 110
    new-instance v3, Lku/g;

    .line 111
    .line 112
    invoke-direct/range {v3 .. v9}, Lku/g;-><init>(ILjava/lang/Boolean;Ljava/lang/Double;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Long;)V

    .line 113
    .line 114
    .line 115
    return-object v3
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lku/e;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lku/g;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lku/e;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Luz0/g;->a:Luz0/g;

    .line 15
    .line 16
    iget-object v1, p2, Lku/g;->a:Ljava/lang/Boolean;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Luz0/u;->a:Luz0/u;

    .line 23
    .line 24
    iget-object v1, p2, Lku/g;->b:Ljava/lang/Double;

    .line 25
    .line 26
    const/4 v2, 0x1

    .line 27
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    sget-object v0, Luz0/k0;->a:Luz0/k0;

    .line 31
    .line 32
    iget-object v1, p2, Lku/g;->c:Ljava/lang/Integer;

    .line 33
    .line 34
    const/4 v2, 0x2

    .line 35
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    const/4 v1, 0x3

    .line 39
    iget-object v2, p2, Lku/g;->d:Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    sget-object v0, Luz0/q0;->a:Luz0/q0;

    .line 45
    .line 46
    iget-object p2, p2, Lku/g;->e:Ljava/lang/Long;

    .line 47
    .line 48
    const/4 v1, 0x4

    .line 49
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public final typeParametersSerializers()[Lqz0/a;
    .locals 0

    .line 1
    sget-object p0, Luz0/b1;->b:[Lqz0/a;

    .line 2
    .line 3
    return-object p0
.end method
