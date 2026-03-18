.class public final synthetic Lcd/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lcd/l;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcd/l;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcd/l;->a:Lcd/l;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.charginghistory.models.home.HomeChargingHistoryRequest.HomeChargingHistoryRequestFilters"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "stationId"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "rfidCardId"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "startDateTimeAfter"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "startDateTimeBefore"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "startedByApp"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Lcd/l;->descriptor:Lsz0/g;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 6

    .line 1
    sget-object p0, Lcd/n;->f:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aget-object v1, p0, v0

    .line 5
    .line 6
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Lqz0/a;

    .line 11
    .line 12
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/4 v2, 0x1

    .line 17
    aget-object p0, p0, v2

    .line 18
    .line 19
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lqz0/a;

    .line 24
    .line 25
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object v3, Lmz0/f;->a:Lmz0/f;

    .line 30
    .line 31
    invoke-static {v3}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    invoke-static {v3}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    const/4 v5, 0x5

    .line 40
    new-array v5, v5, [Lqz0/a;

    .line 41
    .line 42
    aput-object v1, v5, v0

    .line 43
    .line 44
    aput-object p0, v5, v2

    .line 45
    .line 46
    const/4 p0, 0x2

    .line 47
    aput-object v4, v5, p0

    .line 48
    .line 49
    const/4 p0, 0x3

    .line 50
    aput-object v3, v5, p0

    .line 51
    .line 52
    sget-object p0, Luz0/g;->a:Luz0/g;

    .line 53
    .line 54
    const/4 v0, 0x4

    .line 55
    aput-object p0, v5, v0

    .line 56
    .line 57
    return-object v5
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Lcd/l;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lcd/n;->f:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v5, v2

    .line 13
    move v10, v5

    .line 14
    move-object v6, v3

    .line 15
    move-object v7, v6

    .line 16
    move-object v8, v7

    .line 17
    move-object v9, v8

    .line 18
    move v3, v1

    .line 19
    :goto_0
    if-eqz v3, :cond_6

    .line 20
    .line 21
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    const/4 v11, -0x1

    .line 26
    if-eq v4, v11, :cond_5

    .line 27
    .line 28
    if-eqz v4, :cond_4

    .line 29
    .line 30
    if-eq v4, v1, :cond_3

    .line 31
    .line 32
    const/4 v11, 0x2

    .line 33
    if-eq v4, v11, :cond_2

    .line 34
    .line 35
    const/4 v11, 0x3

    .line 36
    if-eq v4, v11, :cond_1

    .line 37
    .line 38
    const/4 v10, 0x4

    .line 39
    if-ne v4, v10, :cond_0

    .line 40
    .line 41
    invoke-interface {p1, p0, v10}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 42
    .line 43
    .line 44
    move-result v10

    .line 45
    or-int/lit8 v5, v5, 0x10

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    new-instance p0, Lqz0/k;

    .line 49
    .line 50
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_1
    sget-object v4, Lmz0/f;->a:Lmz0/f;

    .line 55
    .line 56
    invoke-interface {p1, p0, v11, v4, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    move-object v9, v4

    .line 61
    check-cast v9, Lgz0/p;

    .line 62
    .line 63
    or-int/lit8 v5, v5, 0x8

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    sget-object v4, Lmz0/f;->a:Lmz0/f;

    .line 67
    .line 68
    invoke-interface {p1, p0, v11, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    move-object v8, v4

    .line 73
    check-cast v8, Lgz0/p;

    .line 74
    .line 75
    or-int/lit8 v5, v5, 0x4

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_3
    aget-object v4, v0, v1

    .line 79
    .line 80
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    check-cast v4, Lqz0/a;

    .line 85
    .line 86
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    move-object v7, v4

    .line 91
    check-cast v7, Ljava/util/List;

    .line 92
    .line 93
    or-int/lit8 v5, v5, 0x2

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_4
    aget-object v4, v0, v2

    .line 97
    .line 98
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    check-cast v4, Lqz0/a;

    .line 103
    .line 104
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    move-object v6, v4

    .line 109
    check-cast v6, Ljava/util/List;

    .line 110
    .line 111
    or-int/lit8 v5, v5, 0x1

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_5
    move v3, v2

    .line 115
    goto :goto_0

    .line 116
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 117
    .line 118
    .line 119
    new-instance v4, Lcd/n;

    .line 120
    .line 121
    invoke-direct/range {v4 .. v10}, Lcd/n;-><init>(ILjava/util/List;Ljava/util/List;Lgz0/p;Lgz0/p;Z)V

    .line 122
    .line 123
    .line 124
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lcd/l;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Lcd/n;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean p0, p2, Lcd/n;->e:Z

    .line 9
    .line 10
    iget-object v0, p2, Lcd/n;->d:Lgz0/p;

    .line 11
    .line 12
    iget-object v1, p2, Lcd/n;->c:Lgz0/p;

    .line 13
    .line 14
    iget-object v2, p2, Lcd/n;->b:Ljava/util/List;

    .line 15
    .line 16
    iget-object p2, p2, Lcd/n;->a:Ljava/util/List;

    .line 17
    .line 18
    sget-object v3, Lcd/l;->descriptor:Lsz0/g;

    .line 19
    .line 20
    invoke-interface {p1, v3}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    sget-object v4, Lcd/n;->f:[Llx0/i;

    .line 25
    .line 26
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    if-eqz p2, :cond_1

    .line 34
    .line 35
    :goto_0
    const/4 v5, 0x0

    .line 36
    aget-object v6, v4, v5

    .line 37
    .line 38
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    check-cast v6, Lqz0/a;

    .line 43
    .line 44
    invoke-interface {p1, v3, v5, v6, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-eqz p2, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    if-eqz v2, :cond_3

    .line 55
    .line 56
    :goto_1
    const/4 p2, 0x1

    .line 57
    aget-object v4, v4, p2

    .line 58
    .line 59
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v4, Lqz0/a;

    .line 64
    .line 65
    invoke-interface {p1, v3, p2, v4, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    :cond_3
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    if-eqz p2, :cond_4

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_4
    if-eqz v1, :cond_5

    .line 76
    .line 77
    :goto_2
    sget-object p2, Lmz0/f;->a:Lmz0/f;

    .line 78
    .line 79
    const/4 v2, 0x2

    .line 80
    invoke-interface {p1, v3, v2, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_5
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    if-eqz p2, :cond_6

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_6
    if-eqz v0, :cond_7

    .line 91
    .line 92
    :goto_3
    sget-object p2, Lmz0/f;->a:Lmz0/f;

    .line 93
    .line 94
    const/4 v1, 0x3

    .line 95
    invoke-interface {p1, v3, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    :cond_7
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    if-eqz p2, :cond_8

    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_8
    if-eqz p0, :cond_9

    .line 106
    .line 107
    :goto_4
    const/4 p2, 0x4

    .line 108
    invoke-interface {p1, v3, p2, p0}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 109
    .line 110
    .line 111
    :cond_9
    invoke-interface {p1, v3}, Ltz0/b;->b(Lsz0/g;)V

    .line 112
    .line 113
    .line 114
    return-void
.end method
