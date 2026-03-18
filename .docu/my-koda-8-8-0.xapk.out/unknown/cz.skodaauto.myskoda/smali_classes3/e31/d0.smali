.class public final synthetic Le31/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Le31/d0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Le31/d0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le31/d0;->a:Le31/d0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.appointmentbooking.base.data.models.AvailableCapacityResponse.Slot"

    .line 11
    .line 12
    const/4 v3, 0x5

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "start"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "end"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "expectedReturnTime"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "startLocalTime"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "availableSaIds"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    sput-object v1, Le31/d0;->descriptor:Lsz0/g;

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 7

    .line 1
    sget-object p0, Le31/f0;->f:[Llx0/i;

    .line 2
    .line 3
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 4
    .line 5
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const/4 v4, 0x4

    .line 22
    aget-object p0, p0, v4

    .line 23
    .line 24
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lqz0/a;

    .line 29
    .line 30
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const/4 v5, 0x5

    .line 35
    new-array v5, v5, [Lqz0/a;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    aput-object v1, v5, v6

    .line 39
    .line 40
    const/4 v1, 0x1

    .line 41
    aput-object v2, v5, v1

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    aput-object v3, v5, v1

    .line 45
    .line 46
    const/4 v1, 0x3

    .line 47
    aput-object v0, v5, v1

    .line 48
    .line 49
    aput-object p0, v5, v4

    .line 50
    .line 51
    return-object v5
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Le31/d0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Le31/f0;->f:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v9, v2

    .line 13
    move-object v5, v3

    .line 14
    move-object v6, v5

    .line 15
    move-object v7, v6

    .line 16
    move-object v8, v7

    .line 17
    move-object v10, v8

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
    const/4 v11, 0x4

    .line 39
    if-ne v4, v11, :cond_0

    .line 40
    .line 41
    aget-object v4, v0, v11

    .line 42
    .line 43
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    check-cast v4, Lqz0/a;

    .line 48
    .line 49
    invoke-interface {p1, p0, v11, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    move-object v10, v4

    .line 54
    check-cast v10, Ljava/util/List;

    .line 55
    .line 56
    or-int/lit8 v9, v9, 0x10

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    new-instance p0, Lqz0/k;

    .line 60
    .line 61
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_1
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 66
    .line 67
    invoke-interface {p1, p0, v11, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    move-object v8, v4

    .line 72
    check-cast v8, Ljava/lang/String;

    .line 73
    .line 74
    or-int/lit8 v9, v9, 0x8

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 78
    .line 79
    invoke-interface {p1, p0, v11, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    move-object v7, v4

    .line 84
    check-cast v7, Ljava/lang/String;

    .line 85
    .line 86
    or-int/lit8 v9, v9, 0x4

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_3
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 90
    .line 91
    invoke-interface {p1, p0, v1, v4, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    move-object v6, v4

    .line 96
    check-cast v6, Ljava/lang/String;

    .line 97
    .line 98
    or-int/lit8 v9, v9, 0x2

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_4
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 102
    .line 103
    invoke-interface {p1, p0, v2, v4, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    move-object v5, v4

    .line 108
    check-cast v5, Ljava/lang/String;

    .line 109
    .line 110
    or-int/lit8 v9, v9, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_5
    move v3, v2

    .line 114
    goto :goto_0

    .line 115
    :cond_6
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 116
    .line 117
    .line 118
    new-instance v4, Le31/f0;

    .line 119
    .line 120
    invoke-direct/range {v4 .. v10}, Le31/f0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/util/List;)V

    .line 121
    .line 122
    .line 123
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Le31/d0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Le31/f0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Le31/f0;->e:Ljava/util/List;

    .line 9
    .line 10
    iget-object v0, p2, Le31/f0;->d:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v1, p2, Le31/f0;->c:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v2, p2, Le31/f0;->b:Ljava/lang/String;

    .line 15
    .line 16
    iget-object p2, p2, Le31/f0;->a:Ljava/lang/String;

    .line 17
    .line 18
    sget-object v3, Le31/d0;->descriptor:Lsz0/g;

    .line 19
    .line 20
    invoke-interface {p1, v3}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    sget-object v4, Le31/f0;->f:[Llx0/i;

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
    sget-object v5, Luz0/q1;->a:Luz0/q1;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    invoke-interface {p1, v3, v6, v5, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    if-eqz p2, :cond_2

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    if-eqz v2, :cond_3

    .line 49
    .line 50
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 51
    .line 52
    const/4 v5, 0x1

    .line 53
    invoke-interface {p1, v3, v5, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_3
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    if-eqz p2, :cond_4

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_4
    if-eqz v1, :cond_5

    .line 64
    .line 65
    :goto_2
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 66
    .line 67
    const/4 v2, 0x2

    .line 68
    invoke-interface {p1, v3, v2, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_5
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    if-eqz p2, :cond_6

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_6
    if-eqz v0, :cond_7

    .line 79
    .line 80
    :goto_3
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 81
    .line 82
    const/4 v1, 0x3

    .line 83
    invoke-interface {p1, v3, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_7
    invoke-interface {p1, v3}, Ltz0/b;->e(Lsz0/g;)Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    if-eqz p2, :cond_8

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_8
    if-eqz p0, :cond_9

    .line 94
    .line 95
    :goto_4
    const/4 p2, 0x4

    .line 96
    aget-object v0, v4, p2

    .line 97
    .line 98
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    check-cast v0, Lqz0/a;

    .line 103
    .line 104
    invoke-interface {p1, v3, p2, v0, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    :cond_9
    invoke-interface {p1, v3}, Ltz0/b;->b(Lsz0/g;)V

    .line 108
    .line 109
    .line 110
    return-void
.end method
