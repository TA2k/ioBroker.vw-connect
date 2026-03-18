.class public final synthetic Le31/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Le31/q0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Le31/q0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le31/q0;->a:Le31/q0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.appointmentbooking.base.data.models.AvailableServicesResponse"

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "categoryId"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "categoryName"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "contents"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "sortNumber"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Le31/q0;->descriptor:Lsz0/g;

    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 6

    .line 1
    sget-object p0, Le31/s0;->e:[Llx0/i;

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
    move-result-object v0

    .line 13
    const/4 v2, 0x2

    .line 14
    aget-object p0, p0, v2

    .line 15
    .line 16
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lqz0/a;

    .line 21
    .line 22
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    sget-object v3, Luz0/k0;->a:Luz0/k0;

    .line 27
    .line 28
    invoke-static {v3}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    const/4 v4, 0x4

    .line 33
    new-array v4, v4, [Lqz0/a;

    .line 34
    .line 35
    const/4 v5, 0x0

    .line 36
    aput-object v1, v4, v5

    .line 37
    .line 38
    const/4 v1, 0x1

    .line 39
    aput-object v0, v4, v1

    .line 40
    .line 41
    aput-object p0, v4, v2

    .line 42
    .line 43
    const/4 p0, 0x3

    .line 44
    aput-object v3, v4, p0

    .line 45
    .line 46
    return-object v4
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object p0, Le31/q0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Le31/s0;->e:[Llx0/i;

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
    move-object v6, v3

    .line 14
    move-object v7, v6

    .line 15
    move-object v8, v7

    .line 16
    move-object v9, v8

    .line 17
    move v3, v1

    .line 18
    :goto_0
    if-eqz v3, :cond_5

    .line 19
    .line 20
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    const/4 v10, -0x1

    .line 25
    if-eq v4, v10, :cond_4

    .line 26
    .line 27
    if-eqz v4, :cond_3

    .line 28
    .line 29
    if-eq v4, v1, :cond_2

    .line 30
    .line 31
    const/4 v10, 0x2

    .line 32
    if-eq v4, v10, :cond_1

    .line 33
    .line 34
    const/4 v10, 0x3

    .line 35
    if-ne v4, v10, :cond_0

    .line 36
    .line 37
    sget-object v4, Luz0/k0;->a:Luz0/k0;

    .line 38
    .line 39
    invoke-interface {p1, p0, v10, v4, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    move-object v9, v4

    .line 44
    check-cast v9, Ljava/lang/Integer;

    .line 45
    .line 46
    or-int/lit8 v5, v5, 0x8

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    new-instance p0, Lqz0/k;

    .line 50
    .line 51
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_1
    aget-object v4, v0, v10

    .line 56
    .line 57
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    check-cast v4, Lqz0/a;

    .line 62
    .line 63
    invoke-interface {p1, p0, v10, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    move-object v8, v4

    .line 68
    check-cast v8, Ljava/util/List;

    .line 69
    .line 70
    or-int/lit8 v5, v5, 0x4

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 74
    .line 75
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    move-object v7, v4

    .line 80
    check-cast v7, Ljava/lang/String;

    .line 81
    .line 82
    or-int/lit8 v5, v5, 0x2

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_3
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 86
    .line 87
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    move-object v6, v4

    .line 92
    check-cast v6, Ljava/lang/String;

    .line 93
    .line 94
    or-int/lit8 v5, v5, 0x1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_4
    move v3, v2

    .line 98
    goto :goto_0

    .line 99
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 100
    .line 101
    .line 102
    new-instance v4, Le31/s0;

    .line 103
    .line 104
    invoke-direct/range {v4 .. v9}, Le31/s0;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/Integer;)V

    .line 105
    .line 106
    .line 107
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Le31/q0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Le31/s0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Le31/s0;->d:Ljava/lang/Integer;

    .line 9
    .line 10
    iget-object v0, p2, Le31/s0;->c:Ljava/util/List;

    .line 11
    .line 12
    iget-object v1, p2, Le31/s0;->b:Ljava/lang/String;

    .line 13
    .line 14
    iget-object p2, p2, Le31/s0;->a:Ljava/lang/String;

    .line 15
    .line 16
    sget-object v2, Le31/q0;->descriptor:Lsz0/g;

    .line 17
    .line 18
    invoke-interface {p1, v2}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    sget-object v3, Le31/s0;->e:[Llx0/i;

    .line 23
    .line 24
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-eqz v4, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    if-eqz p2, :cond_1

    .line 32
    .line 33
    :goto_0
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 34
    .line 35
    const/4 v5, 0x0

    .line 36
    invoke-interface {p1, v2, v5, v4, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    :cond_1
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    if-eqz p2, :cond_2

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    if-eqz v1, :cond_3

    .line 47
    .line 48
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 49
    .line 50
    const/4 v4, 0x1

    .line 51
    invoke-interface {p1, v2, v4, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :cond_3
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    if-eqz p2, :cond_4

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_4
    if-eqz v0, :cond_5

    .line 62
    .line 63
    :goto_2
    const/4 p2, 0x2

    .line 64
    aget-object v1, v3, p2

    .line 65
    .line 66
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Lqz0/a;

    .line 71
    .line 72
    invoke-interface {p1, v2, p2, v1, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    :cond_5
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_6

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_6
    if-eqz p0, :cond_7

    .line 83
    .line 84
    :goto_3
    sget-object p2, Luz0/k0;->a:Luz0/k0;

    .line 85
    .line 86
    const/4 v0, 0x3

    .line 87
    invoke-interface {p1, v2, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_7
    invoke-interface {p1, v2}, Ltz0/b;->b(Lsz0/g;)V

    .line 91
    .line 92
    .line 93
    return-void
.end method
