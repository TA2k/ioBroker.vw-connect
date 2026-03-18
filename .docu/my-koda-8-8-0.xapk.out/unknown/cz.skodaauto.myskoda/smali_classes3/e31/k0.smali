.class public final synthetic Le31/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Le31/k0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Le31/k0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le31/k0;->a:Le31/k0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.appointmentbooking.base.data.models.AvailableServicesItemResponse"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "description"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "itemId"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "itemName"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "mandatory"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "price"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "sortNumber"

    .line 43
    .line 44
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    sput-object v1, Le31/k0;->descriptor:Lsz0/g;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 7

    .line 1
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object v2, Luz0/g;->a:Luz0/g;

    .line 16
    .line 17
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    sget-object v3, Le31/n0;->a:Le31/n0;

    .line 22
    .line 23
    invoke-static {v3}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    sget-object v4, Luz0/k0;->a:Luz0/k0;

    .line 28
    .line 29
    invoke-static {v4}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    const/4 v5, 0x6

    .line 34
    new-array v5, v5, [Lqz0/a;

    .line 35
    .line 36
    const/4 v6, 0x0

    .line 37
    aput-object v0, v5, v6

    .line 38
    .line 39
    const/4 v0, 0x1

    .line 40
    aput-object v1, v5, v0

    .line 41
    .line 42
    const/4 v0, 0x2

    .line 43
    aput-object p0, v5, v0

    .line 44
    .line 45
    const/4 p0, 0x3

    .line 46
    aput-object v2, v5, p0

    .line 47
    .line 48
    const/4 p0, 0x4

    .line 49
    aput-object v3, v5, p0

    .line 50
    .line 51
    const/4 p0, 0x5

    .line 52
    aput-object v4, v5, p0

    .line 53
    .line 54
    return-object v5
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Le31/k0;->descriptor:Lsz0/g;

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
    move-object v10, v9

    .line 17
    move v2, v0

    .line 18
    :goto_0
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    packed-switch v3, :pswitch_data_0

    .line 25
    .line 26
    .line 27
    new-instance p0, Lqz0/k;

    .line 28
    .line 29
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :pswitch_0
    sget-object v3, Luz0/k0;->a:Luz0/k0;

    .line 34
    .line 35
    const/4 v11, 0x5

    .line 36
    invoke-interface {p1, p0, v11, v3, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    move-object v10, v3

    .line 41
    check-cast v10, Ljava/lang/Integer;

    .line 42
    .line 43
    or-int/lit8 v4, v4, 0x20

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    sget-object v3, Le31/n0;->a:Le31/n0;

    .line 47
    .line 48
    const/4 v11, 0x4

    .line 49
    invoke-interface {p1, p0, v11, v3, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    move-object v9, v3

    .line 54
    check-cast v9, Le31/p0;

    .line 55
    .line 56
    or-int/lit8 v4, v4, 0x10

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :pswitch_2
    sget-object v3, Luz0/g;->a:Luz0/g;

    .line 60
    .line 61
    const/4 v11, 0x3

    .line 62
    invoke-interface {p1, p0, v11, v3, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    move-object v8, v3

    .line 67
    check-cast v8, Ljava/lang/Boolean;

    .line 68
    .line 69
    or-int/lit8 v4, v4, 0x8

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_3
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 73
    .line 74
    const/4 v11, 0x2

    .line 75
    invoke-interface {p1, p0, v11, v3, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    move-object v7, v3

    .line 80
    check-cast v7, Ljava/lang/String;

    .line 81
    .line 82
    or-int/lit8 v4, v4, 0x4

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :pswitch_4
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 86
    .line 87
    invoke-interface {p1, p0, v0, v3, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    move-object v6, v3

    .line 92
    check-cast v6, Ljava/lang/String;

    .line 93
    .line 94
    or-int/lit8 v4, v4, 0x2

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_5
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 98
    .line 99
    invoke-interface {p1, p0, v1, v3, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    move-object v5, v3

    .line 104
    check-cast v5, Ljava/lang/String;

    .line 105
    .line 106
    or-int/lit8 v4, v4, 0x1

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :pswitch_6
    move v2, v1

    .line 110
    goto :goto_0

    .line 111
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 112
    .line 113
    .line 114
    new-instance v3, Le31/m0;

    .line 115
    .line 116
    invoke-direct/range {v3 .. v10}, Le31/m0;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Le31/p0;Ljava/lang/Integer;)V

    .line 117
    .line 118
    .line 119
    return-object v3

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Le31/k0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Le31/m0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Le31/m0;->f:Ljava/lang/Integer;

    .line 9
    .line 10
    iget-object v0, p2, Le31/m0;->e:Le31/p0;

    .line 11
    .line 12
    iget-object v1, p2, Le31/m0;->d:Ljava/lang/Boolean;

    .line 13
    .line 14
    iget-object v2, p2, Le31/m0;->c:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, p2, Le31/m0;->b:Ljava/lang/String;

    .line 17
    .line 18
    iget-object p2, p2, Le31/m0;->a:Ljava/lang/String;

    .line 19
    .line 20
    sget-object v4, Le31/k0;->descriptor:Lsz0/g;

    .line 21
    .line 22
    invoke-interface {p1, v4}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

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
    invoke-interface {p1, v4, v6, v5, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

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
    if-eqz v3, :cond_3

    .line 49
    .line 50
    :goto_1
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 51
    .line 52
    const/4 v5, 0x1

    .line 53
    invoke-interface {p1, v4, v5, p2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_3
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

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
    if-eqz v2, :cond_5

    .line 64
    .line 65
    :goto_2
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 66
    .line 67
    const/4 v3, 0x2

    .line 68
    invoke-interface {p1, v4, v3, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_5
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

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
    if-eqz v1, :cond_7

    .line 79
    .line 80
    :goto_3
    sget-object p2, Luz0/g;->a:Luz0/g;

    .line 81
    .line 82
    const/4 v2, 0x3

    .line 83
    invoke-interface {p1, v4, v2, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_7
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

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
    if-eqz v0, :cond_9

    .line 94
    .line 95
    :goto_4
    sget-object p2, Le31/n0;->a:Le31/n0;

    .line 96
    .line 97
    const/4 v1, 0x4

    .line 98
    invoke-interface {p1, v4, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    :cond_9
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

    .line 102
    .line 103
    .line 104
    move-result p2

    .line 105
    if-eqz p2, :cond_a

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_a
    if-eqz p0, :cond_b

    .line 109
    .line 110
    :goto_5
    sget-object p2, Luz0/k0;->a:Luz0/k0;

    .line 111
    .line 112
    const/4 v0, 0x5

    .line 113
    invoke-interface {p1, v4, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_b
    invoke-interface {p1, v4}, Ltz0/b;->b(Lsz0/g;)V

    .line 117
    .line 118
    .line 119
    return-void
.end method
