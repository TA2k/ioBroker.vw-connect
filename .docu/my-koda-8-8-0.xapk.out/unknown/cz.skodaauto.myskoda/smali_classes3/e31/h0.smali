.class public final synthetic Le31/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Le31/h0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Le31/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le31/h0;->a:Le31/h0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.appointmentbooking.base.data.models.AvailableServicesContentResponse"

    .line 11
    .line 12
    const/4 v3, 0x7

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
    const-string v0, "items"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "price"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "recommended"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "serviceId"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "serviceName"

    .line 43
    .line 44
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    const-string v0, "sortNumber"

    .line 48
    .line 49
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 50
    .line 51
    .line 52
    sput-object v1, Le31/h0;->descriptor:Lsz0/g;

    .line 53
    .line 54
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 9

    .line 1
    sget-object p0, Le31/j0;->h:[Llx0/i;

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
    const/4 v2, 0x1

    .line 10
    aget-object p0, p0, v2

    .line 11
    .line 12
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lqz0/a;

    .line 17
    .line 18
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    sget-object v3, Le31/n0;->a:Le31/n0;

    .line 23
    .line 24
    invoke-static {v3}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    sget-object v4, Luz0/g;->a:Luz0/g;

    .line 29
    .line 30
    invoke-static {v4}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    sget-object v6, Luz0/k0;->a:Luz0/k0;

    .line 43
    .line 44
    invoke-static {v6}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    const/4 v7, 0x7

    .line 49
    new-array v7, v7, [Lqz0/a;

    .line 50
    .line 51
    const/4 v8, 0x0

    .line 52
    aput-object v1, v7, v8

    .line 53
    .line 54
    aput-object p0, v7, v2

    .line 55
    .line 56
    const/4 p0, 0x2

    .line 57
    aput-object v3, v7, p0

    .line 58
    .line 59
    const/4 p0, 0x3

    .line 60
    aput-object v4, v7, p0

    .line 61
    .line 62
    const/4 p0, 0x4

    .line 63
    aput-object v5, v7, p0

    .line 64
    .line 65
    const/4 p0, 0x5

    .line 66
    aput-object v0, v7, p0

    .line 67
    .line 68
    const/4 p0, 0x6

    .line 69
    aput-object v6, v7, p0

    .line 70
    .line 71
    return-object v7
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object p0, Le31/h0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Le31/j0;->h:[Llx0/i;

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
    move-object v10, v9

    .line 18
    move-object v11, v10

    .line 19
    move-object v12, v11

    .line 20
    move v3, v1

    .line 21
    :goto_0
    if-eqz v3, :cond_0

    .line 22
    .line 23
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    packed-switch v4, :pswitch_data_0

    .line 28
    .line 29
    .line 30
    new-instance p0, Lqz0/k;

    .line 31
    .line 32
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :pswitch_0
    sget-object v4, Luz0/k0;->a:Luz0/k0;

    .line 37
    .line 38
    const/4 v13, 0x6

    .line 39
    invoke-interface {p1, p0, v13, v4, v12}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    move-object v12, v4

    .line 44
    check-cast v12, Ljava/lang/Integer;

    .line 45
    .line 46
    or-int/lit8 v5, v5, 0x40

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_1
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 50
    .line 51
    const/4 v13, 0x5

    .line 52
    invoke-interface {p1, p0, v13, v4, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    move-object v11, v4

    .line 57
    check-cast v11, Ljava/lang/String;

    .line 58
    .line 59
    or-int/lit8 v5, v5, 0x20

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_2
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 63
    .line 64
    const/4 v13, 0x4

    .line 65
    invoke-interface {p1, p0, v13, v4, v10}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    move-object v10, v4

    .line 70
    check-cast v10, Ljava/lang/String;

    .line 71
    .line 72
    or-int/lit8 v5, v5, 0x10

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_3
    sget-object v4, Luz0/g;->a:Luz0/g;

    .line 76
    .line 77
    const/4 v13, 0x3

    .line 78
    invoke-interface {p1, p0, v13, v4, v9}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    move-object v9, v4

    .line 83
    check-cast v9, Ljava/lang/Boolean;

    .line 84
    .line 85
    or-int/lit8 v5, v5, 0x8

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_4
    sget-object v4, Le31/n0;->a:Le31/n0;

    .line 89
    .line 90
    const/4 v13, 0x2

    .line 91
    invoke-interface {p1, p0, v13, v4, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    move-object v8, v4

    .line 96
    check-cast v8, Le31/p0;

    .line 97
    .line 98
    or-int/lit8 v5, v5, 0x4

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :pswitch_5
    aget-object v4, v0, v1

    .line 102
    .line 103
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    check-cast v4, Lqz0/a;

    .line 108
    .line 109
    invoke-interface {p1, p0, v1, v4, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    move-object v7, v4

    .line 114
    check-cast v7, Ljava/util/List;

    .line 115
    .line 116
    or-int/lit8 v5, v5, 0x2

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :pswitch_6
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 120
    .line 121
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    move-object v6, v4

    .line 126
    check-cast v6, Ljava/lang/String;

    .line 127
    .line 128
    or-int/lit8 v5, v5, 0x1

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :pswitch_7
    move v3, v2

    .line 132
    goto :goto_0

    .line 133
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 134
    .line 135
    .line 136
    new-instance v4, Le31/j0;

    .line 137
    .line 138
    invoke-direct/range {v4 .. v12}, Le31/j0;-><init>(ILjava/lang/String;Ljava/util/List;Le31/p0;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;)V

    .line 139
    .line 140
    .line 141
    return-object v4

    .line 142
    nop

    .line 143
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_7
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
    sget-object p0, Le31/h0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 9

    .line 1
    check-cast p2, Le31/j0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Le31/j0;->g:Ljava/lang/Integer;

    .line 9
    .line 10
    iget-object v0, p2, Le31/j0;->f:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v1, p2, Le31/j0;->e:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v2, p2, Le31/j0;->d:Ljava/lang/Boolean;

    .line 15
    .line 16
    iget-object v3, p2, Le31/j0;->c:Le31/p0;

    .line 17
    .line 18
    iget-object v4, p2, Le31/j0;->b:Ljava/util/List;

    .line 19
    .line 20
    iget-object p2, p2, Le31/j0;->a:Ljava/lang/String;

    .line 21
    .line 22
    sget-object v5, Le31/h0;->descriptor:Lsz0/g;

    .line 23
    .line 24
    invoke-interface {p1, v5}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    sget-object v6, Le31/j0;->h:[Llx0/i;

    .line 29
    .line 30
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    if-eqz v7, :cond_0

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    if-eqz p2, :cond_1

    .line 38
    .line 39
    :goto_0
    sget-object v7, Luz0/q1;->a:Luz0/q1;

    .line 40
    .line 41
    const/4 v8, 0x0

    .line 42
    invoke-interface {p1, v5, v8, v7, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    if-eqz v4, :cond_3

    .line 53
    .line 54
    :goto_1
    const/4 p2, 0x1

    .line 55
    aget-object v6, v6, p2

    .line 56
    .line 57
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    check-cast v6, Lqz0/a;

    .line 62
    .line 63
    invoke-interface {p1, v5, p2, v6, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_3
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    if-eqz v3, :cond_5

    .line 74
    .line 75
    :goto_2
    sget-object p2, Le31/n0;->a:Le31/n0;

    .line 76
    .line 77
    const/4 v4, 0x2

    .line 78
    invoke-interface {p1, v5, v4, p2, v3}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_5
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    if-eqz p2, :cond_6

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_6
    if-eqz v2, :cond_7

    .line 89
    .line 90
    :goto_3
    sget-object p2, Luz0/g;->a:Luz0/g;

    .line 91
    .line 92
    const/4 v3, 0x3

    .line 93
    invoke-interface {p1, v5, v3, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_7
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 97
    .line 98
    .line 99
    move-result p2

    .line 100
    if-eqz p2, :cond_8

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_8
    if-eqz v1, :cond_9

    .line 104
    .line 105
    :goto_4
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 106
    .line 107
    const/4 v2, 0x4

    .line 108
    invoke-interface {p1, v5, v2, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_9
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    if-eqz p2, :cond_a

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_a
    if-eqz v0, :cond_b

    .line 119
    .line 120
    :goto_5
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 121
    .line 122
    const/4 v1, 0x5

    .line 123
    invoke-interface {p1, v5, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_b
    invoke-interface {p1, v5}, Ltz0/b;->e(Lsz0/g;)Z

    .line 127
    .line 128
    .line 129
    move-result p2

    .line 130
    if-eqz p2, :cond_c

    .line 131
    .line 132
    goto :goto_6

    .line 133
    :cond_c
    if-eqz p0, :cond_d

    .line 134
    .line 135
    :goto_6
    sget-object p2, Luz0/k0;->a:Luz0/k0;

    .line 136
    .line 137
    const/4 v0, 0x6

    .line 138
    invoke-interface {p1, v5, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    :cond_d
    invoke-interface {p1, v5}, Ltz0/b;->b(Lsz0/g;)V

    .line 142
    .line 143
    .line 144
    return-void
.end method
