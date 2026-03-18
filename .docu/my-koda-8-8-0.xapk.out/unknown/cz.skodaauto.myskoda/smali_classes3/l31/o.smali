.class public final synthetic Ll31/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Ll31/o;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ll31/o;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ll31/o;->a:Ll31/o;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.appointmentbooking.base.navigation.ModuleVersionRouterRoute"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "version"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "mock"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "odometer"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "isElectric"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "mslVersion"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "sboVersion"

    .line 43
    .line 44
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    sput-object v1, Ll31/o;->descriptor:Lsz0/g;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 6

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
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 8
    .line 9
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/4 v4, 0x6

    .line 22
    new-array v4, v4, [Lqz0/a;

    .line 23
    .line 24
    const/4 v5, 0x0

    .line 25
    aput-object v0, v4, v5

    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    aput-object v1, v4, v0

    .line 29
    .line 30
    sget-object v0, Luz0/k0;->a:Luz0/k0;

    .line 31
    .line 32
    const/4 v1, 0x2

    .line 33
    aput-object v0, v4, v1

    .line 34
    .line 35
    const/4 v0, 0x3

    .line 36
    aput-object v2, v4, v0

    .line 37
    .line 38
    const/4 v0, 0x4

    .line 39
    aput-object v3, v4, v0

    .line 40
    .line 41
    const/4 v0, 0x5

    .line 42
    aput-object p0, v4, v0

    .line 43
    .line 44
    return-object v4
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Ll31/o;->descriptor:Lsz0/g;

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
    move v6, v4

    .line 12
    move v7, v6

    .line 13
    move-object v5, v2

    .line 14
    move-object v8, v5

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
    sget-object v3, Luz0/q1;->a:Luz0/q1;

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
    check-cast v10, Ljava/lang/String;

    .line 42
    .line 43
    or-int/lit8 v4, v4, 0x20

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    sget-object v3, Luz0/q1;->a:Luz0/q1;

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
    check-cast v9, Ljava/lang/String;

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
    const/4 v3, 0x2

    .line 73
    invoke-interface {p1, p0, v3}, Ltz0/a;->l(Lsz0/g;I)I

    .line 74
    .line 75
    .line 76
    move-result v7

    .line 77
    or-int/lit8 v4, v4, 0x4

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_4
    invoke-interface {p1, p0, v0}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 81
    .line 82
    .line 83
    move-result v6

    .line 84
    or-int/lit8 v4, v4, 0x2

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :pswitch_5
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 88
    .line 89
    invoke-interface {p1, p0, v1, v3, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    move-object v5, v3

    .line 94
    check-cast v5, Ljava/lang/String;

    .line 95
    .line 96
    or-int/lit8 v4, v4, 0x1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :pswitch_6
    move v2, v1

    .line 100
    goto :goto_0

    .line 101
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 102
    .line 103
    .line 104
    new-instance v3, Ll31/q;

    .line 105
    .line 106
    invoke-direct/range {v3 .. v10}, Ll31/q;-><init>(ILjava/lang/String;ZILjava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    return-object v3

    .line 110
    nop

    .line 111
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
    sget-object p0, Ll31/o;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Ll31/q;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Ll31/q;->f:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p2, Ll31/q;->e:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v1, p2, Ll31/q;->d:Ljava/lang/Boolean;

    .line 13
    .line 14
    iget v2, p2, Ll31/q;->c:I

    .line 15
    .line 16
    iget-boolean v3, p2, Ll31/q;->b:Z

    .line 17
    .line 18
    iget-object p2, p2, Ll31/q;->a:Ljava/lang/String;

    .line 19
    .line 20
    sget-object v4, Ll31/o;->descriptor:Lsz0/g;

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
    const/4 p2, 0x1

    .line 51
    invoke-interface {p1, v4, p2, v3}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 52
    .line 53
    .line 54
    :cond_3
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

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
    const/4 p2, -0x1

    .line 62
    if-eq v2, p2, :cond_5

    .line 63
    .line 64
    :goto_2
    const/4 p2, 0x2

    .line 65
    invoke-interface {p1, p2, v2, v4}, Ltz0/b;->n(IILsz0/g;)V

    .line 66
    .line 67
    .line 68
    :cond_5
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

    .line 69
    .line 70
    .line 71
    move-result p2

    .line 72
    if-eqz p2, :cond_6

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_6
    if-eqz v1, :cond_7

    .line 76
    .line 77
    :goto_3
    sget-object p2, Luz0/g;->a:Luz0/g;

    .line 78
    .line 79
    const/4 v2, 0x3

    .line 80
    invoke-interface {p1, v4, v2, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_7
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

    .line 84
    .line 85
    .line 86
    move-result p2

    .line 87
    if-eqz p2, :cond_8

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_8
    if-eqz v0, :cond_9

    .line 91
    .line 92
    :goto_4
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 93
    .line 94
    const/4 v1, 0x4

    .line 95
    invoke-interface {p1, v4, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    :cond_9
    invoke-interface {p1, v4}, Ltz0/b;->e(Lsz0/g;)Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    if-eqz p2, :cond_a

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_a
    if-eqz p0, :cond_b

    .line 106
    .line 107
    :goto_5
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 108
    .line 109
    const/4 v0, 0x5

    .line 110
    invoke-interface {p1, v4, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_b
    invoke-interface {p1, v4}, Ltz0/b;->b(Lsz0/g;)V

    .line 114
    .line 115
    .line 116
    return-void
.end method
