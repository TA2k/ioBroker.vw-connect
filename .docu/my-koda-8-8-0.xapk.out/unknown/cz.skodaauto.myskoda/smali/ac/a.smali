.class public final synthetic Lac/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lac/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lac/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lac/a;->a:Lac/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.common.presentation.addressforms.Address"

    .line 11
    .line 12
    const/16 v3, 0x8

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "firstName"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "lastName"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "addressLine1"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "zip"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "city"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "state"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "countryCode"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "addressLine2"

    .line 54
    .line 55
    const/4 v2, 0x1

    .line 56
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 57
    .line 58
    .line 59
    sput-object v1, Lac/a;->descriptor:Lsz0/g;

    .line 60
    .line 61
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

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
    const/16 v1, 0x8

    .line 8
    .line 9
    new-array v1, v1, [Lqz0/a;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    aput-object p0, v1, v2

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    aput-object p0, v1, v2

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    aput-object p0, v1, v2

    .line 19
    .line 20
    const/4 v2, 0x3

    .line 21
    aput-object p0, v1, v2

    .line 22
    .line 23
    const/4 v2, 0x4

    .line 24
    aput-object p0, v1, v2

    .line 25
    .line 26
    const/4 v2, 0x5

    .line 27
    aput-object p0, v1, v2

    .line 28
    .line 29
    const/4 v2, 0x6

    .line 30
    aput-object p0, v1, v2

    .line 31
    .line 32
    const/4 p0, 0x7

    .line 33
    aput-object v0, v1, p0

    .line 34
    .line 35
    return-object v1
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    sget-object p0, Lac/a;->descriptor:Lsz0/g;

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
    move-object v11, v10

    .line 18
    move-object v12, v11

    .line 19
    move v2, v0

    .line 20
    :goto_0
    if-eqz v2, :cond_0

    .line 21
    .line 22
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    packed-switch v3, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    new-instance p0, Lqz0/k;

    .line 30
    .line 31
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :pswitch_0
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 36
    .line 37
    const/4 v13, 0x7

    .line 38
    invoke-interface {p1, p0, v13, v3, v12}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    move-object v12, v3

    .line 43
    check-cast v12, Ljava/lang/String;

    .line 44
    .line 45
    or-int/lit16 v4, v4, 0x80

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    const/4 v3, 0x6

    .line 49
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v11

    .line 53
    or-int/lit8 v4, v4, 0x40

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :pswitch_2
    const/4 v3, 0x5

    .line 57
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v10

    .line 61
    or-int/lit8 v4, v4, 0x20

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :pswitch_3
    const/4 v3, 0x4

    .line 65
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    or-int/lit8 v4, v4, 0x10

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_4
    const/4 v3, 0x3

    .line 73
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    or-int/lit8 v4, v4, 0x8

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_5
    const/4 v3, 0x2

    .line 81
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    or-int/lit8 v4, v4, 0x4

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_6
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    or-int/lit8 v4, v4, 0x2

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :pswitch_7
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    or-int/lit8 v4, v4, 0x1

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :pswitch_8
    move v2, v1

    .line 103
    goto :goto_0

    .line 104
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 105
    .line 106
    .line 107
    new-instance v3, Lac/c;

    .line 108
    .line 109
    invoke-direct/range {v3 .. v12}, Lac/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    return-object v3

    .line 113
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_8
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
    sget-object p0, Lac/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lac/c;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lac/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v0, p2, Lac/c;->a:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v1, p2, Lac/c;->h:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-interface {p1, p0, v2, v0}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    iget-object v2, p2, Lac/c;->b:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    iget-object v2, p2, Lac/c;->c:Ljava/lang/String;

    .line 30
    .line 31
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const/4 v0, 0x3

    .line 35
    iget-object v2, p2, Lac/c;->d:Ljava/lang/String;

    .line 36
    .line 37
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x4

    .line 41
    iget-object v2, p2, Lac/c;->e:Ljava/lang/String;

    .line 42
    .line 43
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const/4 v0, 0x5

    .line 47
    iget-object v2, p2, Lac/c;->f:Ljava/lang/String;

    .line 48
    .line 49
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const/4 v0, 0x6

    .line 53
    iget-object p2, p2, Lac/c;->g:Ljava/lang/String;

    .line 54
    .line 55
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    if-eqz p2, :cond_0

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    if-eqz v1, :cond_1

    .line 66
    .line 67
    :goto_0
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 68
    .line 69
    const/4 v0, 0x7

    .line 70
    invoke-interface {p1, p0, v0, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 74
    .line 75
    .line 76
    return-void
.end method
