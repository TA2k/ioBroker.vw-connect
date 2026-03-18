.class public final synthetic Lnj/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lnj/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lnj/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnj/a;->a:Lnj/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.sdk.headless.subscription.internal.models.HeadlessSubscription"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "status"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "displayName"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "id"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "expiryDate"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "isPlugAndChargeCapable"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "plugAndCharge"

    .line 43
    .line 44
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 45
    .line 46
    .line 47
    sput-object v1, Lnj/a;->descriptor:Lsz0/g;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    sget-object p0, Lnj/e;->g:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x6

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget-object p0, p0, v1

    .line 8
    .line 9
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    aput-object p0, v0, v1

    .line 14
    .line 15
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    aput-object p0, v0, v1

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    aput-object p0, v0, v1

    .line 22
    .line 23
    const/4 p0, 0x3

    .line 24
    sget-object v1, Lmz0/f;->a:Lmz0/f;

    .line 25
    .line 26
    aput-object v1, v0, p0

    .line 27
    .line 28
    const/4 p0, 0x4

    .line 29
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 30
    .line 31
    aput-object v1, v0, p0

    .line 32
    .line 33
    sget-object p0, Llj/a;->a:Llj/a;

    .line 34
    .line 35
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const/4 v1, 0x5

    .line 40
    aput-object p0, v0, v1

    .line 41
    .line 42
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lnj/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lnj/e;->g:[Llx0/i;

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
    move-object v11, v9

    .line 19
    move v3, v1

    .line 20
    :goto_0
    if-eqz v3, :cond_0

    .line 21
    .line 22
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    packed-switch v4, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    new-instance p0, Lqz0/k;

    .line 30
    .line 31
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :pswitch_0
    sget-object v4, Llj/a;->a:Llj/a;

    .line 36
    .line 37
    const/4 v12, 0x5

    .line 38
    invoke-interface {p1, p0, v12, v4, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    move-object v11, v4

    .line 43
    check-cast v11, Llj/e;

    .line 44
    .line 45
    or-int/lit8 v5, v5, 0x20

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    const/4 v4, 0x4

    .line 49
    invoke-interface {p1, p0, v4}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 50
    .line 51
    .line 52
    move-result v10

    .line 53
    or-int/lit8 v5, v5, 0x10

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :pswitch_2
    sget-object v4, Lmz0/f;->a:Lmz0/f;

    .line 57
    .line 58
    const/4 v12, 0x3

    .line 59
    invoke-interface {p1, p0, v12, v4, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    move-object v9, v4

    .line 64
    check-cast v9, Lgz0/p;

    .line 65
    .line 66
    or-int/lit8 v5, v5, 0x8

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_3
    const/4 v4, 0x2

    .line 70
    invoke-interface {p1, p0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v8

    .line 74
    or-int/lit8 v5, v5, 0x4

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :pswitch_4
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    or-int/lit8 v5, v5, 0x2

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :pswitch_5
    aget-object v4, v0, v2

    .line 85
    .line 86
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    check-cast v4, Lqz0/a;

    .line 91
    .line 92
    invoke-interface {p1, p0, v2, v4, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    move-object v6, v4

    .line 97
    check-cast v6, Lnj/d;

    .line 98
    .line 99
    or-int/lit8 v5, v5, 0x1

    .line 100
    .line 101
    goto :goto_0

    .line 102
    :pswitch_6
    move v3, v2

    .line 103
    goto :goto_0

    .line 104
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 105
    .line 106
    .line 107
    new-instance v4, Lnj/e;

    .line 108
    .line 109
    invoke-direct/range {v4 .. v11}, Lnj/e;-><init>(ILnj/d;Ljava/lang/String;Ljava/lang/String;Lgz0/p;ZLlj/e;)V

    .line 110
    .line 111
    .line 112
    return-object v4

    .line 113
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
    sget-object p0, Lnj/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lnj/e;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lnj/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lnj/e;->g:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v0, v0, v1

    .line 18
    .line 19
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lqz0/a;

    .line 24
    .line 25
    iget-object v2, p2, Lnj/e;->a:Lnj/d;

    .line 26
    .line 27
    invoke-interface {p1, p0, v1, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    iget-object v1, p2, Lnj/e;->b:Ljava/lang/String;

    .line 32
    .line 33
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const/4 v0, 0x2

    .line 37
    iget-object v1, p2, Lnj/e;->c:Ljava/lang/String;

    .line 38
    .line 39
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    sget-object v0, Lmz0/f;->a:Lmz0/f;

    .line 43
    .line 44
    iget-object v1, p2, Lnj/e;->d:Lgz0/p;

    .line 45
    .line 46
    const/4 v2, 0x3

    .line 47
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    const/4 v0, 0x4

    .line 51
    iget-boolean v1, p2, Lnj/e;->e:Z

    .line 52
    .line 53
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 54
    .line 55
    .line 56
    sget-object v0, Llj/a;->a:Llj/a;

    .line 57
    .line 58
    iget-object p2, p2, Lnj/e;->f:Llj/e;

    .line 59
    .line 60
    const/4 v1, 0x5

    .line 61
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 65
    .line 66
    .line 67
    return-void
.end method
