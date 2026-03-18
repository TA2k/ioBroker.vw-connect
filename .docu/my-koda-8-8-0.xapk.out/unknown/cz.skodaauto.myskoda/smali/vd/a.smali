.class public final synthetic Lvd/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lvd/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lvd/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvd/a;->a:Lvd/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.coupons.models.BffCoupon"

    .line 11
    .line 12
    const/16 v3, 0x8

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "formattedExpirationDate"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "code"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "formattedRemainingCredit"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "originalCreditLabel"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "formattedOriginalCredit"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "redemptionDateLabel"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "formattedRedemptionDate"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "showExpirationWarning"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    sput-object v1, Lvd/a;->descriptor:Lsz0/g;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    const/16 p0, 0x8

    .line 2
    .line 3
    new-array p0, p0, [Lqz0/a;

    .line 4
    .line 5
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    aput-object v0, p0, v1

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    aput-object v0, p0, v1

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    aput-object v0, p0, v1

    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    aput-object v0, p0, v1

    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    aput-object v0, p0, v1

    .line 21
    .line 22
    const/4 v1, 0x5

    .line 23
    aput-object v0, p0, v1

    .line 24
    .line 25
    const/4 v1, 0x6

    .line 26
    aput-object v0, p0, v1

    .line 27
    .line 28
    sget-object v0, Luz0/g;->a:Luz0/g;

    .line 29
    .line 30
    const/4 v1, 0x7

    .line 31
    aput-object v0, p0, v1

    .line 32
    .line 33
    return-object p0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lvd/a;->descriptor:Lsz0/g;

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
    move v12, v4

    .line 12
    move-object v5, v2

    .line 13
    move-object v6, v5

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
    const/4 v3, 0x7

    .line 36
    invoke-interface {p1, p0, v3}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 37
    .line 38
    .line 39
    move-result v12

    .line 40
    or-int/lit16 v4, v4, 0x80

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_1
    const/4 v3, 0x6

    .line 44
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v11

    .line 48
    or-int/lit8 v4, v4, 0x40

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_2
    const/4 v3, 0x5

    .line 52
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v10

    .line 56
    or-int/lit8 v4, v4, 0x20

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :pswitch_3
    const/4 v3, 0x4

    .line 60
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v9

    .line 64
    or-int/lit8 v4, v4, 0x10

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_4
    const/4 v3, 0x3

    .line 68
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    or-int/lit8 v4, v4, 0x8

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_5
    const/4 v3, 0x2

    .line 76
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    or-int/lit8 v4, v4, 0x4

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_6
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v6

    .line 87
    or-int/lit8 v4, v4, 0x2

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :pswitch_7
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    or-int/lit8 v4, v4, 0x1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_8
    move v2, v1

    .line 98
    goto :goto_0

    .line 99
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 100
    .line 101
    .line 102
    new-instance v3, Lvd/c;

    .line 103
    .line 104
    invoke-direct/range {v3 .. v12}, Lvd/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 105
    .line 106
    .line 107
    return-object v3

    .line 108
    nop

    .line 109
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
    sget-object p0, Lvd/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Lvd/c;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lvd/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const/4 v0, 0x0

    .line 15
    iget-object v1, p2, Lvd/c;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    iget-object v1, p2, Lvd/c;->b:Ljava/lang/String;

    .line 22
    .line 23
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x2

    .line 27
    iget-object v1, p2, Lvd/c;->c:Ljava/lang/String;

    .line 28
    .line 29
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x3

    .line 33
    iget-object v1, p2, Lvd/c;->d:Ljava/lang/String;

    .line 34
    .line 35
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 v0, 0x4

    .line 39
    iget-object v1, p2, Lvd/c;->e:Ljava/lang/String;

    .line 40
    .line 41
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const/4 v0, 0x5

    .line 45
    iget-object v1, p2, Lvd/c;->f:Ljava/lang/String;

    .line 46
    .line 47
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const/4 v0, 0x6

    .line 51
    iget-object v1, p2, Lvd/c;->g:Ljava/lang/String;

    .line 52
    .line 53
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const/4 v0, 0x7

    .line 57
    iget-boolean p2, p2, Lvd/c;->h:Z

    .line 58
    .line 59
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 60
    .line 61
    .line 62
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 63
    .line 64
    .line 65
    return-void
.end method
