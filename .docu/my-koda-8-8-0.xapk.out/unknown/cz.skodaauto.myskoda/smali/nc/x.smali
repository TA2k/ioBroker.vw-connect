.class public final synthetic Lnc/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lnc/x;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lnc/x;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnc/x;->a:Lnc/x;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.common.presentation.payment.models.StoredPaymentOption"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "reference"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "iconUrl"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "identifier"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "providerCode"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "providerName"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "expiration"

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    sput-object v1, Lnc/x;->descriptor:Lsz0/g;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lnc/a0;->a:Lnc/a0;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x6

    .line 8
    new-array v1, v1, [Lqz0/a;

    .line 9
    .line 10
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    aput-object v2, v1, v3

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    aput-object v2, v1, v3

    .line 17
    .line 18
    const/4 v3, 0x2

    .line 19
    aput-object p0, v1, v3

    .line 20
    .line 21
    const/4 p0, 0x3

    .line 22
    aput-object v2, v1, p0

    .line 23
    .line 24
    const/4 p0, 0x4

    .line 25
    aput-object v2, v1, p0

    .line 26
    .line 27
    const/4 p0, 0x5

    .line 28
    aput-object v0, v1, p0

    .line 29
    .line 30
    return-object v1
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Lnc/x;->descriptor:Lsz0/g;

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
    sget-object v3, Lnc/a0;->a:Lnc/a0;

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
    check-cast v10, Lnc/c0;

    .line 42
    .line 43
    or-int/lit8 v4, v4, 0x20

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    const/4 v3, 0x4

    .line 47
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v9

    .line 51
    or-int/lit8 v4, v4, 0x10

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_2
    const/4 v3, 0x3

    .line 55
    invoke-interface {p1, p0, v3}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    or-int/lit8 v4, v4, 0x8

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_3
    sget-object v3, Lnc/a0;->a:Lnc/a0;

    .line 63
    .line 64
    const/4 v11, 0x2

    .line 65
    invoke-interface {p1, p0, v11, v3, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    move-object v7, v3

    .line 70
    check-cast v7, Lnc/c0;

    .line 71
    .line 72
    or-int/lit8 v4, v4, 0x4

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_4
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    or-int/lit8 v4, v4, 0x2

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :pswitch_5
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    or-int/lit8 v4, v4, 0x1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :pswitch_6
    move v2, v1

    .line 90
    goto :goto_0

    .line 91
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 92
    .line 93
    .line 94
    new-instance v3, Lnc/z;

    .line 95
    .line 96
    invoke-direct/range {v3 .. v10}, Lnc/z;-><init>(ILjava/lang/String;Ljava/lang/String;Lnc/c0;Ljava/lang/String;Ljava/lang/String;Lnc/c0;)V

    .line 97
    .line 98
    .line 99
    return-object v3

    .line 100
    nop

    .line 101
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
    sget-object p0, Lnc/x;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lnc/z;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lnc/x;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object v0, p2, Lnc/z;->d:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v1, p2, Lnc/z;->i:Lnc/c0;

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
    iget-object v2, p2, Lnc/z;->e:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {p1, p0, v0, v2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    sget-object v0, Lnc/a0;->a:Lnc/a0;

    .line 29
    .line 30
    iget-object v2, p2, Lnc/z;->f:Lnc/c0;

    .line 31
    .line 32
    const/4 v3, 0x2

    .line 33
    invoke-interface {p1, p0, v3, v0, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    const/4 v2, 0x3

    .line 37
    iget-object v3, p2, Lnc/z;->g:Ljava/lang/String;

    .line 38
    .line 39
    invoke-interface {p1, p0, v2, v3}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const/4 v2, 0x4

    .line 43
    iget-object p2, p2, Lnc/z;->h:Ljava/lang/String;

    .line 44
    .line 45
    invoke-interface {p1, p0, v2, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    if-eqz p2, :cond_0

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_0
    if-eqz v1, :cond_1

    .line 56
    .line 57
    :goto_0
    const/4 p2, 0x5

    .line 58
    invoke-interface {p1, p0, p2, v0, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method
