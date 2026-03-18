.class public final synthetic Lah/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lah/t;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lah/t;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lah/t;->a:Lah/t;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.firmware.LatestUpdateProcess"

    .line 11
    .line 12
    const/4 v3, 0x6

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "id"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "version"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "releaseNotesLink"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "updateAttempts"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    const-string v0, "status"

    .line 38
    .line 39
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    const-string v0, "decisionConsent"

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    sput-object v1, Lah/t;->descriptor:Lsz0/g;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lah/x;->g:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x6

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    aput-object v1, v0, v2

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    aput-object v1, v0, v2

    .line 13
    .line 14
    const/4 v2, 0x2

    .line 15
    aput-object v1, v0, v2

    .line 16
    .line 17
    const/4 v1, 0x3

    .line 18
    sget-object v2, Luz0/k0;->a:Luz0/k0;

    .line 19
    .line 20
    aput-object v2, v0, v1

    .line 21
    .line 22
    const/4 v1, 0x4

    .line 23
    aget-object p0, p0, v1

    .line 24
    .line 25
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    aput-object p0, v0, v1

    .line 30
    .line 31
    sget-object p0, Lah/o;->a:Lah/o;

    .line 32
    .line 33
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const/4 v1, 0x5

    .line 38
    aput-object p0, v0, v1

    .line 39
    .line 40
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lah/t;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lah/x;->g:[Llx0/i;

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
    move v9, v5

    .line 14
    move-object v6, v3

    .line 15
    move-object v7, v6

    .line 16
    move-object v8, v7

    .line 17
    move-object v10, v8

    .line 18
    move-object v11, v10

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
    sget-object v4, Lah/o;->a:Lah/o;

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
    check-cast v11, Lah/q;

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
    aget-object v12, v0, v4

    .line 50
    .line 51
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v12

    .line 55
    check-cast v12, Lqz0/a;

    .line 56
    .line 57
    invoke-interface {p1, p0, v4, v12, v10}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    move-object v10, v4

    .line 62
    check-cast v10, Lah/w;

    .line 63
    .line 64
    or-int/lit8 v5, v5, 0x10

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :pswitch_2
    const/4 v4, 0x3

    .line 68
    invoke-interface {p1, p0, v4}, Ltz0/a;->l(Lsz0/g;I)I

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    or-int/lit8 v5, v5, 0x8

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :pswitch_3
    const/4 v4, 0x2

    .line 76
    invoke-interface {p1, p0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v8

    .line 80
    or-int/lit8 v5, v5, 0x4

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :pswitch_4
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v7

    .line 87
    or-int/lit8 v5, v5, 0x2

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :pswitch_5
    invoke-interface {p1, p0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    or-int/lit8 v5, v5, 0x1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :pswitch_6
    move v3, v2

    .line 98
    goto :goto_0

    .line 99
    :cond_0
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 100
    .line 101
    .line 102
    new-instance v4, Lah/x;

    .line 103
    .line 104
    invoke-direct/range {v4 .. v11}, Lah/x;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILah/w;Lah/q;)V

    .line 105
    .line 106
    .line 107
    return-object v4

    .line 108
    nop

    .line 109
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
    sget-object p0, Lah/t;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lah/x;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lah/t;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lah/x;->g:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lah/x;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p2, Lah/x;->f:Lah/q;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-interface {p1, p0, v3, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    iget-object v3, p2, Lah/x;->b:Ljava/lang/String;

    .line 26
    .line 27
    invoke-interface {p1, p0, v1, v3}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const/4 v1, 0x2

    .line 31
    iget-object v3, p2, Lah/x;->c:Ljava/lang/String;

    .line 32
    .line 33
    invoke-interface {p1, p0, v1, v3}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const/4 v1, 0x3

    .line 37
    iget v3, p2, Lah/x;->d:I

    .line 38
    .line 39
    invoke-interface {p1, v1, v3, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 40
    .line 41
    .line 42
    const/4 v1, 0x4

    .line 43
    aget-object v0, v0, v1

    .line 44
    .line 45
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Lqz0/a;

    .line 50
    .line 51
    iget-object p2, p2, Lah/x;->e:Lah/w;

    .line 52
    .line 53
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    if-eqz p2, :cond_0

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    if-eqz v2, :cond_1

    .line 64
    .line 65
    :goto_0
    sget-object p2, Lah/o;->a:Lah/o;

    .line 66
    .line 67
    const/4 v0, 0x5

    .line 68
    invoke-interface {p1, p0, v0, p2, v2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method
