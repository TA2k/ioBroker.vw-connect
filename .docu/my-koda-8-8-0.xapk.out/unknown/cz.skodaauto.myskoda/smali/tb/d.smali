.class public final synthetic Ltb/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Ltb/d;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ltb/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltb/d;->a:Ltb/d;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.bff.api.models.DisplayError"

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "message"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "phoneNumber"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "recoveryAction"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    const-string v0, "emailAddress"

    .line 33
    .line 34
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Ltb/d;->descriptor:Lsz0/g;

    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 5

    .line 1
    sget-object p0, Ltb/g;->a:Ltb/g;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Ltb/x;->a:Ltb/x;

    .line 8
    .line 9
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sget-object v1, Ltb/j;->a:Ltb/j;

    .line 14
    .line 15
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 20
    .line 21
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const/4 v3, 0x4

    .line 26
    new-array v3, v3, [Lqz0/a;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    aput-object p0, v3, v4

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    aput-object v0, v3, p0

    .line 33
    .line 34
    const/4 p0, 0x2

    .line 35
    aput-object v1, v3, p0

    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    aput-object v2, v3, p0

    .line 39
    .line 40
    return-object v3
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object p0, Ltb/d;->descriptor:Lsz0/g;

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
    move v2, v0

    .line 16
    :goto_0
    if-eqz v2, :cond_5

    .line 17
    .line 18
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/4 v9, -0x1

    .line 23
    if-eq v3, v9, :cond_4

    .line 24
    .line 25
    if-eqz v3, :cond_3

    .line 26
    .line 27
    if-eq v3, v0, :cond_2

    .line 28
    .line 29
    const/4 v9, 0x2

    .line 30
    if-eq v3, v9, :cond_1

    .line 31
    .line 32
    const/4 v9, 0x3

    .line 33
    if-ne v3, v9, :cond_0

    .line 34
    .line 35
    sget-object v3, Luz0/q1;->a:Luz0/q1;

    .line 36
    .line 37
    invoke-interface {p1, p0, v9, v3, v8}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    move-object v8, v3

    .line 42
    check-cast v8, Ljava/lang/String;

    .line 43
    .line 44
    or-int/lit8 v4, v4, 0x8

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    new-instance p0, Lqz0/k;

    .line 48
    .line 49
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_1
    sget-object v3, Ltb/j;->a:Ltb/j;

    .line 54
    .line 55
    invoke-interface {p1, p0, v9, v3, v7}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    move-object v7, v3

    .line 60
    check-cast v7, Ltb/l;

    .line 61
    .line 62
    or-int/lit8 v4, v4, 0x4

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    sget-object v3, Ltb/x;->a:Ltb/x;

    .line 66
    .line 67
    invoke-interface {p1, p0, v0, v3, v6}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    move-object v6, v3

    .line 72
    check-cast v6, Ltb/z;

    .line 73
    .line 74
    or-int/lit8 v4, v4, 0x2

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    sget-object v3, Ltb/g;->a:Ltb/g;

    .line 78
    .line 79
    invoke-interface {p1, p0, v1, v3, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    move-object v5, v3

    .line 84
    check-cast v5, Ltb/i;

    .line 85
    .line 86
    or-int/lit8 v4, v4, 0x1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_4
    move v2, v1

    .line 90
    goto :goto_0

    .line 91
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 92
    .line 93
    .line 94
    new-instance v3, Ltb/f;

    .line 95
    .line 96
    invoke-direct/range {v3 .. v8}, Ltb/f;-><init>(ILtb/i;Ltb/z;Ltb/l;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    return-object v3
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Ltb/d;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Ltb/f;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Ltb/f;->d:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, p2, Ltb/f;->c:Ltb/l;

    .line 11
    .line 12
    iget-object v1, p2, Ltb/f;->b:Ltb/z;

    .line 13
    .line 14
    iget-object p2, p2, Ltb/f;->a:Ltb/i;

    .line 15
    .line 16
    sget-object v2, Ltb/d;->descriptor:Lsz0/g;

    .line 17
    .line 18
    invoke-interface {p1, v2}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    if-eqz p2, :cond_1

    .line 30
    .line 31
    :goto_0
    sget-object v3, Ltb/g;->a:Ltb/g;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    invoke-interface {p1, v2, v4, v3, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    if-eqz p2, :cond_2

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    if-eqz v1, :cond_3

    .line 45
    .line 46
    :goto_1
    sget-object p2, Ltb/x;->a:Ltb/x;

    .line 47
    .line 48
    const/4 v3, 0x1

    .line 49
    invoke-interface {p1, v2, v3, p2, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    :cond_3
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 53
    .line 54
    .line 55
    move-result p2

    .line 56
    if-eqz p2, :cond_4

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_4
    if-eqz v0, :cond_5

    .line 60
    .line 61
    :goto_2
    sget-object p2, Ltb/j;->a:Ltb/j;

    .line 62
    .line 63
    const/4 v1, 0x2

    .line 64
    invoke-interface {p1, v2, v1, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_5
    invoke-interface {p1, v2}, Ltz0/b;->e(Lsz0/g;)Z

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    if-eqz p2, :cond_6

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_6
    if-eqz p0, :cond_7

    .line 75
    .line 76
    :goto_3
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 77
    .line 78
    const/4 v0, 0x3

    .line 79
    invoke-interface {p1, v2, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    :cond_7
    invoke-interface {p1, v2}, Ltz0/b;->b(Lsz0/g;)V

    .line 83
    .line 84
    .line 85
    return-void
.end method
