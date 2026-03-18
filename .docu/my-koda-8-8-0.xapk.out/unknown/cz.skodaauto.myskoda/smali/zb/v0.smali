.class public final Lzb/v0;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public e:Lzb/u0;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzb/v0;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lz9/y;Ll2/o;I)V
    .locals 4

    .line 1
    const-string v0, "navController"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p2, Ll2/t;

    .line 7
    .line 8
    const v0, -0x41e12917

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x2

    .line 23
    :goto_0
    or-int/2addr v0, p3

    .line 24
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    const/16 v1, 0x20

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/16 v1, 0x10

    .line 34
    .line 35
    :goto_1
    or-int/2addr v0, v1

    .line 36
    and-int/lit8 v1, v0, 0x13

    .line 37
    .line 38
    const/16 v2, 0x12

    .line 39
    .line 40
    const/4 v3, 0x1

    .line 41
    if-eq v1, v2, :cond_2

    .line 42
    .line 43
    move v1, v3

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/4 v1, 0x0

    .line 46
    :goto_2
    and-int/2addr v0, v3

    .line 47
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_5

    .line 52
    .line 53
    iget-object v0, p0, Lzb/v0;->e:Lzb/u0;

    .line 54
    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    iget-object v0, v0, Lzb/u0;->a:Lz9/y;

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_3
    const/4 v0, 0x0

    .line 61
    :goto_3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-eqz v0, :cond_4

    .line 66
    .line 67
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-eqz p2, :cond_6

    .line 72
    .line 73
    new-instance v0, Lzb/t0;

    .line 74
    .line 75
    const/4 v1, 0x0

    .line 76
    invoke-direct {v0, p0, p1, p3, v1}, Lzb/t0;-><init>(Lzb/v0;Lz9/y;II)V

    .line 77
    .line 78
    .line 79
    :goto_4
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 80
    .line 81
    return-void

    .line 82
    :cond_4
    new-instance v0, Lzb/u0;

    .line 83
    .line 84
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 85
    .line 86
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Landroid/content/Context;

    .line 91
    .line 92
    invoke-static {p2}, Lc/j;->a(Ll2/o;)Lb/j0;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    sget-object v3, Lw3/h1;->e:Ll2/u2;

    .line 100
    .line 101
    invoke-virtual {p2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    check-cast v3, Lw3/d1;

    .line 106
    .line 107
    invoke-direct {v0, p1, v1, v2, v3}, Lzb/u0;-><init>(Lz9/y;Landroid/content/Context;Lb/j0;Lw3/d1;)V

    .line 108
    .line 109
    .line 110
    iput-object v0, p0, Lzb/v0;->e:Lzb/u0;

    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 114
    .line 115
    .line 116
    :goto_5
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 117
    .line 118
    .line 119
    move-result-object p2

    .line 120
    if-eqz p2, :cond_6

    .line 121
    .line 122
    new-instance v0, Lzb/t0;

    .line 123
    .line 124
    const/4 v1, 0x1

    .line 125
    invoke-direct {v0, p0, p1, p3, v1}, Lzb/t0;-><init>(Lzb/v0;Lz9/y;II)V

    .line 126
    .line 127
    .line 128
    goto :goto_4

    .line 129
    :cond_6
    return-void
.end method

.method public final b()Lz9/y;
    .locals 1

    .line 1
    iget-object p0, p0, Lzb/v0;->e:Lzb/u0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lzb/u0;->a:Lz9/y;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "ViewModelNavigator: navController must only used on the @Composable NavHost()"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public final d(Lay0/n;)Lxh/e;
    .locals 2

    .line 1
    const-string v0, "block"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lxh/e;

    .line 7
    .line 8
    const/16 v1, 0x8

    .line 9
    .line 10
    invoke-direct {v0, v1, p0, p1}, Lxh/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final f(Lay0/k;)Lyj/b;
    .locals 1

    .line 1
    const-string v0, "block"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lyj/b;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Lyj/b;-><init>(Lzb/v0;Lay0/k;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public final g(Lay0/k;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lzb/v0;->e:Lzb/u0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object p1, Lgi/b;->h:Lgi/b;

    .line 6
    .line 7
    new-instance v0, Lzb/s0;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {v0, p0, v1}, Lzb/s0;-><init>(Lzb/v0;I)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Lgi/a;->e:Lgi/a;

    .line 14
    .line 15
    const-class v1, Lzb/v0;

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const/16 v2, 0x24

    .line 22
    .line 23
    invoke-static {v1, v2}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const/16 v3, 0x2e

    .line 28
    .line 29
    invoke-static {v3, v2, v2}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-nez v3, :cond_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const-string v1, "Kt"

    .line 41
    .line 42
    invoke-static {v2, v1}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    :goto_0
    const/4 v2, 0x0

    .line 47
    invoke-static {v1, p0, p1, v2, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    return-void
.end method
