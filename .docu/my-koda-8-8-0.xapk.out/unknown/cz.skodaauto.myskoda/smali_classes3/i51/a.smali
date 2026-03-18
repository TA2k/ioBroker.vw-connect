.class public final Li51/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Laq/a;

.field public final b:Ly41/a;

.field public final c:Ly41/f;


# direct methods
.method public constructor <init>(Lzv0/c;Ly41/g;Lj51/i;Lj51/h;Landroid/content/Context;)V
    .locals 8

    .line 1
    new-instance v5, Lb81/c;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    invoke-direct {v5, v0}, Lb81/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Laq/a;

    .line 8
    .line 9
    const/16 v1, 0x18

    .line 10
    .line 11
    invoke-direct {v0, p4, v1}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Li51/a;->a:Laq/a;

    .line 18
    .line 19
    new-instance v0, Ly41/a;

    .line 20
    .line 21
    invoke-direct {v0, p2, p3, v5}, Ly41/a;-><init>(Ly41/g;Lj51/i;Lb81/c;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Li51/a;->b:Ly41/a;

    .line 25
    .line 26
    new-instance p3, Laa/x;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    invoke-direct {p3, p5, v0}, Laa/x;-><init>(Landroid/content/Context;I)V

    .line 30
    .line 31
    .line 32
    invoke-static {p3}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 33
    .line 34
    .line 35
    move-result-object p3

    .line 36
    new-instance p5, Lxf/b;

    .line 37
    .line 38
    const/16 v0, 0x11

    .line 39
    .line 40
    invoke-direct {p5, v0}, Lxf/b;-><init>(I)V

    .line 41
    .line 42
    .line 43
    invoke-static {p5}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 44
    .line 45
    .line 46
    move-result-object p5

    .line 47
    new-instance v0, Ly41/f;

    .line 48
    .line 49
    new-instance v1, Lgw0/c;

    .line 50
    .line 51
    new-instance v2, Lb81/b;

    .line 52
    .line 53
    invoke-direct {v2, p4}, Lb81/b;-><init>(Lj51/h;)V

    .line 54
    .line 55
    .line 56
    new-instance p4, Le51/e;

    .line 57
    .line 58
    invoke-direct {p4, p1, p2}, Le51/e;-><init>(Lzv0/c;Ly41/g;)V

    .line 59
    .line 60
    .line 61
    const/4 v3, 0x4

    .line 62
    invoke-direct {v1, v2, p4, v5, v3}, Lgw0/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 63
    .line 64
    .line 65
    new-instance v2, Lb81/a;

    .line 66
    .line 67
    const/16 p4, 0x9

    .line 68
    .line 69
    invoke-direct {v2, p4, p1, p2}, Lb81/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    new-instance v3, Lb81/b;

    .line 73
    .line 74
    const/16 p4, 0xf

    .line 75
    .line 76
    invoke-direct {v3, p4, p1, p2}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    new-instance v4, Le51/e;

    .line 80
    .line 81
    invoke-direct {v4, p1, p2}, Le51/e;-><init>(Lzv0/c;Ly41/g;)V

    .line 82
    .line 83
    .line 84
    new-instance v6, Lfv/b;

    .line 85
    .line 86
    invoke-virtual {p3}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    check-cast p1, Lm6/g;

    .line 91
    .line 92
    invoke-virtual {p5}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    check-cast p2, Lr51/a;

    .line 97
    .line 98
    const-string p3, "dataStore"

    .line 99
    .line 100
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    const-string p1, "crypto"

    .line 104
    .line 105
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const/4 p1, 0x2

    .line 109
    invoke-direct {v6, p1}, Lfv/b;-><init>(I)V

    .line 110
    .line 111
    .line 112
    new-instance v7, Lfv/b;

    .line 113
    .line 114
    const/16 p1, 0x8

    .line 115
    .line 116
    invoke-direct {v7, p1}, Lfv/b;-><init>(I)V

    .line 117
    .line 118
    .line 119
    invoke-direct/range {v0 .. v7}, Ly41/f;-><init>(Lgw0/c;Lb81/a;Lb81/b;Le51/e;Lb81/c;Lfv/b;Lfv/b;)V

    .line 120
    .line 121
    .line 122
    iput-object v0, p0, Li51/a;->c:Ly41/f;

    .line 123
    .line 124
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Ly41/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ly41/b;

    .line 7
    .line 8
    iget v1, v0, Ly41/b;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ly41/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ly41/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ly41/b;-><init>(Li51/a;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ly41/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ly41/b;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p1, Llx0/o;

    .line 40
    .line 41
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    sget-object p1, Lx51/c;->o1:Lx51/b;

    .line 56
    .line 57
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    iget-object p1, p1, Lx51/b;->d:La61/a;

    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    iput v3, v0, Ly41/b;->f:I

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Li51/a;->b(Lrx0/c;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    if-ne p1, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    :goto_1
    sget-object v0, Lx51/c;->o1:Lx51/b;

    .line 75
    .line 76
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    new-instance v2, Lf91/a;

    .line 81
    .line 82
    const/4 v3, 0x3

    .line 83
    invoke-direct {v2, p1, v3}, Lf91/a;-><init>(Ljava/lang/Object;I)V

    .line 84
    .line 85
    .line 86
    const/4 v3, 0x6

    .line 87
    invoke-static {v0, v1, v2, v3}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    if-nez v1, :cond_5

    .line 95
    .line 96
    check-cast p1, Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    if-eqz p1, :cond_4

    .line 103
    .line 104
    iget-object p1, p0, Li51/a;->c:Ly41/f;

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_4
    new-instance p1, Lz41/c;

    .line 108
    .line 109
    const-string v1, "Smartphone does not support digital key creation."

    .line 110
    .line 111
    const/4 v2, 0x0

    .line 112
    invoke-direct {p1, v1, v2}, Lz41/e;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 113
    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    goto :goto_2

    .line 120
    :cond_5
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    :goto_2
    invoke-static {p0}, Lkp/e0;->c(Ljava/lang/Object;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    new-instance v1, Lf91/a;

    .line 129
    .line 130
    const/4 v2, 0x4

    .line 131
    invoke-direct {v1, p1, v2}, Lf91/a;-><init>(Ljava/lang/Object;I)V

    .line 132
    .line 133
    .line 134
    invoke-static {v0, p0, v1, v3}, Lx51/c;->i(Lx51/c;Ljava/lang/String;Lay0/a;I)V

    .line 135
    .line 136
    .line 137
    return-object p1
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Ly41/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ly41/c;

    .line 7
    .line 8
    iget v1, v0, Ly41/c;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ly41/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ly41/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ly41/c;-><init>(Li51/a;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ly41/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ly41/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p1, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iput v3, v0, Ly41/c;->f:I

    .line 56
    .line 57
    iget-object p0, p0, Li51/a;->a:Laq/a;

    .line 58
    .line 59
    invoke-virtual {p0, v0}, Laq/a;->A(Lrx0/c;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-ne p0, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    return-object p0
.end method
