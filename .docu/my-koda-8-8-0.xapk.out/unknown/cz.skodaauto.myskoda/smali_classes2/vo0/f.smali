.class public final Lvo0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lro0/u;

.field public final b:Lro0/c;

.field public final c:Lvo0/a;

.field public final d:Lkc0/z;

.field public final e:Lfj0/g;

.field public f:Ljava/lang/ref/WeakReference;

.field public final g:Ll2/j1;

.field public final h:Ll2/j1;


# direct methods
.method public constructor <init>(Lro0/u;Lro0/c;Lvo0/a;Lkc0/z;Lfj0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvo0/f;->a:Lro0/u;

    .line 5
    .line 6
    iput-object p2, p0, Lvo0/f;->b:Lro0/c;

    .line 7
    .line 8
    iput-object p3, p0, Lvo0/f;->c:Lvo0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lvo0/f;->d:Lkc0/z;

    .line 11
    .line 12
    iput-object p5, p0, Lvo0/f;->e:Lfj0/g;

    .line 13
    .line 14
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lvo0/f;->g:Ll2/j1;

    .line 23
    .line 24
    const/4 p1, 0x0

    .line 25
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lvo0/f;->h:Ll2/j1;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lvo0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lvo0/b;

    .line 7
    .line 8
    iget v1, v0, Lvo0/b;->f:I

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
    iput v1, v0, Lvo0/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lvo0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lvo0/b;-><init>(Lvo0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lvo0/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lvo0/b;->f:I

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
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance p1, Lvd/i;

    .line 52
    .line 53
    const/4 v2, 0x3

    .line 54
    invoke-direct {p1, v2}, Lvd/i;-><init>(I)V

    .line 55
    .line 56
    .line 57
    const-string v2, "MULTI.MySkoda"

    .line 58
    .line 59
    invoke-static {v2, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-static {p1}, Llp/nd;->d(Lkj0/f;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lvo0/f;->h:Ll2/j1;

    .line 67
    .line 68
    invoke-virtual {p1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    check-cast p1, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 73
    .line 74
    if-eqz p1, :cond_3

    .line 75
    .line 76
    iput v3, v0, Lvo0/b;->f:I

    .line 77
    .line 78
    invoke-virtual {p1, v0}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->clearDataAndClose(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ne p1, v1, :cond_3

    .line 83
    .line 84
    return-object v1

    .line 85
    :cond_3
    :goto_1
    iget-object p0, p0, Lvo0/f;->a:Lro0/u;

    .line 86
    .line 87
    check-cast p0, Lpo0/e;

    .line 88
    .line 89
    const/4 p1, 0x0

    .line 90
    iput-object p1, p0, Lpo0/e;->a:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 91
    .line 92
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0
.end method

.method public final b(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lvo0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lvo0/d;

    .line 7
    .line 8
    iget v1, v0, Lvo0/d;->g:I

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
    iput v1, v0, Lvo0/d;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lvo0/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lvo0/d;-><init>(Lvo0/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lvo0/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lvo0/d;->g:I

    .line 30
    .line 31
    const-string v3, "MULTI.MySkoda"

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-ne v2, v4, :cond_2

    .line 37
    .line 38
    iget-object p1, v0, Lvo0/d;->d:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    :cond_1
    move-object v5, p1

    .line 44
    goto :goto_1

    .line 45
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    new-instance p2, Lvd/i;

    .line 57
    .line 58
    const/4 v2, 0x1

    .line 59
    invoke-direct {p2, v2}, Lvd/i;-><init>(I)V

    .line 60
    .line 61
    .line 62
    invoke-static {v3, p0, p2}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-static {p2}, Llp/nd;->d(Lkj0/f;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, v0, Lvo0/d;->d:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 70
    .line 71
    iput v4, v0, Lvo0/d;->g:I

    .line 72
    .line 73
    iget-object p2, p0, Lvo0/f;->b:Lro0/c;

    .line 74
    .line 75
    invoke-virtual {p2, v0}, Lro0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    if-ne p2, v1, :cond_1

    .line 80
    .line 81
    return-object v1

    .line 82
    :goto_1
    check-cast p2, Lki/k;

    .line 83
    .line 84
    const-string p1, "context"

    .line 85
    .line 86
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    const-string p1, "environment"

    .line 90
    .line 91
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    sget-object v6, Luj/t;->a:Luj/t;

    .line 95
    .line 96
    new-instance v8, Lki/m;

    .line 97
    .line 98
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 99
    .line 100
    .line 101
    iget-object p1, p0, Lvo0/f;->g:Ll2/j1;

    .line 102
    .line 103
    iput-object p1, v8, Lki/m;->a:Ll2/j1;

    .line 104
    .line 105
    new-instance v9, Ltj/b;

    .line 106
    .line 107
    invoke-direct {v9, p2}, Ltj/b;-><init>(Lki/k;)V

    .line 108
    .line 109
    .line 110
    new-instance v4, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 111
    .line 112
    iget-object v7, p0, Lvo0/f;->c:Lvo0/a;

    .line 113
    .line 114
    invoke-direct/range {v4 .. v9}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;-><init>(Landroid/content/Context;Lzb/g;Lki/l;Lki/m;Ltj/b;)V

    .line 115
    .line 116
    .line 117
    iget-object p1, p0, Lvo0/f;->a:Lro0/u;

    .line 118
    .line 119
    check-cast p1, Lpo0/e;

    .line 120
    .line 121
    iput-object v4, p1, Lpo0/e;->a:Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 122
    .line 123
    iget-object p1, p0, Lvo0/f;->h:Ll2/j1;

    .line 124
    .line 125
    invoke-virtual {p1, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    new-instance p1, Lvd/i;

    .line 129
    .line 130
    const/4 p2, 0x2

    .line 131
    invoke-direct {p1, p2}, Lvd/i;-><init>(I)V

    .line 132
    .line 133
    .line 134
    invoke-static {v3, p0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-static {p0}, Llp/nd;->d(Lkj0/f;)V

    .line 139
    .line 140
    .line 141
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    return-object p0
.end method
