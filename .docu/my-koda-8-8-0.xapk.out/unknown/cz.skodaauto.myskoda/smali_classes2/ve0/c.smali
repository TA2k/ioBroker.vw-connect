.class public final Lve0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/e;


# instance fields
.field public final synthetic a:Lve0/d;


# direct methods
.method public constructor <init>(Lve0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lve0/c;->a:Lve0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    return-void
.end method

.method public final bridge synthetic b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lq6/b;

    .line 2
    .line 3
    check-cast p2, Lrx0/c;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lve0/c;->d(Lq6/b;Lrx0/c;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final c(Ljava/lang/Object;La7/k0;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lq6/b;

    .line 2
    .line 3
    invoke-virtual {p1}, Lq6/b;->g()Lq6/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Lq6/b;->b()V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lq6/b;->a:Ljava/util/LinkedHashMap;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->clear()V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public final d(Lq6/b;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lve0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lve0/b;

    .line 7
    .line 8
    iget v1, v0, Lve0/b;->f:I

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
    iput v1, v0, Lve0/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lve0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lve0/b;-><init>(Lve0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lve0/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lve0/b;->f:I

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
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :catchall_0
    move-exception p1

    .line 41
    goto :goto_2

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p2, p0, Lve0/c;->a:Lve0/d;

    .line 54
    .line 55
    :try_start_1
    const-string v2, "keystore_challenge"

    .line 56
    .line 57
    invoke-static {v2}, Llp/m1;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-static {v2}, Ljp/ne;->b(Ljava/lang/String;)Lq6/e;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {p1, v2}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    check-cast p1, Ljava/lang/String;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    if-eqz p1, :cond_4

    .line 73
    .line 74
    iget-object p2, p2, Lve0/d;->a:Lte0/a;

    .line 75
    .line 76
    iput v3, v0, Lve0/b;->f:I

    .line 77
    .line 78
    sget-object v3, Lge0/b;->c:Lcz0/d;

    .line 79
    .line 80
    new-instance v4, Lk90/b;

    .line 81
    .line 82
    invoke-direct {v4, p1, p2, v2}, Lk90/b;-><init>(Ljava/lang/String;Lte0/a;Lkotlin/coroutines/Continuation;)V

    .line 83
    .line 84
    .line 85
    invoke-static {v3, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    if-ne p2, v1, :cond_3

    .line 90
    .line 91
    return-object v1

    .line 92
    :cond_3
    :goto_1
    move-object v2, p2

    .line 93
    check-cast v2, Ljava/lang/String;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :goto_2
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    :cond_4
    :goto_3
    invoke-static {v2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-eqz p1, :cond_6

    .line 105
    .line 106
    invoke-static {p0, p1}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 107
    .line 108
    .line 109
    instance-of p2, p1, Ljava/security/GeneralSecurityException;

    .line 110
    .line 111
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    if-eqz p2, :cond_5

    .line 116
    .line 117
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    const-string v1, "Data store preferences will be cleared."

    .line 120
    .line 121
    invoke-direct {p2, v1, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p0, p2}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 125
    .line 126
    .line 127
    :cond_5
    return-object v0

    .line 128
    :cond_6
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 129
    .line 130
    return-object p0
.end method
