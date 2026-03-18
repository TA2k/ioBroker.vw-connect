.class public final Luj0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwj0/h;
.implements Lme0/a;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lyy0/m1;


# direct methods
.method public constructor <init>(Lti0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Luj0/n;->a:Lti0/a;

    .line 5
    .line 6
    new-instance p1, Ltr0/e;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/16 v1, 0xd

    .line 10
    .line 11
    invoke-direct {p1, p0, v0, v1}, Ltr0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    new-instance v0, Lyy0/m1;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Luj0/n;->b:Lyy0/m1;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Luj0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Luj0/k;

    .line 7
    .line 8
    iget v1, v0, Luj0/k;->f:I

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
    iput v1, v0, Luj0/k;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luj0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Luj0/k;-><init>(Luj0/n;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Luj0/k;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luj0/k;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
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
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v5, v0, Luj0/k;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Luj0/n;->a:Lti0/a;

    .line 63
    .line 64
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Luj0/a;

    .line 72
    .line 73
    iput v4, v0, Luj0/k;->f:I

    .line 74
    .line 75
    iget-object p0, p1, Luj0/a;->a:Lla/u;

    .line 76
    .line 77
    new-instance p1, Lu2/d;

    .line 78
    .line 79
    const/16 v2, 0x10

    .line 80
    .line 81
    invoke-direct {p1, v2}, Lu2/d;-><init>(I)V

    .line 82
    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    invoke-static {v0, p0, v2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v1, :cond_5

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_5
    move-object p0, v3

    .line 93
    :goto_2
    if-ne p0, v1, :cond_6

    .line 94
    .line 95
    :goto_3
    return-object v1

    .line 96
    :cond_6
    return-object v3
.end method

.method public final b(Lxj0/j;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Luj0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Luj0/l;

    .line 7
    .line 8
    iget v1, v0, Luj0/l;->g:I

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
    iput v1, v0, Luj0/l;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Luj0/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Luj0/l;-><init>(Luj0/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Luj0/l;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Luj0/l;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
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
    :cond_2
    iget-object p1, v0, Luj0/l;->d:Lxj0/j;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object p1, v0, Luj0/l;->d:Lxj0/j;

    .line 63
    .line 64
    iput v5, v0, Luj0/l;->g:I

    .line 65
    .line 66
    iget-object p0, p0, Luj0/n;->a:Lti0/a;

    .line 67
    .line 68
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    if-ne p2, v1, :cond_4

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    :goto_1
    check-cast p2, Luj0/a;

    .line 76
    .line 77
    const-string p0, "<this>"

    .line 78
    .line 79
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance p0, Luj0/b;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    invoke-direct {p0, v5, p1}, Luj0/b;-><init>(ILjava/lang/String;)V

    .line 89
    .line 90
    .line 91
    const/4 p1, 0x0

    .line 92
    iput-object p1, v0, Luj0/l;->d:Lxj0/j;

    .line 93
    .line 94
    iput v4, v0, Luj0/l;->g:I

    .line 95
    .line 96
    iget-object p1, p2, Luj0/a;->a:Lla/u;

    .line 97
    .line 98
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 99
    .line 100
    const/16 v4, 0xd

    .line 101
    .line 102
    invoke-direct {v2, v4, p2, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    const/4 p0, 0x0

    .line 106
    invoke-static {v0, p1, p0, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-ne p0, v1, :cond_5

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_5
    move-object p0, v3

    .line 114
    :goto_2
    if-ne p0, v1, :cond_6

    .line 115
    .line 116
    :goto_3
    return-object v1

    .line 117
    :cond_6
    return-object v3
.end method
