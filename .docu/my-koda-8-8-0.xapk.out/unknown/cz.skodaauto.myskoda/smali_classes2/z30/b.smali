.class public final Lz30/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwr0/e;


# direct methods
.method public constructor <init>(Lwr0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz30/b;->a:Lwr0/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lz30/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lz30/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lz30/a;

    .line 7
    .line 8
    iget v1, v0, Lz30/a;->f:I

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
    iput v1, v0, Lz30/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lz30/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lz30/a;-><init>(Lz30/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lz30/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lz30/a;->f:I

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
    iput v3, v0, Lz30/a;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lz30/b;->a:Lwr0/e;

    .line 54
    .line 55
    iget-object p1, p1, Lwr0/e;->a:Lwr0/g;

    .line 56
    .line 57
    check-cast p1, Lur0/g;

    .line 58
    .line 59
    invoke-virtual {p1, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p1, Lyr0/e;

    .line 67
    .line 68
    if-eqz p1, :cond_4

    .line 69
    .line 70
    iget-object p1, p1, Lyr0/e;->a:Ljava/lang/String;

    .line 71
    .line 72
    if-eqz p1, :cond_4

    .line 73
    .line 74
    invoke-static {}, Llp/ab;->b()Lis/c;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    iget-object p0, p0, Lis/c;->a:Lms/p;

    .line 79
    .line 80
    iget-object v0, p0, Lms/p;->p:Lns/d;

    .line 81
    .line 82
    iget-object v0, v0, Lns/d;->a:Lns/b;

    .line 83
    .line 84
    new-instance v1, Lh0/h0;

    .line 85
    .line 86
    const/16 v2, 0x18

    .line 87
    .line 88
    invoke-direct {v1, v2, p0, p1}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0, v1}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_4
    new-instance p1, Lxf/b;

    .line 96
    .line 97
    const/16 v0, 0x1c

    .line 98
    .line 99
    invoke-direct {p1, v0}, Lxf/b;-><init>(I)V

    .line 100
    .line 101
    .line 102
    const/4 v0, 0x0

    .line 103
    invoke-static {v0, p0, p1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 104
    .line 105
    .line 106
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    return-object p0
.end method
