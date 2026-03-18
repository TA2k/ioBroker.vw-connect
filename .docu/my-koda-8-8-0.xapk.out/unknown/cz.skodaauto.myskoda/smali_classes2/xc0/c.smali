.class public final Lxc0/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lid0/c;

.field public final i:Lwc0/b;

.field public final j:Lbh0/j;

.field public final k:Lqf0/g;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Lid0/c;Lwc0/b;Lbh0/j;Lqf0/g;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lxc0/a;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Lxc0/a;-><init>(Ljava/lang/String;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lxc0/c;->h:Lid0/c;

    .line 12
    .line 13
    iput-object p2, p0, Lxc0/c;->i:Lwc0/b;

    .line 14
    .line 15
    iput-object p3, p0, Lxc0/c;->j:Lbh0/j;

    .line 16
    .line 17
    iput-object p4, p0, Lxc0/c;->k:Lqf0/g;

    .line 18
    .line 19
    iput-object p5, p0, Lxc0/c;->l:Lij0/a;

    .line 20
    .line 21
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance p2, Lau0/b;

    .line 26
    .line 27
    invoke-direct {p2, p0, v2}, Lau0/b;-><init>(Lxc0/c;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    const/4 p0, 0x3

    .line 31
    invoke-static {p1, v2, v2, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public static final h(Lxc0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lxc0/c;->l:Lij0/a;

    .line 2
    .line 3
    instance-of v1, p1, Lxc0/b;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lxc0/b;

    .line 9
    .line 10
    iget v2, v1, Lxc0/b;->f:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lxc0/b;->f:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lxc0/b;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lxc0/b;-><init>(Lxc0/c;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lxc0/b;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lxc0/b;->f:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lxc0/c;->i:Lwc0/b;

    .line 54
    .line 55
    iput v4, v1, Lxc0/b;->f:I

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, v1}, Lwc0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v2, :cond_3

    .line 65
    .line 66
    return-object v2

    .line 67
    :cond_3
    :goto_1
    const-string p0, "IS"

    .line 68
    .line 69
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    const/4 p1, 0x0

    .line 74
    if-eqz p0, :cond_4

    .line 75
    .line 76
    new-array p0, p1, [Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v0, Ljj0/f;

    .line 79
    .line 80
    const p1, 0x7f120127

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :cond_4
    new-array p0, p1, [Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v0, Ljj0/f;

    .line 91
    .line 92
    const p1, 0x7f120126

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0
.end method
