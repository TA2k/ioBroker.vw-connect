.class public final Lwj0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwj0/u;

.field public final b:Luj0/g;


# direct methods
.method public constructor <init>(Lwj0/u;Luj0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwj0/f0;->a:Lwj0/u;

    .line 5
    .line 6
    iput-object p2, p0, Lwj0/f0;->b:Luj0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lxj0/r;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lwj0/f0;->c(Lxj0/r;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lwj0/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lwj0/e0;

    .line 7
    .line 8
    iget v1, v0, Lwj0/e0;->g:I

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
    iput v1, v0, Lwj0/e0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwj0/e0;

    .line 21
    .line 22
    check-cast p2, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p2}, Lwj0/e0;-><init>(Lwj0/f0;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v0, Lwj0/e0;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lwj0/e0;->g:I

    .line 32
    .line 33
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v5, :cond_2

    .line 40
    .line 41
    if-ne v2, v4, :cond_1

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-object v3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object p1, v0, Lwj0/e0;->d:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object p2, p0, Lwj0/f0;->b:Luj0/g;

    .line 65
    .line 66
    iget-object p2, p2, Luj0/g;->b:Lyy0/l1;

    .line 67
    .line 68
    iput-object p1, v0, Lwj0/e0;->d:Ljava/lang/String;

    .line 69
    .line 70
    iput v5, v0, Lwj0/e0;->g:I

    .line 71
    .line 72
    invoke-static {p2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    :goto_1
    check-cast p2, Ljava/util/List;

    .line 80
    .line 81
    if-eqz p2, :cond_7

    .line 82
    .line 83
    check-cast p2, Ljava/lang/Iterable;

    .line 84
    .line 85
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    :cond_5
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    const/4 v5, 0x0

    .line 94
    if-eqz v2, :cond_6

    .line 95
    .line 96
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    move-object v6, v2

    .line 101
    check-cast v6, Lxj0/r;

    .line 102
    .line 103
    invoke-virtual {v6}, Lxj0/r;->b()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    invoke-static {v6, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    if-eqz v6, :cond_5

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_6
    move-object v2, v5

    .line 115
    :goto_2
    check-cast v2, Lxj0/r;

    .line 116
    .line 117
    if-eqz v2, :cond_7

    .line 118
    .line 119
    iput-object v5, v0, Lwj0/e0;->d:Ljava/lang/String;

    .line 120
    .line 121
    iput v4, v0, Lwj0/e0;->g:I

    .line 122
    .line 123
    invoke-virtual {p0, v2}, Lwj0/f0;->c(Lxj0/r;)V

    .line 124
    .line 125
    .line 126
    if-ne v3, v1, :cond_7

    .line 127
    .line 128
    :goto_3
    return-object v1

    .line 129
    :cond_7
    return-object v3
.end method

.method public final c(Lxj0/r;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lwj0/f0;->a:Lwj0/u;

    .line 2
    .line 3
    check-cast p0, Luj0/f;

    .line 4
    .line 5
    const-string v0, "pin"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Luj0/f;->a:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method
