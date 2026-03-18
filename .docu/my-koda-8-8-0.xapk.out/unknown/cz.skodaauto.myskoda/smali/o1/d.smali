.class public final Lo1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx2/q;


# instance fields
.field public b:Z

.field public final c:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lo1/d;->c:Ljava/util/ArrayList;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final h(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lo1/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lo1/c;

    .line 7
    .line 8
    iget v1, v0, Lo1/c;->g:I

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
    iput v1, v0, Lo1/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lo1/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lo1/c;-><init>(Lo1/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lo1/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lo1/c;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lo1/d;->c:Ljava/util/ArrayList;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v0, Lo1/c;->d:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :catchall_0
    move-exception p1

    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-boolean p0, p0, Lo1/d;->b:Z

    .line 58
    .line 59
    if-nez p0, :cond_4

    .line 60
    .line 61
    new-instance p0, Lkotlin/jvm/internal/f0;

    .line 62
    .line 63
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 64
    .line 65
    .line 66
    :try_start_1
    iput-object p0, v0, Lo1/c;->d:Lkotlin/jvm/internal/f0;

    .line 67
    .line 68
    iput v4, v0, Lo1/c;->g:I

    .line 69
    .line 70
    new-instance p1, Lvy0/l;

    .line 71
    .line 72
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-direct {p1, v4, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 80
    .line 81
    .line 82
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 83
    .line 84
    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 91
    if-ne p1, v1, :cond_3

    .line 92
    .line 93
    return-object v1

    .line 94
    :cond_3
    :goto_1
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 95
    .line 96
    invoke-static {v3}, Lkotlin/jvm/internal/j0;->a(Ljava/lang/Object;)Ljava/util/Collection;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    invoke-interface {p1, p0}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :goto_2
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 105
    .line 106
    invoke-static {v3}, Lkotlin/jvm/internal/j0;->a(Ljava/lang/Object;)Ljava/util/Collection;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-interface {v0, p0}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    throw p1

    .line 114
    :cond_4
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0
.end method
