.class public final Lgb0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrs0/f;


# direct methods
.method public constructor <init>(Lrs0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/h;->a:Lrs0/f;

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
    invoke-virtual {p0, p2}, Lgb0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lgb0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgb0/g;

    .line 7
    .line 8
    iget v1, v0, Lgb0/g;->f:I

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
    iput v1, v0, Lgb0/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgb0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgb0/g;-><init>(Lgb0/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgb0/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgb0/g;->f:I

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
    iget-object p0, p0, Lgb0/h;->a:Lrs0/f;

    .line 52
    .line 53
    check-cast p0, Lps0/f;

    .line 54
    .line 55
    iget-object p0, p0, Lps0/f;->c:Lyy0/i;

    .line 56
    .line 57
    iput v3, v0, Lgb0/g;->f:I

    .line 58
    .line 59
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    check-cast p1, Lss0/d0;

    .line 67
    .line 68
    if-eqz p1, :cond_6

    .line 69
    .line 70
    instance-of p0, p1, Lss0/j0;

    .line 71
    .line 72
    if-eqz p0, :cond_4

    .line 73
    .line 74
    new-instance p0, Lne0/e;

    .line 75
    .line 76
    sget-object p1, Lhb0/a;->d:Lhb0/a;

    .line 77
    .line 78
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :cond_4
    instance-of p0, p1, Lss0/g;

    .line 83
    .line 84
    if-eqz p0, :cond_5

    .line 85
    .line 86
    new-instance p0, Lne0/e;

    .line 87
    .line 88
    sget-object p1, Lhb0/a;->e:Lhb0/a;

    .line 89
    .line 90
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    return-object p0

    .line 94
    :cond_5
    new-instance p0, La8/r0;

    .line 95
    .line 96
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :cond_6
    new-instance v0, Lne0/c;

    .line 101
    .line 102
    sget-object v1, Lss0/e0;->d:Lss0/e0;

    .line 103
    .line 104
    const/4 v4, 0x0

    .line 105
    const/16 v5, 0x1e

    .line 106
    .line 107
    const/4 v2, 0x0

    .line 108
    const/4 v3, 0x0

    .line 109
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 110
    .line 111
    .line 112
    return-object v0
.end method
