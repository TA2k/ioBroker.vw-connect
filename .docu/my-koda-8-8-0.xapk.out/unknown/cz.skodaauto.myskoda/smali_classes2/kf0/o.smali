.class public final Lkf0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lrs0/b;


# direct methods
.method public constructor <init>(Lrs0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/o;->a:Lrs0/b;

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
    invoke-virtual {p0, p2}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lkf0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lkf0/n;

    .line 7
    .line 8
    iget v1, v0, Lkf0/n;->f:I

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
    iput v1, v0, Lkf0/n;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lkf0/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lkf0/n;-><init>(Lkf0/o;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lkf0/n;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lkf0/n;->f:I

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
    iput v3, v0, Lkf0/n;->f:I

    .line 52
    .line 53
    iget-object p0, p0, Lkf0/o;->a:Lrs0/b;

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Lrs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 63
    .line 64
    instance-of p0, p1, Lne0/e;

    .line 65
    .line 66
    if-eqz p0, :cond_5

    .line 67
    .line 68
    check-cast p1, Lne0/e;

    .line 69
    .line 70
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lss0/d0;

    .line 73
    .line 74
    instance-of p1, p0, Lss0/j0;

    .line 75
    .line 76
    if-eqz p1, :cond_4

    .line 77
    .line 78
    new-instance p1, Lne0/e;

    .line 79
    .line 80
    invoke-direct {p1, p0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    return-object p1

    .line 84
    :cond_4
    new-instance v0, Lne0/c;

    .line 85
    .line 86
    sget-object v1, Lss0/h0;->d:Lss0/h0;

    .line 87
    .line 88
    const/4 v4, 0x0

    .line 89
    const/16 v5, 0x1e

    .line 90
    .line 91
    const/4 v2, 0x0

    .line 92
    const/4 v3, 0x0

    .line 93
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 94
    .line 95
    .line 96
    return-object v0

    .line 97
    :cond_5
    instance-of p0, p1, Lne0/c;

    .line 98
    .line 99
    if-eqz p0, :cond_6

    .line 100
    .line 101
    return-object p1

    .line 102
    :cond_6
    new-instance p0, La8/r0;

    .line 103
    .line 104
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 105
    .line 106
    .line 107
    throw p0
.end method
