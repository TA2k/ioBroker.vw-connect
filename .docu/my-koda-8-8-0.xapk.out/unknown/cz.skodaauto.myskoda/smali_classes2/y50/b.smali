.class public final Ly50/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lw50/c;

.field public final b:Ly50/e;


# direct methods
.method public constructor <init>(Lw50/c;Ly50/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly50/b;->a:Lw50/c;

    .line 5
    .line 6
    iput-object p2, p0, Ly50/b;->b:Ly50/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Ly50/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Ly50/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ly50/a;

    .line 7
    .line 8
    iget v1, v0, Ly50/a;->f:I

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
    iput v1, v0, Ly50/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ly50/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ly50/a;-><init>(Ly50/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ly50/a;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ly50/a;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iput v3, v0, Ly50/a;->f:I

    .line 53
    .line 54
    iget-object p1, p0, Ly50/b;->a:Lw50/c;

    .line 55
    .line 56
    iget-object v0, p1, Lw50/c;->a:Lxl0/f;

    .line 57
    .line 58
    new-instance v2, Lus0/a;

    .line 59
    .line 60
    const/4 v3, 0x2

    .line 61
    invoke-direct {v2, p1, v4, v3}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 62
    .line 63
    .line 64
    new-instance p1, Lvb/a;

    .line 65
    .line 66
    const/16 v3, 0x17

    .line 67
    .line 68
    invoke-direct {p1, v3}, Lvb/a;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, v2, p1, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_3

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_3
    :goto_1
    check-cast p1, Lyy0/i;

    .line 79
    .line 80
    new-instance v0, Lwa0/c;

    .line 81
    .line 82
    const/16 v1, 0xb

    .line 83
    .line 84
    invoke-direct {v0, p0, v4, v1}, Lwa0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 85
    .line 86
    .line 87
    new-instance p0, Lne0/n;

    .line 88
    .line 89
    const/4 v1, 0x5

    .line 90
    invoke-direct {p0, p1, v0, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 91
    .line 92
    .line 93
    return-object p0
.end method
