.class public final Lyy0/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:Lkotlin/jvm/internal/d0;

.field public final synthetic e:I

.field public final synthetic f:Lyy0/j;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/d0;ILyy0/j;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyy0/j0;->d:Lkotlin/jvm/internal/d0;

    .line 5
    .line 6
    iput p2, p0, Lyy0/j0;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Lyy0/j0;->f:Lyy0/j;

    .line 9
    .line 10
    iput-object p4, p0, Lyy0/j0;->g:Ljava/lang/Object;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lyy0/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lyy0/i0;

    .line 7
    .line 8
    iget v1, v0, Lyy0/i0;->f:I

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
    iput v1, v0, Lyy0/i0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/i0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lyy0/i0;-><init>(Lyy0/j0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lyy0/i0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/i0;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object v3

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p0, Lyy0/j0;->d:Lkotlin/jvm/internal/d0;

    .line 61
    .line 62
    iget v2, p2, Lkotlin/jvm/internal/d0;->d:I

    .line 63
    .line 64
    add-int/2addr v2, v5

    .line 65
    iput v2, p2, Lkotlin/jvm/internal/d0;->d:I

    .line 66
    .line 67
    iget p2, p0, Lyy0/j0;->e:I

    .line 68
    .line 69
    iget-object v6, p0, Lyy0/j0;->f:Lyy0/j;

    .line 70
    .line 71
    if-ge v2, p2, :cond_5

    .line 72
    .line 73
    iput v5, v0, Lyy0/i0;->f:I

    .line 74
    .line 75
    invoke-interface {v6, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v1, :cond_4

    .line 80
    .line 81
    return-object v1

    .line 82
    :cond_4
    return-object v3

    .line 83
    :cond_5
    iput v4, v0, Lyy0/i0;->f:I

    .line 84
    .line 85
    iget-object p0, p0, Lyy0/j0;->g:Ljava/lang/Object;

    .line 86
    .line 87
    invoke-static {v6, p1, p0, v0}, Lyy0/u;->d(Lyy0/j;Ljava/lang/Object;Ljava/lang/Object;Lrx0/c;)V

    .line 88
    .line 89
    .line 90
    return-object v1
.end method
