.class public final Landroidx/collection/n0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Landroidx/collection/o0;

.field public f:Landroidx/collection/p0;

.field public g:[J

.field public h:I

.field public i:I

.field public synthetic j:Ljava/lang/Object;

.field public final synthetic k:Landroidx/collection/p0;

.field public final synthetic l:Landroidx/collection/o0;


# direct methods
.method public constructor <init>(Landroidx/collection/p0;Landroidx/collection/o0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/collection/n0;->k:Landroidx/collection/p0;

    .line 2
    .line 3
    iput-object p2, p0, Landroidx/collection/n0;->l:Landroidx/collection/o0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Landroidx/collection/n0;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/collection/n0;->k:Landroidx/collection/p0;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/n0;->l:Landroidx/collection/o0;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Landroidx/collection/n0;-><init>(Landroidx/collection/p0;Landroidx/collection/o0;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Landroidx/collection/n0;->j:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lky0/k;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Landroidx/collection/n0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Landroidx/collection/n0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Landroidx/collection/n0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Landroidx/collection/n0;->i:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget v1, p0, Landroidx/collection/n0;->h:I

    .line 11
    .line 12
    iget-object v3, p0, Landroidx/collection/n0;->g:[J

    .line 13
    .line 14
    iget-object v4, p0, Landroidx/collection/n0;->f:Landroidx/collection/p0;

    .line 15
    .line 16
    iget-object v5, p0, Landroidx/collection/n0;->e:Landroidx/collection/o0;

    .line 17
    .line 18
    iget-object v6, p0, Landroidx/collection/n0;->j:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v6, Lky0/k;

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Landroidx/collection/n0;->j:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v6, p1

    .line 40
    check-cast v6, Lky0/k;

    .line 41
    .line 42
    iget-object v4, p0, Landroidx/collection/n0;->k:Landroidx/collection/p0;

    .line 43
    .line 44
    iget-object p1, v4, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 45
    .line 46
    iget-object v3, p1, Landroidx/collection/m0;->c:[J

    .line 47
    .line 48
    iget v1, p1, Landroidx/collection/m0;->e:I

    .line 49
    .line 50
    iget-object v5, p0, Landroidx/collection/n0;->l:Landroidx/collection/o0;

    .line 51
    .line 52
    :goto_0
    const p1, 0x7fffffff

    .line 53
    .line 54
    .line 55
    if-eq v1, p1, :cond_2

    .line 56
    .line 57
    aget-wide v7, v3, v1

    .line 58
    .line 59
    const/16 p1, 0x1f

    .line 60
    .line 61
    shr-long/2addr v7, p1

    .line 62
    const-wide/32 v9, 0x7fffffff

    .line 63
    .line 64
    .line 65
    and-long/2addr v7, v9

    .line 66
    long-to-int p1, v7

    .line 67
    iput v1, v5, Landroidx/collection/o0;->e:I

    .line 68
    .line 69
    iget-object v7, v4, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 70
    .line 71
    iget-object v7, v7, Landroidx/collection/m0;->b:[Ljava/lang/Object;

    .line 72
    .line 73
    aget-object v1, v7, v1

    .line 74
    .line 75
    iput-object v6, p0, Landroidx/collection/n0;->j:Ljava/lang/Object;

    .line 76
    .line 77
    iput-object v5, p0, Landroidx/collection/n0;->e:Landroidx/collection/o0;

    .line 78
    .line 79
    iput-object v4, p0, Landroidx/collection/n0;->f:Landroidx/collection/p0;

    .line 80
    .line 81
    iput-object v3, p0, Landroidx/collection/n0;->g:[J

    .line 82
    .line 83
    iput p1, p0, Landroidx/collection/n0;->h:I

    .line 84
    .line 85
    iput v2, p0, Landroidx/collection/n0;->i:I

    .line 86
    .line 87
    invoke-virtual {v6, v1, p0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 88
    .line 89
    .line 90
    return-object v0

    .line 91
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0
.end method
