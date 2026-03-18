.class public final Lh2/q8;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:I

.field public synthetic e:Li2/n;

.field public synthetic f:Li2/u0;

.field public synthetic g:Lh2/s8;

.field public final synthetic h:Lh2/r8;

.field public final synthetic i:F

.field public final synthetic j:Lc1/a0;


# direct methods
.method public constructor <init>(Lh2/r8;FLc1/a0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh2/q8;->h:Lh2/r8;

    .line 2
    .line 3
    iput p2, p0, Lh2/q8;->i:F

    .line 4
    .line 5
    iput-object p3, p0, Lh2/q8;->j:Lc1/a0;

    .line 6
    .line 7
    const/4 p1, 0x4

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Li2/n;

    .line 2
    .line 3
    check-cast p2, Li2/u0;

    .line 4
    .line 5
    check-cast p3, Lh2/s8;

    .line 6
    .line 7
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance v0, Lh2/q8;

    .line 10
    .line 11
    iget v1, p0, Lh2/q8;->i:F

    .line 12
    .line 13
    iget-object v2, p0, Lh2/q8;->j:Lc1/a0;

    .line 14
    .line 15
    iget-object p0, p0, Lh2/q8;->h:Lh2/r8;

    .line 16
    .line 17
    invoke-direct {v0, p0, v1, v2, p4}, Lh2/q8;-><init>(Lh2/r8;FLc1/a0;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, v0, Lh2/q8;->e:Li2/n;

    .line 21
    .line 22
    iput-object p2, v0, Lh2/q8;->f:Li2/u0;

    .line 23
    .line 24
    iput-object p3, v0, Lh2/q8;->g:Lh2/s8;

    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Lh2/q8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lh2/q8;->d:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    goto :goto_2

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object p1, p0, Lh2/q8;->e:Li2/n;

    .line 26
    .line 27
    iget-object v1, p0, Lh2/q8;->f:Li2/u0;

    .line 28
    .line 29
    iget-object v3, p0, Lh2/q8;->g:Lh2/s8;

    .line 30
    .line 31
    invoke-virtual {v1, v3}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_3

    .line 40
    .line 41
    new-instance v1, Lkotlin/jvm/internal/c0;

    .line 42
    .line 43
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 44
    .line 45
    .line 46
    iget-object v3, p0, Lh2/q8;->h:Lh2/r8;

    .line 47
    .line 48
    iget-object v4, v3, Lh2/r8;->e:Li2/p;

    .line 49
    .line 50
    iget-object v4, v4, Li2/p;->j:Ll2/f1;

    .line 51
    .line 52
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_2

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    :goto_0
    move v4, v3

    .line 64
    goto :goto_1

    .line 65
    :cond_2
    iget-object v3, v3, Lh2/r8;->e:Li2/p;

    .line 66
    .line 67
    iget-object v3, v3, Li2/p;->j:Ll2/f1;

    .line 68
    .line 69
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    goto :goto_0

    .line 74
    :goto_1
    iput v4, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 75
    .line 76
    new-instance v8, Lh2/p8;

    .line 77
    .line 78
    const/4 v3, 0x0

    .line 79
    invoke-direct {v8, p1, v1, v3}, Lh2/p8;-><init>(Li2/n;Lkotlin/jvm/internal/c0;I)V

    .line 80
    .line 81
    .line 82
    const/4 p1, 0x0

    .line 83
    iput-object p1, p0, Lh2/q8;->e:Li2/n;

    .line 84
    .line 85
    iput-object p1, p0, Lh2/q8;->f:Li2/u0;

    .line 86
    .line 87
    iput v2, p0, Lh2/q8;->d:I

    .line 88
    .line 89
    iget v6, p0, Lh2/q8;->i:F

    .line 90
    .line 91
    iget-object v7, p0, Lh2/q8;->j:Lc1/a0;

    .line 92
    .line 93
    move-object v9, p0

    .line 94
    invoke-static/range {v4 .. v9}, Lc1/d;->c(FFFLc1/j;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v0, :cond_3

    .line 99
    .line 100
    return-object v0

    .line 101
    :cond_3
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0
.end method
