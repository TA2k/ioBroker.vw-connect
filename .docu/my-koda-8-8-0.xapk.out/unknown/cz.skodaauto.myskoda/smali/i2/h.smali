.class public final Li2/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public d:I

.field public synthetic e:Li2/n;

.field public synthetic f:Li2/u0;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Li2/p;

.field public final synthetic i:F


# direct methods
.method public constructor <init>(Li2/p;FLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Li2/h;->h:Li2/p;

    .line 2
    .line 3
    iput p2, p0, Li2/h;->i:F

    .line 4
    .line 5
    const/4 p1, 0x4

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Li2/n;

    .line 2
    .line 3
    check-cast p2, Li2/u0;

    .line 4
    .line 5
    check-cast p4, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    new-instance v0, Li2/h;

    .line 8
    .line 9
    iget-object v1, p0, Li2/h;->h:Li2/p;

    .line 10
    .line 11
    iget p0, p0, Li2/h;->i:F

    .line 12
    .line 13
    invoke-direct {v0, v1, p0, p4}, Li2/h;-><init>(Li2/p;FLkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Li2/h;->e:Li2/n;

    .line 17
    .line 18
    iput-object p2, v0, Li2/h;->f:Li2/u0;

    .line 19
    .line 20
    iput-object p3, v0, Li2/h;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Li2/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Li2/h;->d:I

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
    goto :goto_1

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
    iget-object p1, p0, Li2/h;->e:Li2/n;

    .line 26
    .line 27
    iget-object v1, p0, Li2/h;->f:Li2/u0;

    .line 28
    .line 29
    iget-object v3, p0, Li2/h;->g:Ljava/lang/Object;

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
    iget-object v3, p0, Li2/h;->h:Li2/p;

    .line 47
    .line 48
    iget-object v4, v3, Li2/p;->j:Ll2/f1;

    .line 49
    .line 50
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eqz v4, :cond_2

    .line 59
    .line 60
    const/4 v4, 0x0

    .line 61
    goto :goto_0

    .line 62
    :cond_2
    iget-object v4, v3, Li2/p;->j:Ll2/f1;

    .line 63
    .line 64
    invoke-virtual {v4}, Ll2/f1;->o()F

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    :goto_0
    iput v4, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 69
    .line 70
    iget-object v3, v3, Li2/p;->c:Ld2/g;

    .line 71
    .line 72
    iget-object v3, v3, Ld2/g;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v3, Lh2/r8;

    .line 75
    .line 76
    iget-object v7, v3, Lh2/r8;->d:Lc1/j;

    .line 77
    .line 78
    new-instance v8, Lh2/p8;

    .line 79
    .line 80
    const/4 v3, 0x1

    .line 81
    invoke-direct {v8, p1, v1, v3}, Lh2/p8;-><init>(Li2/n;Lkotlin/jvm/internal/c0;I)V

    .line 82
    .line 83
    .line 84
    const/4 p1, 0x0

    .line 85
    iput-object p1, p0, Li2/h;->e:Li2/n;

    .line 86
    .line 87
    iput-object p1, p0, Li2/h;->f:Li2/u0;

    .line 88
    .line 89
    iput v2, p0, Li2/h;->d:I

    .line 90
    .line 91
    iget v6, p0, Li2/h;->i:F

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
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0
.end method
