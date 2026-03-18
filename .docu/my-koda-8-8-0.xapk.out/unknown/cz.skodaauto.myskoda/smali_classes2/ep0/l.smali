.class public final Lep0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lcp0/q;


# direct methods
.method public constructor <init>(Lkf0/o;Lcp0/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lep0/l;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lep0/l;->b:Lcp0/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lfp0/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lep0/l;->b(Lfp0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lfp0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lep0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lep0/k;

    .line 7
    .line 8
    iget v1, v0, Lep0/k;->g:I

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
    iput v1, v0, Lep0/k;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lep0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lep0/k;-><init>(Lep0/l;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lep0/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lep0/k;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget-object p1, v0, Lep0/k;->d:Lfp0/d;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput-object p1, v0, Lep0/k;->d:Lfp0/d;

    .line 61
    .line 62
    iput v4, v0, Lep0/k;->g:I

    .line 63
    .line 64
    iget-object p2, p0, Lep0/l;->a:Lkf0/o;

    .line 65
    .line 66
    invoke-virtual {p2, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    if-ne p2, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p2, Lne0/t;

    .line 74
    .line 75
    instance-of v2, p2, Lne0/c;

    .line 76
    .line 77
    if-eqz v2, :cond_5

    .line 78
    .line 79
    check-cast p2, Lne0/c;

    .line 80
    .line 81
    return-object p2

    .line 82
    :cond_5
    instance-of v2, p2, Lne0/e;

    .line 83
    .line 84
    if-eqz v2, :cond_7

    .line 85
    .line 86
    check-cast p2, Lne0/e;

    .line 87
    .line 88
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p2, Lss0/j0;

    .line 91
    .line 92
    iget-object p2, p2, Lss0/j0;->d:Ljava/lang/String;

    .line 93
    .line 94
    const/4 v2, 0x0

    .line 95
    iput-object v2, v0, Lep0/k;->d:Lfp0/d;

    .line 96
    .line 97
    iput v3, v0, Lep0/k;->g:I

    .line 98
    .line 99
    iget-object p0, p0, Lep0/l;->b:Lcp0/q;

    .line 100
    .line 101
    invoke-virtual {p0, p2, p1, v0}, Lcp0/q;->d(Ljava/lang/String;Lfp0/d;Lrx0/c;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_6

    .line 106
    .line 107
    :goto_2
    return-object v1

    .line 108
    :cond_6
    :goto_3
    new-instance p0, Lne0/e;

    .line 109
    .line 110
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    return-object p0

    .line 116
    :cond_7
    new-instance p0, La8/r0;

    .line 117
    .line 118
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 119
    .line 120
    .line 121
    throw p0
.end method
