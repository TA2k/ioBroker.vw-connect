.class public final Lqc0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lcs0/t;

.field public final b:Loc0/b;


# direct methods
.method public constructor <init>(Lcs0/t;Loc0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqc0/b;->a:Lcs0/t;

    .line 5
    .line 6
    iput-object p2, p0, Lqc0/b;->b:Loc0/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lss0/k;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lqc0/b;->b(Lss0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lss0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lqc0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lqc0/a;

    .line 7
    .line 8
    iget v1, v0, Lqc0/a;->g:I

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
    iput v1, v0, Lqc0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqc0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lqc0/a;-><init>(Lqc0/b;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lqc0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqc0/a;->g:I

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
    iget-object p1, v0, Lqc0/a;->d:Lss0/k;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p2, p0, Lqc0/b;->a:Lcs0/t;

    .line 54
    .line 55
    invoke-virtual {p2}, Lcs0/t;->invoke()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    check-cast p2, Lyy0/i;

    .line 60
    .line 61
    iput-object p1, v0, Lqc0/a;->d:Lss0/k;

    .line 62
    .line 63
    iput v3, v0, Lqc0/a;->g:I

    .line 64
    .line 65
    invoke-static {p2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-ne p2, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    if-eqz p2, :cond_5

    .line 79
    .line 80
    iget-object p2, p1, Lss0/k;->i:Lss0/a0;

    .line 81
    .line 82
    if-eqz p2, :cond_5

    .line 83
    .line 84
    iget-object p2, p2, Lss0/a0;->a:Lss0/b;

    .line 85
    .line 86
    sget-object v0, Lss0/e;->U1:Lss0/e;

    .line 87
    .line 88
    invoke-static {p2, v0}, Llp/pf;->g(Lss0/b;Lss0/e;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_4

    .line 93
    .line 94
    sget-object v0, Lss0/e;->T1:Lss0/e;

    .line 95
    .line 96
    invoke-static {p2, v0}, Llp/pf;->g(Lss0/b;Lss0/e;)Z

    .line 97
    .line 98
    .line 99
    move-result p2

    .line 100
    if-eqz p2, :cond_5

    .line 101
    .line 102
    :cond_4
    iget-object p1, p1, Lss0/k;->a:Ljava/lang/String;

    .line 103
    .line 104
    const-string p2, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 105
    .line 106
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    iget-object p0, p0, Lqc0/b;->b:Loc0/b;

    .line 110
    .line 111
    iget-object p2, p0, Loc0/b;->a:Lxl0/f;

    .line 112
    .line 113
    new-instance v0, Llo0/b;

    .line 114
    .line 115
    const/4 v1, 0x0

    .line 116
    const/16 v2, 0xb

    .line 117
    .line 118
    invoke-direct {v0, v2, p0, p1, v1}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p2, v0}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    return-object p0

    .line 126
    :cond_5
    new-instance p0, Lne0/e;

    .line 127
    .line 128
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    new-instance p1, Lyy0/m;

    .line 134
    .line 135
    const/4 p2, 0x0

    .line 136
    invoke-direct {p1, p0, p2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 137
    .line 138
    .line 139
    return-object p1
.end method
