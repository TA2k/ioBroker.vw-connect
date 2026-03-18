.class public final Lpp0/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/v;

.field public final b:Lck0/d;

.field public final c:Lck0/e;


# direct methods
.method public constructor <init>(Lal0/v;Lck0/d;Lck0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/v0;->a:Lal0/v;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/v0;->b:Lck0/d;

    .line 7
    .line 8
    iput-object p3, p0, Lpp0/v0;->c:Lck0/e;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lpp0/v0;->b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lpp0/u0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lpp0/u0;

    .line 7
    .line 8
    iget v1, v0, Lpp0/u0;->h:I

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
    iput v1, v0, Lpp0/u0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/u0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lpp0/u0;-><init>(Lpp0/v0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lpp0/u0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/u0;->h:I

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
    iget p1, v0, Lpp0/u0;->e:I

    .line 52
    .line 53
    iget-object v2, v0, Lpp0/u0;->d:Ljava/util/Iterator;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    check-cast p1, Ljava/lang/Iterable;

    .line 63
    .line 64
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    const/4 p2, 0x0

    .line 69
    move-object v2, p1

    .line 70
    move p1, p2

    .line 71
    :cond_4
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    if-eqz p2, :cond_5

    .line 76
    .line 77
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    check-cast p2, Ldk0/a;

    .line 82
    .line 83
    iput-object v2, v0, Lpp0/u0;->d:Ljava/util/Iterator;

    .line 84
    .line 85
    iput p1, v0, Lpp0/u0;->e:I

    .line 86
    .line 87
    iput v4, v0, Lpp0/u0;->h:I

    .line 88
    .line 89
    iget-object v5, p0, Lpp0/v0;->b:Lck0/d;

    .line 90
    .line 91
    invoke-virtual {v5, p2, v0}, Lck0/d;->b(Ldk0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    if-ne p2, v1, :cond_4

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_5
    const/4 p1, 0x0

    .line 99
    iput-object p1, v0, Lpp0/u0;->d:Ljava/util/Iterator;

    .line 100
    .line 101
    iput v3, v0, Lpp0/u0;->h:I

    .line 102
    .line 103
    iget-object p1, p0, Lpp0/v0;->a:Lal0/v;

    .line 104
    .line 105
    iget-object p1, p1, Lal0/v;->a:Lal0/b0;

    .line 106
    .line 107
    check-cast p1, Lyk0/e;

    .line 108
    .line 109
    iget-object p2, p1, Lyk0/e;->e:Ljava/util/UUID;

    .line 110
    .line 111
    if-nez p2, :cond_6

    .line 112
    .line 113
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    iput-object p2, p1, Lyk0/e;->e:Ljava/util/UUID;

    .line 118
    .line 119
    const-string p1, "also(...)"

    .line 120
    .line 121
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    :cond_6
    if-ne p2, v1, :cond_7

    .line 125
    .line 126
    :goto_2
    return-object v1

    .line 127
    :cond_7
    :goto_3
    check-cast p2, Ljava/util/UUID;

    .line 128
    .line 129
    iget-object p0, p0, Lpp0/v0;->c:Lck0/e;

    .line 130
    .line 131
    invoke-virtual {p0, p2}, Lck0/e;->a(Ljava/util/UUID;)V

    .line 132
    .line 133
    .line 134
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    return-object p0
.end method
