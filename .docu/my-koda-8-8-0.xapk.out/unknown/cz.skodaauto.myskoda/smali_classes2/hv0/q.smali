.class public final Lhv0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lgb0/f;

.field public final b:Lal0/x0;

.field public final c:Lhv0/z;

.field public final d:Lhh0/a;


# direct methods
.method public constructor <init>(Lgb0/f;Lal0/x0;Lhv0/z;Lhh0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/q;->a:Lgb0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/q;->b:Lal0/x0;

    .line 7
    .line 8
    iput-object p3, p0, Lhv0/q;->c:Lhv0/z;

    .line 9
    .line 10
    iput-object p4, p0, Lhv0/q;->d:Lhh0/a;

    .line 11
    .line 12
    return-void
.end method

.method public static final b(Lhv0/q;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lhv0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhv0/o;

    .line 7
    .line 8
    iget v1, v0, Lhv0/o;->j:I

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
    iput v1, v0, Lhv0/o;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhv0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhv0/o;-><init>(Lhv0/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhv0/o;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhv0/o;->j:I

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
    iget p0, v0, Lhv0/o;->g:I

    .line 37
    .line 38
    iget-object v1, v0, Lhv0/o;->f:[Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, [Liv0/e;

    .line 41
    .line 42
    iget-object v2, v0, Lhv0/o;->e:Liv0/d;

    .line 43
    .line 44
    iget-object v0, v0, Lhv0/o;->d:[Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, [Liv0/e;

    .line 47
    .line 48
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    const/4 p1, 0x6

    .line 64
    new-array p1, p1, [Liv0/e;

    .line 65
    .line 66
    sget-object v2, Liv0/a;->a:Liv0/a;

    .line 67
    .line 68
    const/4 v4, 0x0

    .line 69
    aput-object v2, p1, v4

    .line 70
    .line 71
    sget-object v2, Liv0/c;->a:Liv0/c;

    .line 72
    .line 73
    aput-object v2, p1, v3

    .line 74
    .line 75
    const/4 v2, 0x2

    .line 76
    sget-object v4, Liv0/i;->a:Liv0/i;

    .line 77
    .line 78
    aput-object v4, p1, v2

    .line 79
    .line 80
    const/4 v2, 0x3

    .line 81
    sget-object v4, Liv0/m;->a:Liv0/m;

    .line 82
    .line 83
    aput-object v4, p1, v2

    .line 84
    .line 85
    iget-object p0, p0, Lhv0/q;->d:Lhh0/a;

    .line 86
    .line 87
    sget-object v2, Lih0/a;->j:Lih0/a;

    .line 88
    .line 89
    iput-object p1, v0, Lhv0/o;->d:[Ljava/lang/Object;

    .line 90
    .line 91
    sget-object v4, Liv0/d;->a:Liv0/d;

    .line 92
    .line 93
    iput-object v4, v0, Lhv0/o;->e:Liv0/d;

    .line 94
    .line 95
    iput-object p1, v0, Lhv0/o;->f:[Ljava/lang/Object;

    .line 96
    .line 97
    const/4 v5, 0x4

    .line 98
    iput v5, v0, Lhv0/o;->g:I

    .line 99
    .line 100
    iput v3, v0, Lhv0/o;->j:I

    .line 101
    .line 102
    invoke-virtual {p0, v2, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    if-ne p0, v1, :cond_3

    .line 107
    .line 108
    return-object v1

    .line 109
    :cond_3
    move-object v0, p1

    .line 110
    move-object v1, v0

    .line 111
    move-object v2, v4

    .line 112
    move-object p1, p0

    .line 113
    move p0, v5

    .line 114
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    if-eqz p1, :cond_4

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_4
    const/4 v2, 0x0

    .line 124
    :goto_2
    aput-object v2, v1, p0

    .line 125
    .line 126
    const/4 p0, 0x5

    .line 127
    sget-object p1, Liv0/u;->a:Liv0/u;

    .line 128
    .line 129
    aput-object p1, v0, p0

    .line 130
    .line 131
    invoke-static {v0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lhv0/q;->c:Lhv0/z;

    .line 4
    .line 5
    check-cast p1, Lfv0/c;

    .line 6
    .line 7
    iget-object p1, p1, Lfv0/c;->b:Lyy0/l1;

    .line 8
    .line 9
    new-instance p2, Lac/k;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    const/16 v1, 0xd

    .line 13
    .line 14
    invoke-direct {p2, v0, p0, v1}, Lac/k;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1, p2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
