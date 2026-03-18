.class public final Lbh0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lbh0/a;

.field public final b:Lbh0/d;


# direct methods
.method public constructor <init>(Lbh0/a;Lbh0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbh0/f;->a:Lbh0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lbh0/f;->b:Lbh0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ldh0/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lbh0/f;->b(Ldh0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ldh0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lbh0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lbh0/e;

    .line 7
    .line 8
    iget v1, v0, Lbh0/e;->g:I

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
    iput v1, v0, Lbh0/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lbh0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lbh0/e;-><init>(Lbh0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lbh0/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lbh0/e;->g:I

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
    return-object p2

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
    iget-object p1, v0, Lbh0/e;->d:Ldh0/b;

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
    iget-object p2, p1, Ldh0/b;->a:Ldh0/a;

    .line 61
    .line 62
    iget-object v2, p1, Ldh0/b;->b:Ljava/lang/String;

    .line 63
    .line 64
    iput-object p1, v0, Lbh0/e;->d:Ldh0/b;

    .line 65
    .line 66
    iput v4, v0, Lbh0/e;->g:I

    .line 67
    .line 68
    iget-object v4, p0, Lbh0/f;->a:Lbh0/a;

    .line 69
    .line 70
    check-cast v4, Lzg0/a;

    .line 71
    .line 72
    new-instance v5, Lzg0/b;

    .line 73
    .line 74
    invoke-direct {v5, p2, v2}, Lzg0/b;-><init>(Ldh0/a;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v4, v5}, Lzg0/a;->a(Lzg0/h;)Lyy0/m1;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    invoke-static {p2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    if-ne p2, v1, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    :goto_1
    check-cast p2, Lne0/t;

    .line 89
    .line 90
    instance-of v2, p2, Lne0/e;

    .line 91
    .line 92
    if-eqz v2, :cond_5

    .line 93
    .line 94
    new-instance p0, Lne0/e;

    .line 95
    .line 96
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    return-object p0

    .line 102
    :cond_5
    instance-of p2, p2, Lne0/c;

    .line 103
    .line 104
    if-eqz p2, :cond_7

    .line 105
    .line 106
    iget-object p1, p1, Ldh0/b;->a:Ldh0/a;

    .line 107
    .line 108
    const/4 p2, 0x0

    .line 109
    iput-object p2, v0, Lbh0/e;->d:Ldh0/b;

    .line 110
    .line 111
    iput v3, v0, Lbh0/e;->g:I

    .line 112
    .line 113
    iget-object p0, p0, Lbh0/f;->b:Lbh0/d;

    .line 114
    .line 115
    invoke-virtual {p0, p1, v0}, Lbh0/d;->b(Ldh0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v1, :cond_6

    .line 120
    .line 121
    :goto_2
    return-object v1

    .line 122
    :cond_6
    return-object p0

    .line 123
    :cond_7
    new-instance p0, La8/r0;

    .line 124
    .line 125
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 126
    .line 127
    .line 128
    throw p0
.end method
