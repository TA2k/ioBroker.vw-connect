.class public final Lm80/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/o;

.field public final i:Lk80/a;

.field public final j:Lk80/e;

.field public final k:Lk80/g;

.field public final l:Ltr0/b;

.field public final m:Lrq0/f;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/o;Lk80/a;Lk80/e;Lk80/g;Ltr0/b;Lrq0/f;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lm80/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v3, v2, v3, v2}, Lm80/b;-><init>(ZLl80/c;ZLql0/g;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lm80/e;->h:Lkf0/o;

    .line 13
    .line 14
    iput-object p2, p0, Lm80/e;->i:Lk80/a;

    .line 15
    .line 16
    iput-object p3, p0, Lm80/e;->j:Lk80/e;

    .line 17
    .line 18
    iput-object p4, p0, Lm80/e;->k:Lk80/g;

    .line 19
    .line 20
    iput-object p5, p0, Lm80/e;->l:Ltr0/b;

    .line 21
    .line 22
    iput-object p6, p0, Lm80/e;->m:Lrq0/f;

    .line 23
    .line 24
    iput-object p7, p0, Lm80/e;->n:Lij0/a;

    .line 25
    .line 26
    new-instance p1, Lm80/a;

    .line 27
    .line 28
    const/4 p2, 0x0

    .line 29
    invoke-direct {p1, p0, v1, p2}, Lm80/a;-><init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public static final h(Lm80/e;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lm80/c;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lm80/c;

    .line 10
    .line 11
    iget v1, v0, Lm80/c;->f:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lm80/c;->f:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lm80/c;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Lm80/c;-><init>(Lm80/e;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Lm80/c;->d:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lm80/c;->f:I

    .line 33
    .line 34
    const/4 v3, 0x3

    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    if-eqz v2, :cond_4

    .line 40
    .line 41
    if-eq v2, v5, :cond_3

    .line 42
    .line 43
    if-eq v2, v4, :cond_2

    .line 44
    .line 45
    if-ne v2, v3, :cond_1

    .line 46
    .line 47
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-object v6

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget-object p1, p0, Lm80/e;->h:Lkf0/o;

    .line 71
    .line 72
    iput v5, v0, Lm80/c;->f:I

    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v1, :cond_5

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_5
    :goto_1
    check-cast p1, Lne0/t;

    .line 85
    .line 86
    instance-of v2, p1, Lne0/c;

    .line 87
    .line 88
    const/4 v5, 0x0

    .line 89
    if-eqz v2, :cond_6

    .line 90
    .line 91
    move-object p1, v5

    .line 92
    goto :goto_2

    .line 93
    :cond_6
    instance-of v2, p1, Lne0/e;

    .line 94
    .line 95
    if-eqz v2, :cond_a

    .line 96
    .line 97
    check-cast p1, Lne0/e;

    .line 98
    .line 99
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 100
    .line 101
    :goto_2
    check-cast p1, Lss0/j0;

    .line 102
    .line 103
    if-eqz p1, :cond_7

    .line 104
    .line 105
    iget-object v5, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 106
    .line 107
    :cond_7
    if-eqz v5, :cond_9

    .line 108
    .line 109
    iget-object p1, p0, Lm80/e;->i:Lk80/a;

    .line 110
    .line 111
    iput v4, v0, Lm80/c;->f:I

    .line 112
    .line 113
    invoke-virtual {p1, v5, v0}, Lk80/a;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    if-ne p1, v1, :cond_8

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_8
    :goto_3
    check-cast p1, Lyy0/i;

    .line 121
    .line 122
    new-instance v2, Lm80/d;

    .line 123
    .line 124
    const/4 v4, 0x0

    .line 125
    invoke-direct {v2, p0, v4}, Lm80/d;-><init>(Lm80/e;I)V

    .line 126
    .line 127
    .line 128
    iput v3, v0, Lm80/c;->f:I

    .line 129
    .line 130
    invoke-interface {p1, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-ne p0, v1, :cond_9

    .line 135
    .line 136
    :goto_4
    return-object v1

    .line 137
    :cond_9
    return-object v6

    .line 138
    :cond_a
    new-instance p0, La8/r0;

    .line 139
    .line 140
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 141
    .line 142
    .line 143
    throw p0
.end method
