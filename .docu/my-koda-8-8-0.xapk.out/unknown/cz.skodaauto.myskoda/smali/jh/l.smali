.class public final Ljh/l;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lai/e;

.field public final e:Ljh/b;

.field public final f:Ljh/b;

.field public final g:Lh2/d6;

.field public final h:I

.field public final i:Lyy0/c2;

.field public final j:Lyy0/l1;

.field public final k:Llx0/q;

.field public l:Lah/h;


# direct methods
.method public constructor <init>(Lai/e;Ljh/b;Ljh/b;Lh2/d6;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljh/l;->d:Lai/e;

    .line 5
    .line 6
    iput-object p2, p0, Ljh/l;->e:Ljh/b;

    .line 7
    .line 8
    iput-object p3, p0, Ljh/l;->f:Ljh/b;

    .line 9
    .line 10
    iput-object p4, p0, Ljh/l;->g:Lh2/d6;

    .line 11
    .line 12
    const p1, 0x7fffffff

    .line 13
    .line 14
    .line 15
    iput p1, p0, Ljh/l;->h:I

    .line 16
    .line 17
    new-instance p1, Llc/q;

    .line 18
    .line 19
    sget-object p2, Llc/a;->c:Llc/c;

    .line 20
    .line 21
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Ljh/l;->i:Lyy0/c2;

    .line 29
    .line 30
    new-instance p2, Lyy0/l1;

    .line 31
    .line 32
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 33
    .line 34
    .line 35
    iput-object p2, p0, Ljh/l;->j:Lyy0/l1;

    .line 36
    .line 37
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Ljh/l;->k:Llx0/q;

    .line 42
    .line 43
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    new-instance p2, Ljh/j;

    .line 48
    .line 49
    const/4 p3, 0x0

    .line 50
    const/4 p4, 0x0

    .line 51
    invoke-direct {p2, p0, p4, p3}, Ljh/j;-><init>(Ljh/l;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    const/4 p0, 0x3

    .line 55
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public static final a(Ljh/l;)V
    .locals 4

    .line 1
    iget-object v0, p0, Ljh/l;->i:Lyy0/c2;

    .line 2
    .line 3
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Llc/q;

    .line 9
    .line 10
    new-instance v2, Llc/q;

    .line 11
    .line 12
    sget-object v3, Llc/a;->c:Llc/c;

    .line 13
    .line 14
    invoke-direct {v2, v3}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    iget-object v0, p0, Ljh/l;->k:Llx0/q;

    .line 24
    .line 25
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lzb/k0;

    .line 30
    .line 31
    new-instance v1, Ljh/j;

    .line 32
    .line 33
    const/4 v2, 0x1

    .line 34
    const/4 v3, 0x0

    .line 35
    invoke-direct {v1, p0, v3, v2}, Ljh/j;-><init>(Ljh/l;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x6

    .line 39
    const-string v2, "DATA_POLLING_TAG"

    .line 40
    .line 41
    invoke-static {v0, v2, v3, v1, p0}, Lzb/k0;->c(Lzb/k0;Ljava/lang/String;Lvy0/x;Lay0/n;I)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public static final b(Ljh/l;ZLrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Ljh/k;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Ljh/k;

    .line 10
    .line 11
    iget v1, v0, Ljh/k;->g:I

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
    iput v1, v0, Ljh/k;->g:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ljh/k;

    .line 24
    .line 25
    invoke-direct {v0, p0, p2}, Ljh/k;-><init>(Ljh/l;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p2, v0, Ljh/k;->e:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Ljh/k;->g:I

    .line 33
    .line 34
    const/4 v3, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-boolean p1, v0, Ljh/k;->d:Z

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

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
    iget-object p2, p0, Ljh/l;->f:Ljh/b;

    .line 57
    .line 58
    new-instance v2, Lzg/k;

    .line 59
    .line 60
    invoke-direct {v2, p1}, Lzg/k;-><init>(Z)V

    .line 61
    .line 62
    .line 63
    iput-boolean p1, v0, Ljh/k;->d:Z

    .line 64
    .line 65
    iput v3, v0, Ljh/k;->g:I

    .line 66
    .line 67
    invoke-virtual {p2, v2, v0}, Ljh/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-ne p2, v1, :cond_3

    .line 72
    .line 73
    return-object v1

    .line 74
    :cond_3
    :goto_1
    check-cast p2, Llx0/o;

    .line 75
    .line 76
    iget-object p2, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 77
    .line 78
    instance-of v0, p2, Llx0/n;

    .line 79
    .line 80
    if-nez v0, :cond_4

    .line 81
    .line 82
    move-object v0, p2

    .line 83
    check-cast v0, Llx0/b0;

    .line 84
    .line 85
    :cond_4
    invoke-static {p2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    if-eqz p2, :cond_6

    .line 90
    .line 91
    xor-int/2addr p1, v3

    .line 92
    iget-object p2, p0, Ljh/l;->l:Lah/h;

    .line 93
    .line 94
    if-eqz p2, :cond_6

    .line 95
    .line 96
    iget-object p0, p0, Ljh/l;->i:Lyy0/c2;

    .line 97
    .line 98
    :cond_5
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    move-object v1, v0

    .line 103
    check-cast v1, Llc/q;

    .line 104
    .line 105
    invoke-static {p2}, Llp/zb;->m(Lah/h;)Ljh/h;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    sget-object v2, Ljh/a;->d:Ljh/a;

    .line 110
    .line 111
    const/16 v2, 0x7f

    .line 112
    .line 113
    invoke-static {v1, p1, v2}, Ljh/h;->a(Ljh/h;ZI)Ljh/h;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    new-instance v2, Llc/q;

    .line 118
    .line 119
    invoke-direct {v2, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0, v0, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    if-eqz v0, :cond_5

    .line 127
    .line 128
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    return-object p0
.end method


# virtual methods
.method public final d(Ljava/lang/Throwable;)V
    .locals 4

    .line 1
    :cond_0
    iget-object v0, p0, Ljh/l;->i:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Llc/q;

    .line 9
    .line 10
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    new-instance v3, Llc/q;

    .line 15
    .line 16
    invoke-direct {v3, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v1, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    return-void
.end method

.method public final f(Lay0/n;)V
    .locals 3

    .line 1
    iget-object v0, p0, Ljh/l;->k:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lzb/k0;

    .line 8
    .line 9
    const-string v1, "DATA_POLLING_TAG"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lzb/k0;->a(Lzb/k0;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v1, Lg1/y2;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-direct {v1, p0, p1, v2}, Lg1/y2;-><init>(Ljh/l;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x3

    .line 25
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 26
    .line 27
    .line 28
    return-void
.end method
