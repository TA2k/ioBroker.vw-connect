.class public final Le30/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/m;

.field public final i:Lkf0/k;

.field public final j:Lc30/j;

.field public final k:Lc30/o;

.field public final l:Lc30/n;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/m;Lkf0/k;Lc30/j;Lc30/o;Lc30/n;Lij0/a;)V
    .locals 5

    .line 1
    new-instance v0, Le30/h;

    .line 2
    .line 3
    sget-object v1, Le30/g;->e:Le30/g;

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    const/4 v3, 0x1

    .line 7
    and-int/2addr v2, v3

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    :cond_0
    const/4 v2, 0x7

    .line 12
    and-int/lit8 v2, v2, 0x2

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    move-object v1, v4

    .line 18
    :cond_1
    invoke-direct {v0, v3, v1, v4}, Le30/h;-><init>(ZLe30/g;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Le30/j;->h:Lkf0/m;

    .line 25
    .line 26
    iput-object p2, p0, Le30/j;->i:Lkf0/k;

    .line 27
    .line 28
    iput-object p3, p0, Le30/j;->j:Lc30/j;

    .line 29
    .line 30
    iput-object p4, p0, Le30/j;->k:Lc30/o;

    .line 31
    .line 32
    iput-object p5, p0, Le30/j;->l:Lc30/n;

    .line 33
    .line 34
    iput-object p6, p0, Le30/j;->m:Lij0/a;

    .line 35
    .line 36
    new-instance p1, Le30/e;

    .line 37
    .line 38
    const/4 p2, 0x0

    .line 39
    const/4 p3, 0x0

    .line 40
    invoke-direct {p1, p0, p3, p2}, Le30/e;-><init>(Le30/j;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 44
    .line 45
    .line 46
    new-instance p1, Le30/e;

    .line 47
    .line 48
    const/4 p2, 0x1

    .line 49
    invoke-direct {p1, p0, p3, p2}, Le30/e;-><init>(Le30/j;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public static final h(Le30/j;Lss0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Le30/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Le30/i;

    .line 7
    .line 8
    iget v1, v0, Le30/i;->g:I

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
    iput v1, v0, Le30/i;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Le30/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Le30/i;-><init>(Le30/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Le30/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Le30/i;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget-object p1, v0, Le30/i;->d:Le30/g;

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_2

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p1, Lss0/k;->d:Lss0/m;

    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    if-eqz p1, :cond_4

    .line 61
    .line 62
    const/4 p2, 0x3

    .line 63
    if-eq p1, p2, :cond_3

    .line 64
    .line 65
    const/4 p2, 0x5

    .line 66
    if-eq p1, p2, :cond_4

    .line 67
    .line 68
    move-object p1, v3

    .line 69
    goto :goto_1

    .line 70
    :cond_3
    sget-object p1, Le30/g;->e:Le30/g;

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_4
    sget-object p1, Le30/g;->d:Le30/g;

    .line 74
    .line 75
    :goto_1
    iget-object p2, p0, Le30/j;->i:Lkf0/k;

    .line 76
    .line 77
    iput-object p1, v0, Le30/i;->d:Le30/g;

    .line 78
    .line 79
    iput v4, v0, Le30/i;->g:I

    .line 80
    .line 81
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    if-ne p2, v1, :cond_5

    .line 89
    .line 90
    return-object v1

    .line 91
    :cond_5
    :goto_2
    check-cast p2, Lss0/b;

    .line 92
    .line 93
    sget-object v0, Lss0/e;->Q:Lss0/e;

    .line 94
    .line 95
    invoke-static {p2, v0}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    check-cast v0, Le30/h;

    .line 104
    .line 105
    const/4 v1, 0x4

    .line 106
    invoke-static {v0, p2, p1, v3, v1}, Le30/h;->a(Le30/h;ZLe30/g;Ljava/lang/String;I)Le30/h;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 111
    .line 112
    .line 113
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0
.end method
