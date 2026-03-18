.class public final Lpg/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxh/e;

.field public final b:Lmg/b;

.field public final c:Ljava/lang/String;

.field public final d:Llg/h;

.field public final e:Lyi/a;

.field public f:Lkg/d0;

.field public g:Lug/a;


# direct methods
.method public constructor <init>(Lxh/e;Lmg/b;Ljava/lang/String;Llg/h;Lyi/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpg/p;->a:Lxh/e;

    .line 5
    .line 6
    iput-object p2, p0, Lpg/p;->b:Lmg/b;

    .line 7
    .line 8
    iput-object p3, p0, Lpg/p;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lpg/p;->d:Llg/h;

    .line 11
    .line 12
    iput-object p5, p0, Lpg/p;->e:Lyi/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lkg/j0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lpg/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lpg/o;

    .line 7
    .line 8
    iget v1, v0, Lpg/o;->g:I

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
    iput v1, v0, Lpg/o;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpg/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lpg/o;-><init>(Lpg/p;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lpg/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpg/o;->g:I

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
    iget-object p1, v0, Lpg/o;->d:Lkg/j0;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    check-cast p2, Llx0/o;

    .line 42
    .line 43
    iget-object p2, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p0, Lpg/p;->b:Lmg/b;

    .line 61
    .line 62
    iget-object v2, p2, Lmg/b;->b:Lkg/p0;

    .line 63
    .line 64
    iget-object v2, v2, Lkg/p0;->d:Ljava/lang/String;

    .line 65
    .line 66
    iget-object p2, p2, Lmg/b;->a:Ljava/util/List;

    .line 67
    .line 68
    check-cast p2, Ljava/lang/Iterable;

    .line 69
    .line 70
    new-instance v4, Ljava/util/ArrayList;

    .line 71
    .line 72
    const/16 v5, 0xa

    .line 73
    .line 74
    invoke-static {p2, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-eqz v5, :cond_3

    .line 90
    .line 91
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    check-cast v5, Ldc/w;

    .line 96
    .line 97
    new-instance v6, Lkg/x;

    .line 98
    .line 99
    iget-object v5, v5, Ldc/w;->e:Ljava/lang/String;

    .line 100
    .line 101
    invoke-direct {v6, v5}, Lkg/x;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    new-instance p2, Lkg/m0;

    .line 109
    .line 110
    iget-object v5, p0, Lpg/p;->c:Ljava/lang/String;

    .line 111
    .line 112
    invoke-direct {p2, v2, v4, p1, v5}, Lkg/m0;-><init>(Ljava/lang/String;Ljava/util/ArrayList;Lkg/j0;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    iput-object p1, v0, Lpg/o;->d:Lkg/j0;

    .line 116
    .line 117
    iput v3, v0, Lpg/o;->g:I

    .line 118
    .line 119
    iget-object v2, p0, Lpg/p;->d:Llg/h;

    .line 120
    .line 121
    invoke-virtual {v2, p2, v0}, Llg/h;->c(Lkg/m0;Lrx0/c;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p2

    .line 125
    if-ne p2, v1, :cond_4

    .line 126
    .line 127
    return-object v1

    .line 128
    :cond_4
    :goto_2
    sget-object v0, Lkg/j0;->e:Lkg/j0;

    .line 129
    .line 130
    if-ne p1, v0, :cond_5

    .line 131
    .line 132
    sget-object p1, Lug/a;->d:Lug/a;

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_5
    sget-object p1, Lug/a;->e:Lug/a;

    .line 136
    .line 137
    :goto_3
    iput-object p1, p0, Lpg/p;->g:Lug/a;

    .line 138
    .line 139
    iget-object p1, p0, Lpg/p;->e:Lyi/a;

    .line 140
    .line 141
    check-cast p1, Lmj/k;

    .line 142
    .line 143
    invoke-virtual {p1}, Lmj/k;->b()V

    .line 144
    .line 145
    .line 146
    instance-of p1, p2, Llx0/n;

    .line 147
    .line 148
    if-nez p1, :cond_6

    .line 149
    .line 150
    check-cast p2, Lkg/d0;

    .line 151
    .line 152
    iput-object p2, p0, Lpg/p;->f:Lkg/d0;

    .line 153
    .line 154
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 155
    .line 156
    return-object p0

    .line 157
    :cond_6
    return-object p2
.end method
