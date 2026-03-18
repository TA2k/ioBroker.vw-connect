.class public final Lve0/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lve0/u;

.field public e:Ljava/lang/String;

.field public f:Ljava/util/Collection;

.field public g:Ljava/util/Iterator;

.field public h:Lq6/b;

.field public i:Lq6/e;

.field public j:Ljava/util/Collection;

.field public k:I

.field public l:I

.field public m:I

.field public synthetic n:Ljava/lang/Object;

.field public final synthetic o:Ljava/lang/String;

.field public final synthetic p:Ljava/util/Set;

.field public final synthetic q:Lve0/u;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/util/Set;Lve0/u;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lve0/t;->o:Ljava/lang/String;

    .line 2
    .line 3
    iput-object p2, p0, Lve0/t;->p:Ljava/util/Set;

    .line 4
    .line 5
    iput-object p3, p0, Lve0/t;->q:Lve0/u;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lve0/t;

    .line 2
    .line 3
    iget-object v1, p0, Lve0/t;->p:Ljava/util/Set;

    .line 4
    .line 5
    iget-object v2, p0, Lve0/t;->q:Lve0/u;

    .line 6
    .line 7
    iget-object p0, p0, Lve0/t;->o:Ljava/lang/String;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lve0/t;-><init>(Ljava/lang/String;Ljava/util/Set;Lve0/u;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lve0/t;->n:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lq6/b;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lve0/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lve0/t;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lve0/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Lve0/t;->n:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lq6/b;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Lve0/t;->m:I

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    if-ne v2, v3, :cond_0

    .line 13
    .line 14
    iget v0, p0, Lve0/t;->l:I

    .line 15
    .line 16
    iget v2, p0, Lve0/t;->k:I

    .line 17
    .line 18
    iget-object v4, p0, Lve0/t;->j:Ljava/util/Collection;

    .line 19
    .line 20
    check-cast v4, Ljava/util/Collection;

    .line 21
    .line 22
    iget-object v5, p0, Lve0/t;->i:Lq6/e;

    .line 23
    .line 24
    iget-object v6, p0, Lve0/t;->h:Lq6/b;

    .line 25
    .line 26
    iget-object v7, p0, Lve0/t;->g:Ljava/util/Iterator;

    .line 27
    .line 28
    iget-object v8, p0, Lve0/t;->f:Ljava/util/Collection;

    .line 29
    .line 30
    check-cast v8, Ljava/util/Collection;

    .line 31
    .line 32
    iget-object v9, p0, Lve0/t;->e:Ljava/lang/String;

    .line 33
    .line 34
    iget-object v10, p0, Lve0/t;->d:Lve0/u;

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    move-object v11, v6

    .line 40
    move v6, v0

    .line 41
    move-object v0, v11

    .line 42
    goto :goto_1

    .line 43
    :cond_0
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
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lve0/t;->o:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {p1}, Llp/m1;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-static {v2}, Ljp/ne;->c(Ljava/lang/String;)Lq6/e;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    iget-object v4, p0, Lve0/t;->p:Ljava/util/Set;

    .line 65
    .line 66
    check-cast v4, Ljava/lang/Iterable;

    .line 67
    .line 68
    new-instance v5, Ljava/util/ArrayList;

    .line 69
    .line 70
    const/16 v6, 0xa

    .line 71
    .line 72
    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 73
    .line 74
    .line 75
    move-result v6

    .line 76
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 77
    .line 78
    .line 79
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    const/4 v6, 0x0

    .line 84
    iget-object v7, p0, Lve0/t;->q:Lve0/u;

    .line 85
    .line 86
    move-object v9, p1

    .line 87
    move-object v10, v7

    .line 88
    move-object v7, v4

    .line 89
    move-object v4, v5

    .line 90
    move-object v5, v2

    .line 91
    move v2, v6

    .line 92
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-eqz p1, :cond_3

    .line 97
    .line 98
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    check-cast p1, Ljava/lang/String;

    .line 103
    .line 104
    const/4 v8, 0x0

    .line 105
    iput-object v8, p0, Lve0/t;->n:Ljava/lang/Object;

    .line 106
    .line 107
    iput-object v10, p0, Lve0/t;->d:Lve0/u;

    .line 108
    .line 109
    iput-object v9, p0, Lve0/t;->e:Ljava/lang/String;

    .line 110
    .line 111
    move-object v8, v4

    .line 112
    check-cast v8, Ljava/util/Collection;

    .line 113
    .line 114
    iput-object v8, p0, Lve0/t;->f:Ljava/util/Collection;

    .line 115
    .line 116
    iput-object v7, p0, Lve0/t;->g:Ljava/util/Iterator;

    .line 117
    .line 118
    iput-object v0, p0, Lve0/t;->h:Lq6/b;

    .line 119
    .line 120
    iput-object v5, p0, Lve0/t;->i:Lq6/e;

    .line 121
    .line 122
    iput-object v8, p0, Lve0/t;->j:Ljava/util/Collection;

    .line 123
    .line 124
    iput v2, p0, Lve0/t;->k:I

    .line 125
    .line 126
    iput v6, p0, Lve0/t;->l:I

    .line 127
    .line 128
    iput v3, p0, Lve0/t;->m:I

    .line 129
    .line 130
    invoke-static {v10, v9, p1, p0}, Lve0/u;->a(Lve0/u;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/io/Serializable;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    if-ne p1, v1, :cond_2

    .line 135
    .line 136
    return-object v1

    .line 137
    :cond_2
    move-object v8, v4

    .line 138
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 139
    .line 140
    invoke-interface {v4, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-object v4, v8

    .line 144
    goto :goto_0

    .line 145
    :cond_3
    check-cast v4, Ljava/util/List;

    .line 146
    .line 147
    check-cast v4, Ljava/lang/Iterable;

    .line 148
    .line 149
    invoke-static {v4}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    invoke-virtual {v0, v5, p0}, Lq6/b;->e(Lq6/e;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object p0
.end method
