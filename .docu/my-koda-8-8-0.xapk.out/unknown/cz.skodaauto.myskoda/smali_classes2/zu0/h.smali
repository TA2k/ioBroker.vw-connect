.class public final Lzu0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Llq0/d;


# direct methods
.method public constructor <init>(Llq0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzu0/h;->a:Llq0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lzu0/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lzu0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzu0/g;

    .line 7
    .line 8
    iget v1, v0, Lzu0/g;->k:I

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
    iput v1, v0, Lzu0/g;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzu0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lzu0/g;-><init>(Lzu0/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lzu0/g;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzu0/g;->k:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget v2, v0, Lzu0/g;->h:I

    .line 39
    .line 40
    iget v5, v0, Lzu0/g;->g:I

    .line 41
    .line 42
    iget-object v6, v0, Lzu0/g;->f:Ljava/util/Collection;

    .line 43
    .line 44
    check-cast v6, Ljava/util/Collection;

    .line 45
    .line 46
    iget-object v7, v0, Lzu0/g;->e:Ljava/util/Iterator;

    .line 47
    .line 48
    iget-object v8, v0, Lzu0/g;->d:Ljava/util/Collection;

    .line 49
    .line 50
    check-cast v8, Ljava/util/Collection;

    .line 51
    .line 52
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    sget-object p1, Lmq0/b;->i:Lsx0/b;

    .line 68
    .line 69
    new-instance v2, Ljava/util/ArrayList;

    .line 70
    .line 71
    const/16 v5, 0xa

    .line 72
    .line 73
    invoke-static {p1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    invoke-direct {v2, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 78
    .line 79
    .line 80
    new-instance v5, Landroidx/collection/d1;

    .line 81
    .line 82
    const/4 v6, 0x6

    .line 83
    invoke-direct {v5, p1, v6}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 84
    .line 85
    .line 86
    const/4 p1, 0x0

    .line 87
    move-object v6, v2

    .line 88
    move-object v7, v5

    .line 89
    move v2, p1

    .line 90
    move v5, v2

    .line 91
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-eqz p1, :cond_4

    .line 96
    .line 97
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    check-cast p1, Lmq0/b;

    .line 102
    .line 103
    move-object v8, v6

    .line 104
    check-cast v8, Ljava/util/Collection;

    .line 105
    .line 106
    iput-object v8, v0, Lzu0/g;->d:Ljava/util/Collection;

    .line 107
    .line 108
    iput-object v7, v0, Lzu0/g;->e:Ljava/util/Iterator;

    .line 109
    .line 110
    iput-object v8, v0, Lzu0/g;->f:Ljava/util/Collection;

    .line 111
    .line 112
    iput v5, v0, Lzu0/g;->g:I

    .line 113
    .line 114
    iput v2, v0, Lzu0/g;->h:I

    .line 115
    .line 116
    iput v4, v0, Lzu0/g;->k:I

    .line 117
    .line 118
    iget-object v8, p0, Lzu0/h;->a:Llq0/d;

    .line 119
    .line 120
    invoke-virtual {v8, p1, v0}, Llq0/d;->b(Lmq0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    if-ne p1, v1, :cond_3

    .line 125
    .line 126
    return-object v1

    .line 127
    :cond_3
    move-object v8, v6

    .line 128
    :goto_2
    invoke-interface {v6, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-object v6, v8

    .line 132
    goto :goto_1

    .line 133
    :cond_4
    check-cast v6, Ljava/util/List;

    .line 134
    .line 135
    return-object v3
.end method
