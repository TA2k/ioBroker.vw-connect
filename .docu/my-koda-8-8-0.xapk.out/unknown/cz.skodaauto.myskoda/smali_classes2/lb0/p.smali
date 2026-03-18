.class public final Llb0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ljb0/e0;

.field public final b:Llb0/b;

.field public final c:Lkf0/b0;

.field public final d:Llb0/q;

.field public final e:Llb0/c0;


# direct methods
.method public constructor <init>(Ljb0/e0;Llb0/b;Lkf0/b0;Llb0/q;Llb0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/p;->a:Ljb0/e0;

    .line 5
    .line 6
    iput-object p2, p0, Llb0/p;->b:Llb0/b;

    .line 7
    .line 8
    iput-object p3, p0, Llb0/p;->c:Lkf0/b0;

    .line 9
    .line 10
    iput-object p4, p0, Llb0/p;->d:Llb0/q;

    .line 11
    .line 12
    iput-object p5, p0, Llb0/p;->e:Llb0/c0;

    .line 13
    .line 14
    return-void
.end method

.method public static final a(Llb0/p;Lmb0/f;)Lmb0/f;
    .locals 6

    .line 1
    iget-object p0, p1, Lmb0/f;->n:Ljava/util/List;

    .line 2
    .line 3
    iget-object v0, p1, Lmb0/f;->a:Lmb0/e;

    .line 4
    .line 5
    move-object v1, p0

    .line 6
    check-cast v1, Ljava/lang/Iterable;

    .line 7
    .line 8
    instance-of v2, v1, Ljava/util/Collection;

    .line 9
    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    move-object v3, v1

    .line 13
    check-cast v3, Ljava/util/Collection;

    .line 14
    .line 15
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    :cond_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_2

    .line 31
    .line 32
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Lmb0/k;

    .line 37
    .line 38
    iget-object v4, v4, Lmb0/k;->a:Ljava/lang/String;

    .line 39
    .line 40
    const-string v5, "START_AIR_CONDITIONING"

    .line 41
    .line 42
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-eqz v4, :cond_1

    .line 47
    .line 48
    sget-object v0, Lmb0/e;->m:Lmb0/e;

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    :goto_0
    if-eqz v2, :cond_3

    .line 52
    .line 53
    move-object v2, v1

    .line 54
    check-cast v2, Ljava/util/Collection;

    .line 55
    .line 56
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_3

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :cond_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_5

    .line 72
    .line 73
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Lmb0/k;

    .line 78
    .line 79
    iget-object v2, v2, Lmb0/k;->a:Ljava/lang/String;

    .line 80
    .line 81
    const-string v3, "STOP_AIR_CONDITIONING"

    .line 82
    .line 83
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_4

    .line 88
    .line 89
    sget-object v0, Lmb0/e;->n:Lmb0/e;

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_5
    :goto_1
    sget-object v1, Lmb0/e;->e:Lmb0/e;

    .line 93
    .line 94
    sget-object v2, Lmb0/e;->f:Lmb0/e;

    .line 95
    .line 96
    sget-object v3, Lmb0/e;->g:Lmb0/e;

    .line 97
    .line 98
    sget-object v4, Lmb0/e;->h:Lmb0/e;

    .line 99
    .line 100
    filled-new-array {v1, v2, v3, v4}, [Lmb0/e;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-interface {v1, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_6

    .line 113
    .line 114
    sget-object v0, Lmb0/e;->l:Lmb0/e;

    .line 115
    .line 116
    :cond_6
    :goto_2
    invoke-static {p0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    check-cast v1, Lmb0/k;

    .line 121
    .line 122
    if-eqz v1, :cond_7

    .line 123
    .line 124
    iget-object v1, v1, Lmb0/k;->b:Lqr0/q;

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_7
    const/4 v1, 0x0

    .line 128
    :goto_3
    if-eqz v1, :cond_8

    .line 129
    .line 130
    invoke-static {p0}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    check-cast p0, Lmb0/k;

    .line 135
    .line 136
    iget-object p0, p0, Lmb0/k;->b:Lqr0/q;

    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_8
    iget-object p0, p1, Lmb0/f;->e:Lqr0/q;

    .line 140
    .line 141
    :goto_4
    const v1, 0xffee

    .line 142
    .line 143
    .line 144
    invoke-static {p1, v0, p0, v1}, Lmb0/f;->a(Lmb0/f;Lmb0/e;Lqr0/q;I)Lmb0/f;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0
.end method


# virtual methods
.method public final b(Z)Lyy0/i;
    .locals 4

    .line 1
    iget-object v0, p0, Llb0/p;->c:Lkf0/b0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/b0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lrz/k;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Llb0/o;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    iget-object v3, p0, Llb0/p;->a:Ljb0/e0;

    .line 20
    .line 21
    invoke-direct {v0, v2, v3, p0, p1}, Llb0/o;-><init>(Lkotlin/coroutines/Continuation;Ljb0/e0;Llb0/p;Z)V

    .line 22
    .line 23
    .line 24
    invoke-static {v1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0, v0}, Llb0/p;->b(Z)Lyy0/i;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
