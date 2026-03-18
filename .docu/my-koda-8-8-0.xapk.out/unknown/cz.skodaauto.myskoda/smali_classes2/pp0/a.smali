.class public final Lpp0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/c0;


# direct methods
.method public constructor <init>(Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/a;->a:Lpp0/c0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lqp0/b0;)V
    .locals 8

    .line 1
    iget-object p0, p0, Lpp0/a;->a:Lpp0/c0;

    .line 2
    .line 3
    check-cast p0, Lnp0/b;

    .line 4
    .line 5
    iget-object p0, p0, Lnp0/b;->h:Lyy0/c2;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    move-object v1, v0

    .line 12
    check-cast v1, Lqp0/g;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v1, :cond_7

    .line 16
    .line 17
    iget-object v3, v1, Lqp0/g;->a:Ljava/util/List;

    .line 18
    .line 19
    move-object v4, v3

    .line 20
    check-cast v4, Ljava/lang/Iterable;

    .line 21
    .line 22
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    :cond_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_2

    .line 31
    .line 32
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    move-object v6, v5

    .line 37
    check-cast v6, Llx0/l;

    .line 38
    .line 39
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v6, Lqp0/b0;

    .line 42
    .line 43
    invoke-static {v6}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    if-eqz v6, :cond_1

    .line 48
    .line 49
    move-object v2, v5

    .line 50
    :cond_2
    check-cast v2, Llx0/l;

    .line 51
    .line 52
    if-eqz v2, :cond_6

    .line 53
    .line 54
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v2, Lqp0/b0;

    .line 57
    .line 58
    const-string v4, "old"

    .line 59
    .line 60
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    check-cast v3, Ljava/util/Collection;

    .line 64
    .line 65
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    const/4 v5, 0x0

    .line 74
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    const/4 v7, -0x1

    .line 79
    if-eqz v6, :cond_4

    .line 80
    .line 81
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    check-cast v6, Llx0/l;

    .line 86
    .line 87
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 88
    .line 89
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v6

    .line 93
    if-eqz v6, :cond_3

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_4
    move v5, v7

    .line 100
    :goto_1
    if-eq v5, v7, :cond_5

    .line 101
    .line 102
    new-instance v2, Ljava/security/SecureRandom;

    .line 103
    .line 104
    invoke-direct {v2}, Ljava/security/SecureRandom;-><init>()V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2}, Ljava/util/Random;->nextInt()I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    new-instance v4, Llx0/l;

    .line 116
    .line 117
    invoke-direct {v4, v2, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v3, v5, v4}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    :cond_5
    invoke-static {v3}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    iget-object v3, v1, Lqp0/g;->b:Ljava/lang/Integer;

    .line 128
    .line 129
    iget-boolean v1, v1, Lqp0/g;->c:Z

    .line 130
    .line 131
    new-instance v4, Lqp0/g;

    .line 132
    .line 133
    invoke-direct {v4, v2, v3, v1}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 134
    .line 135
    .line 136
    invoke-static {v4}, Ljp/bg;->e(Lqp0/g;)Lqp0/g;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    invoke-static {v1}, Ljp/bg;->e(Lqp0/g;)Lqp0/g;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    :cond_6
    move-object v2, v1

    .line 145
    :cond_7
    invoke-virtual {p0, v0, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    if-eqz v0, :cond_0

    .line 150
    .line 151
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lqp0/b0;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lpp0/a;->a(Lqp0/b0;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
