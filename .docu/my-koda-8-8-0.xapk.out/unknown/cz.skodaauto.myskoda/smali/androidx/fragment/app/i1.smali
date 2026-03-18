.class public final Landroidx/fragment/app/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/fragment/app/g1;


# instance fields
.field public final synthetic a:Landroidx/fragment/app/j1;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/j1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/i1;->a:Landroidx/fragment/app/j1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/ArrayList;Ljava/util/ArrayList;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/i1;->a:Landroidx/fragment/app/j1;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->n:Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const-string v2, "FragmentManager"

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    new-instance v1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v3, "FragmentManager has the following pending actions inside of prepareBackStackState: "

    .line 17
    .line 18
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v3, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    :cond_0
    iget-object v1, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    const/4 v3, 0x0

    .line 40
    const/4 v4, 0x1

    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    const-string p0, "Ignoring call to start back stack pop because the back stack is empty."

    .line 44
    .line 45
    invoke-static {v2, p0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    iget-object v1, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-static {v1, v4}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Landroidx/fragment/app/a;

    .line 56
    .line 57
    iput-object v1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 58
    .line 59
    iget-object v1, v1, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    :cond_2
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-eqz v2, :cond_3

    .line 70
    .line 71
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    check-cast v2, Landroidx/fragment/app/t1;

    .line 76
    .line 77
    iget-object v2, v2, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 78
    .line 79
    if-eqz v2, :cond_2

    .line 80
    .line 81
    iput-boolean v4, v2, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_3
    const/4 v1, -0x1

    .line 85
    invoke-virtual {p0, p1, p2, v1, v3}, Landroidx/fragment/app/j1;->U(Ljava/util/ArrayList;Ljava/util/ArrayList;II)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    :goto_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    if-nez p0, :cond_7

    .line 94
    .line 95
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-lez p0, :cond_7

    .line 100
    .line 101
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    sub-int/2addr p0, v4

    .line 106
    invoke-virtual {p2, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Ljava/lang/Boolean;

    .line 111
    .line 112
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 116
    .line 117
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 125
    .line 126
    .line 127
    move-result p2

    .line 128
    if-eqz p2, :cond_4

    .line 129
    .line 130
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p2

    .line 134
    check-cast p2, Landroidx/fragment/app/a;

    .line 135
    .line 136
    invoke-static {p2}, Landroidx/fragment/app/j1;->G(Landroidx/fragment/app/a;)Ljava/util/HashSet;

    .line 137
    .line 138
    .line 139
    move-result-object p2

    .line 140
    invoke-interface {p0, p2}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 141
    .line 142
    .line 143
    goto :goto_2

    .line 144
    :cond_4
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 149
    .line 150
    .line 151
    move-result p2

    .line 152
    if-eqz p2, :cond_7

    .line 153
    .line 154
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object p2

    .line 158
    if-nez p2, :cond_6

    .line 159
    .line 160
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 161
    .line 162
    .line 163
    move-result-object p2

    .line 164
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    if-nez v0, :cond_5

    .line 169
    .line 170
    goto :goto_3

    .line 171
    :cond_5
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    check-cast p0, Landroidx/fragment/app/j0;

    .line 176
    .line 177
    const/4 p0, 0x0

    .line 178
    throw p0

    .line 179
    :cond_6
    new-instance p0, Ljava/lang/ClassCastException;

    .line 180
    .line 181
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 182
    .line 183
    .line 184
    throw p0

    .line 185
    :cond_7
    return v3
.end method
