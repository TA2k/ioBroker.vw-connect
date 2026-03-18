.class public abstract Landroidx/fragment/app/j1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Landroidx/fragment/app/b1;

.field public final B:Lip/v;

.field public C:Le/g;

.field public D:Le/g;

.field public E:Le/g;

.field public F:Ljava/util/ArrayDeque;

.field public G:Z

.field public H:Z

.field public I:Z

.field public J:Z

.field public K:Z

.field public L:Ljava/util/ArrayList;

.field public M:Ljava/util/ArrayList;

.field public N:Ljava/util/ArrayList;

.field public O:Landroidx/fragment/app/n1;

.field public final P:Landroidx/fragment/app/s;

.field public final a:Ljava/util/ArrayList;

.field public b:Z

.field public final c:Landroidx/fragment/app/s1;

.field public d:Ljava/util/ArrayList;

.field public e:Ljava/util/ArrayList;

.field public final f:Landroidx/fragment/app/v0;

.field public g:Lb/h0;

.field public h:Landroidx/fragment/app/a;

.field public i:Z

.field public final j:Landroidx/fragment/app/z0;

.field public final k:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final l:Ljava/util/Map;

.field public final m:Ljava/util/Map;

.field public final n:Ljava/util/ArrayList;

.field public final o:Landroidx/fragment/app/p0;

.field public final p:Ljava/util/concurrent/CopyOnWriteArrayList;

.field public final q:Landroidx/fragment/app/x0;

.field public final r:Landroidx/fragment/app/x0;

.field public final s:Landroidx/fragment/app/x0;

.field public final t:Landroidx/fragment/app/x0;

.field public final u:Landroidx/fragment/app/a1;

.field public v:I

.field public w:Landroidx/fragment/app/t0;

.field public x:Landroidx/fragment/app/r0;

.field public y:Landroidx/fragment/app/j0;

.field public z:Landroidx/fragment/app/j0;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Landroidx/fragment/app/s1;

    .line 12
    .line 13
    invoke-direct {v0}, Landroidx/fragment/app/s1;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 24
    .line 25
    new-instance v0, Landroidx/fragment/app/v0;

    .line 26
    .line 27
    invoke-direct {v0, p0}, Landroidx/fragment/app/v0;-><init>(Landroidx/fragment/app/j1;)V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Landroidx/fragment/app/j1;->f:Landroidx/fragment/app/v0;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    iput-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->i:Z

    .line 37
    .line 38
    new-instance v0, Landroidx/fragment/app/z0;

    .line 39
    .line 40
    invoke-direct {v0, p0}, Landroidx/fragment/app/z0;-><init>(Landroidx/fragment/app/j1;)V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Landroidx/fragment/app/j1;->j:Landroidx/fragment/app/z0;

    .line 44
    .line 45
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 46
    .line 47
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object v0, p0, Landroidx/fragment/app/j1;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 51
    .line 52
    new-instance v0, Ljava/util/HashMap;

    .line 53
    .line 54
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 55
    .line 56
    .line 57
    invoke-static {v0}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iput-object v0, p0, Landroidx/fragment/app/j1;->l:Ljava/util/Map;

    .line 62
    .line 63
    new-instance v0, Ljava/util/HashMap;

    .line 64
    .line 65
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 66
    .line 67
    .line 68
    invoke-static {v0}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    iput-object v0, p0, Landroidx/fragment/app/j1;->m:Ljava/util/Map;

    .line 73
    .line 74
    new-instance v0, Ljava/util/HashMap;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 77
    .line 78
    .line 79
    invoke-static {v0}, Ljava/util/Collections;->synchronizedMap(Ljava/util/Map;)Ljava/util/Map;

    .line 80
    .line 81
    .line 82
    new-instance v0, Ljava/util/ArrayList;

    .line 83
    .line 84
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 85
    .line 86
    .line 87
    iput-object v0, p0, Landroidx/fragment/app/j1;->n:Ljava/util/ArrayList;

    .line 88
    .line 89
    new-instance v0, Landroidx/fragment/app/p0;

    .line 90
    .line 91
    invoke-direct {v0, p0}, Landroidx/fragment/app/p0;-><init>(Landroidx/fragment/app/j1;)V

    .line 92
    .line 93
    .line 94
    iput-object v0, p0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 95
    .line 96
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 97
    .line 98
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 99
    .line 100
    .line 101
    iput-object v0, p0, Landroidx/fragment/app/j1;->p:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 102
    .line 103
    new-instance v0, Landroidx/fragment/app/x0;

    .line 104
    .line 105
    const/4 v1, 0x0

    .line 106
    invoke-direct {v0, p0, v1}, Landroidx/fragment/app/x0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 107
    .line 108
    .line 109
    iput-object v0, p0, Landroidx/fragment/app/j1;->q:Landroidx/fragment/app/x0;

    .line 110
    .line 111
    new-instance v0, Landroidx/fragment/app/x0;

    .line 112
    .line 113
    const/4 v1, 0x1

    .line 114
    invoke-direct {v0, p0, v1}, Landroidx/fragment/app/x0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 115
    .line 116
    .line 117
    iput-object v0, p0, Landroidx/fragment/app/j1;->r:Landroidx/fragment/app/x0;

    .line 118
    .line 119
    new-instance v0, Landroidx/fragment/app/x0;

    .line 120
    .line 121
    const/4 v1, 0x2

    .line 122
    invoke-direct {v0, p0, v1}, Landroidx/fragment/app/x0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 123
    .line 124
    .line 125
    iput-object v0, p0, Landroidx/fragment/app/j1;->s:Landroidx/fragment/app/x0;

    .line 126
    .line 127
    new-instance v0, Landroidx/fragment/app/x0;

    .line 128
    .line 129
    const/4 v1, 0x3

    .line 130
    invoke-direct {v0, p0, v1}, Landroidx/fragment/app/x0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 131
    .line 132
    .line 133
    iput-object v0, p0, Landroidx/fragment/app/j1;->t:Landroidx/fragment/app/x0;

    .line 134
    .line 135
    new-instance v0, Landroidx/fragment/app/a1;

    .line 136
    .line 137
    invoke-direct {v0, p0}, Landroidx/fragment/app/a1;-><init>(Landroidx/fragment/app/j1;)V

    .line 138
    .line 139
    .line 140
    iput-object v0, p0, Landroidx/fragment/app/j1;->u:Landroidx/fragment/app/a1;

    .line 141
    .line 142
    const/4 v0, -0x1

    .line 143
    iput v0, p0, Landroidx/fragment/app/j1;->v:I

    .line 144
    .line 145
    new-instance v0, Landroidx/fragment/app/b1;

    .line 146
    .line 147
    invoke-direct {v0, p0}, Landroidx/fragment/app/b1;-><init>(Landroidx/fragment/app/j1;)V

    .line 148
    .line 149
    .line 150
    iput-object v0, p0, Landroidx/fragment/app/j1;->A:Landroidx/fragment/app/b1;

    .line 151
    .line 152
    new-instance v0, Lip/v;

    .line 153
    .line 154
    const/4 v1, 0x1

    .line 155
    invoke-direct {v0, v1}, Lip/v;-><init>(I)V

    .line 156
    .line 157
    .line 158
    iput-object v0, p0, Landroidx/fragment/app/j1;->B:Lip/v;

    .line 159
    .line 160
    new-instance v0, Ljava/util/ArrayDeque;

    .line 161
    .line 162
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 163
    .line 164
    .line 165
    iput-object v0, p0, Landroidx/fragment/app/j1;->F:Ljava/util/ArrayDeque;

    .line 166
    .line 167
    new-instance v0, Landroidx/fragment/app/s;

    .line 168
    .line 169
    const/4 v1, 0x2

    .line 170
    invoke-direct {v0, p0, v1}, Landroidx/fragment/app/s;-><init>(Ljava/lang/Object;I)V

    .line 171
    .line 172
    .line 173
    iput-object v0, p0, Landroidx/fragment/app/j1;->P:Landroidx/fragment/app/s;

    .line 174
    .line 175
    return-void
.end method

.method public static E(Landroid/view/View;)Landroidx/fragment/app/j0;
    .locals 3

    .line 1
    :goto_0
    const/4 v0, 0x0

    .line 2
    if-eqz p0, :cond_3

    .line 3
    .line 4
    const v1, 0x7f0a017a

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    instance-of v2, v1, Landroidx/fragment/app/j0;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    check-cast v1, Landroidx/fragment/app/j0;

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    move-object v1, v0

    .line 19
    :goto_1
    if-eqz v1, :cond_1

    .line 20
    .line 21
    return-object v1

    .line 22
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    instance-of v1, p0, Landroid/view/View;

    .line 27
    .line 28
    if-eqz v1, :cond_2

    .line 29
    .line 30
    check-cast p0, Landroid/view/View;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    move-object p0, v0

    .line 34
    goto :goto_0

    .line 35
    :cond_3
    return-object v0
.end method

.method public static G(Landroidx/fragment/app/a;)Ljava/util/HashSet;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    :goto_0
    iget-object v2, p0, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-ge v1, v2, :cond_1

    .line 14
    .line 15
    iget-object v2, p0, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Landroidx/fragment/app/t1;

    .line 22
    .line 23
    iget-object v2, v2, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 24
    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    iget-boolean v3, p0, Landroidx/fragment/app/a;->g:Z

    .line 28
    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    return-object v0
.end method

.method public static L(I)Z
    .locals 1

    .line 1
    const-string v0, "FragmentManager"

    .line 2
    .line 3
    invoke-static {v0, p0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public static M(Landroidx/fragment/app/j0;)Z
    .locals 3

    .line 1
    iget-boolean v0, p0, Landroidx/fragment/app/j0;->mHasMenu:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Landroidx/fragment/app/j0;->mMenuVisible:Z

    .line 6
    .line 7
    if-nez v0, :cond_3

    .line 8
    .line 9
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 10
    .line 11
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 12
    .line 13
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->e()Ljava/util/ArrayList;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const/4 v0, 0x0

    .line 22
    move v1, v0

    .line 23
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_4

    .line 28
    .line 29
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    check-cast v2, Landroidx/fragment/app/j0;

    .line 34
    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    invoke-static {v2}, Landroidx/fragment/app/j1;->M(Landroidx/fragment/app/j0;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    :cond_2
    if-eqz v1, :cond_1

    .line 42
    .line 43
    :cond_3
    const/4 p0, 0x1

    .line 44
    return p0

    .line 45
    :cond_4
    return v0
.end method

.method public static O(Landroidx/fragment/app/j0;)Z
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    iget-object v0, p0, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 5
    .line 6
    iget-object v1, v0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Landroidx/fragment/app/j0;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    iget-object p0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 15
    .line 16
    invoke-static {p0}, Landroidx/fragment/app/j1;->O(Landroidx/fragment/app/j0;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public static e0(Landroidx/fragment/app/j0;)V
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "show: "

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "FragmentManager"

    .line 23
    .line 24
    invoke-static {v1, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-boolean v0, p0, Landroidx/fragment/app/j0;->mHidden:Z

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    iput-boolean v0, p0, Landroidx/fragment/app/j0;->mHidden:Z

    .line 33
    .line 34
    iget-boolean v0, p0, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 35
    .line 36
    xor-int/lit8 v0, v0, 0x1

    .line 37
    .line 38
    iput-boolean v0, p0, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 39
    .line 40
    :cond_1
    return-void
.end method


# virtual methods
.method public final A(Landroidx/fragment/app/a;Z)V
    .locals 4

    .line 1
    if-eqz p2, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-boolean v0, p0, Landroidx/fragment/app/j1;->J:Z

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    :cond_0
    return-void

    .line 12
    :cond_1
    invoke-virtual {p0, p2}, Landroidx/fragment/app/j1;->y(Z)V

    .line 13
    .line 14
    .line 15
    iget-object p2, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    const/4 v1, 0x0

    .line 19
    if-eqz p2, :cond_5

    .line 20
    .line 21
    iput-boolean v1, p2, Landroidx/fragment/app/a;->r:Z

    .line 22
    .line 23
    invoke-virtual {p2}, Landroidx/fragment/app/a;->d()V

    .line 24
    .line 25
    .line 26
    const/4 p2, 0x3

    .line 27
    invoke-static {p2}, Landroidx/fragment/app/j1;->L(I)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_2

    .line 32
    .line 33
    new-instance p2, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    const-string v2, "Reversing mTransitioningOp "

    .line 36
    .line 37
    invoke-direct {p2, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    iget-object v2, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 41
    .line 42
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v2, " as part of execSingleAction for action "

    .line 46
    .line 47
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    const-string v2, "FragmentManager"

    .line 58
    .line 59
    invoke-static {v2, p2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 60
    .line 61
    .line 62
    :cond_2
    iget-object p2, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 63
    .line 64
    invoke-virtual {p2, v1, v1}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 65
    .line 66
    .line 67
    iget-object p2, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 68
    .line 69
    iget-object v2, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 70
    .line 71
    iget-object v3, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-virtual {p2, v2, v3}, Landroidx/fragment/app/a;->a(Ljava/util/ArrayList;Ljava/util/ArrayList;)Z

    .line 74
    .line 75
    .line 76
    iget-object p2, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 77
    .line 78
    iget-object p2, p2, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    :cond_3
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-eqz v2, :cond_4

    .line 89
    .line 90
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    check-cast v2, Landroidx/fragment/app/t1;

    .line 95
    .line 96
    iget-object v2, v2, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 97
    .line 98
    if-eqz v2, :cond_3

    .line 99
    .line 100
    iput-boolean v1, v2, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_4
    iput-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 104
    .line 105
    :cond_5
    iget-object p2, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 106
    .line 107
    iget-object v2, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 108
    .line 109
    invoke-virtual {p1, p2, v2}, Landroidx/fragment/app/a;->a(Ljava/util/ArrayList;Ljava/util/ArrayList;)Z

    .line 110
    .line 111
    .line 112
    const/4 p1, 0x1

    .line 113
    iput-boolean p1, p0, Landroidx/fragment/app/j1;->b:Z

    .line 114
    .line 115
    :try_start_0
    iget-object p1, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 116
    .line 117
    iget-object p2, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-virtual {p0, p1, p2}, Landroidx/fragment/app/j1;->W(Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->d()V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->g0()V

    .line 126
    .line 127
    .line 128
    iget-boolean p1, p0, Landroidx/fragment/app/j1;->K:Z

    .line 129
    .line 130
    if-eqz p1, :cond_8

    .line 131
    .line 132
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->K:Z

    .line 133
    .line 134
    iget-object p1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 135
    .line 136
    invoke-virtual {p1}, Landroidx/fragment/app/s1;->d()Ljava/util/ArrayList;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    :cond_6
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    if-eqz p2, :cond_8

    .line 149
    .line 150
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p2

    .line 154
    check-cast p2, Landroidx/fragment/app/r1;

    .line 155
    .line 156
    iget-object v1, p2, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 157
    .line 158
    iget-boolean v2, v1, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 159
    .line 160
    if-eqz v2, :cond_6

    .line 161
    .line 162
    iget-boolean v2, p0, Landroidx/fragment/app/j1;->b:Z

    .line 163
    .line 164
    if-eqz v2, :cond_7

    .line 165
    .line 166
    const/4 p2, 0x1

    .line 167
    iput-boolean p2, p0, Landroidx/fragment/app/j1;->K:Z

    .line 168
    .line 169
    goto :goto_1

    .line 170
    :cond_7
    const/4 v2, 0x0

    .line 171
    iput-boolean v2, v1, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 172
    .line 173
    invoke-virtual {p2}, Landroidx/fragment/app/r1;->k()V

    .line 174
    .line 175
    .line 176
    goto :goto_1

    .line 177
    :cond_8
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 178
    .line 179
    iget-object p0, p0, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 180
    .line 181
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    invoke-interface {p0, p1}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 190
    .line 191
    .line 192
    return-void

    .line 193
    :catchall_0
    move-exception p1

    .line 194
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->d()V

    .line 195
    .line 196
    .line 197
    throw p1
.end method

.method public final B(Ljava/util/ArrayList;Ljava/util/ArrayList;II)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    move/from16 v4, p4

    .line 10
    .line 11
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v5

    .line 15
    check-cast v5, Landroidx/fragment/app/a;

    .line 16
    .line 17
    iget-boolean v5, v5, Landroidx/fragment/app/a;->o:Z

    .line 18
    .line 19
    iget-object v6, v0, Landroidx/fragment/app/j1;->N:Ljava/util/ArrayList;

    .line 20
    .line 21
    if-nez v6, :cond_0

    .line 22
    .line 23
    new-instance v6, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v6, v0, Landroidx/fragment/app/j1;->N:Ljava/util/ArrayList;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {v6}, Ljava/util/ArrayList;->clear()V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget-object v6, v0, Landroidx/fragment/app/j1;->N:Ljava/util/ArrayList;

    .line 35
    .line 36
    iget-object v7, v0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 37
    .line 38
    invoke-virtual {v7}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 39
    .line 40
    .line 41
    move-result-object v8

    .line 42
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 43
    .line 44
    .line 45
    iget-object v6, v0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 46
    .line 47
    move v9, v3

    .line 48
    const/4 v10, 0x0

    .line 49
    :goto_1
    const/4 v12, 0x1

    .line 50
    if-ge v9, v4, :cond_13

    .line 51
    .line 52
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v13

    .line 56
    check-cast v13, Landroidx/fragment/app/a;

    .line 57
    .line 58
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v14

    .line 62
    check-cast v14, Ljava/lang/Boolean;

    .line 63
    .line 64
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 65
    .line 66
    .line 67
    move-result v14

    .line 68
    if-nez v14, :cond_d

    .line 69
    .line 70
    iget-object v14, v0, Landroidx/fragment/app/j1;->N:Ljava/util/ArrayList;

    .line 71
    .line 72
    iget-object v11, v13, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 73
    .line 74
    const/4 v8, 0x0

    .line 75
    :goto_2
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 76
    .line 77
    .line 78
    move-result v15

    .line 79
    if-ge v8, v15, :cond_c

    .line 80
    .line 81
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v15

    .line 85
    check-cast v15, Landroidx/fragment/app/t1;

    .line 86
    .line 87
    move/from16 v18, v5

    .line 88
    .line 89
    iget v5, v15, Landroidx/fragment/app/t1;->a:I

    .line 90
    .line 91
    if-eq v5, v12, :cond_b

    .line 92
    .line 93
    const/4 v12, 0x2

    .line 94
    move/from16 v20, v9

    .line 95
    .line 96
    const/16 v9, 0x9

    .line 97
    .line 98
    if-eq v5, v12, :cond_5

    .line 99
    .line 100
    const/4 v12, 0x3

    .line 101
    if-eq v5, v12, :cond_4

    .line 102
    .line 103
    const/4 v12, 0x6

    .line 104
    if-eq v5, v12, :cond_4

    .line 105
    .line 106
    const/4 v12, 0x7

    .line 107
    if-eq v5, v12, :cond_3

    .line 108
    .line 109
    const/16 v12, 0x8

    .line 110
    .line 111
    if-eq v5, v12, :cond_1

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_1
    new-instance v5, Landroidx/fragment/app/t1;

    .line 115
    .line 116
    const/4 v12, 0x0

    .line 117
    invoke-direct {v5, v9, v6, v12}, Landroidx/fragment/app/t1;-><init>(ILandroidx/fragment/app/j0;I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v11, v8, v5}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    const/4 v5, 0x1

    .line 124
    iput-boolean v5, v15, Landroidx/fragment/app/t1;->c:Z

    .line 125
    .line 126
    add-int/lit8 v8, v8, 0x1

    .line 127
    .line 128
    iget-object v5, v15, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 129
    .line 130
    move-object v6, v5

    .line 131
    :cond_2
    :goto_3
    move/from16 v23, v10

    .line 132
    .line 133
    :goto_4
    const/4 v9, 0x1

    .line 134
    goto/16 :goto_a

    .line 135
    .line 136
    :cond_3
    const/4 v9, 0x1

    .line 137
    :goto_5
    move/from16 v23, v10

    .line 138
    .line 139
    goto/16 :goto_9

    .line 140
    .line 141
    :cond_4
    iget-object v5, v15, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 142
    .line 143
    invoke-virtual {v14, v5}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    iget-object v5, v15, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 147
    .line 148
    if-ne v5, v6, :cond_2

    .line 149
    .line 150
    new-instance v6, Landroidx/fragment/app/t1;

    .line 151
    .line 152
    invoke-direct {v6, v5, v9}, Landroidx/fragment/app/t1;-><init>(Landroidx/fragment/app/j0;I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v11, v8, v6}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    add-int/lit8 v8, v8, 0x1

    .line 159
    .line 160
    move/from16 v23, v10

    .line 161
    .line 162
    const/4 v6, 0x0

    .line 163
    goto :goto_4

    .line 164
    :cond_5
    iget-object v5, v15, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 165
    .line 166
    iget v12, v5, Landroidx/fragment/app/j0;->mContainerId:I

    .line 167
    .line 168
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 169
    .line 170
    .line 171
    move-result v21

    .line 172
    const/16 v19, 0x1

    .line 173
    .line 174
    add-int/lit8 v21, v21, -0x1

    .line 175
    .line 176
    move/from16 v9, v21

    .line 177
    .line 178
    const/16 v21, 0x0

    .line 179
    .line 180
    :goto_6
    if-ltz v9, :cond_9

    .line 181
    .line 182
    invoke-virtual {v14, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v23

    .line 186
    move/from16 v24, v9

    .line 187
    .line 188
    move-object/from16 v9, v23

    .line 189
    .line 190
    check-cast v9, Landroidx/fragment/app/j0;

    .line 191
    .line 192
    move/from16 v23, v10

    .line 193
    .line 194
    iget v10, v9, Landroidx/fragment/app/j0;->mContainerId:I

    .line 195
    .line 196
    if-ne v10, v12, :cond_8

    .line 197
    .line 198
    if-ne v9, v5, :cond_6

    .line 199
    .line 200
    move/from16 v22, v12

    .line 201
    .line 202
    const/4 v9, 0x1

    .line 203
    const/16 v21, 0x1

    .line 204
    .line 205
    goto :goto_8

    .line 206
    :cond_6
    if-ne v9, v6, :cond_7

    .line 207
    .line 208
    new-instance v6, Landroidx/fragment/app/t1;

    .line 209
    .line 210
    move/from16 v22, v12

    .line 211
    .line 212
    const/4 v10, 0x0

    .line 213
    const/16 v12, 0x9

    .line 214
    .line 215
    invoke-direct {v6, v12, v9, v10}, Landroidx/fragment/app/t1;-><init>(ILandroidx/fragment/app/j0;I)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v11, v8, v6}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    add-int/lit8 v8, v8, 0x1

    .line 222
    .line 223
    const/4 v6, 0x0

    .line 224
    goto :goto_7

    .line 225
    :cond_7
    move/from16 v22, v12

    .line 226
    .line 227
    const/4 v10, 0x0

    .line 228
    const/16 v12, 0x9

    .line 229
    .line 230
    :goto_7
    new-instance v12, Landroidx/fragment/app/t1;

    .line 231
    .line 232
    move-object/from16 v25, v6

    .line 233
    .line 234
    const/4 v6, 0x3

    .line 235
    invoke-direct {v12, v6, v9, v10}, Landroidx/fragment/app/t1;-><init>(ILandroidx/fragment/app/j0;I)V

    .line 236
    .line 237
    .line 238
    iget v6, v15, Landroidx/fragment/app/t1;->d:I

    .line 239
    .line 240
    iput v6, v12, Landroidx/fragment/app/t1;->d:I

    .line 241
    .line 242
    iget v6, v15, Landroidx/fragment/app/t1;->f:I

    .line 243
    .line 244
    iput v6, v12, Landroidx/fragment/app/t1;->f:I

    .line 245
    .line 246
    iget v6, v15, Landroidx/fragment/app/t1;->e:I

    .line 247
    .line 248
    iput v6, v12, Landroidx/fragment/app/t1;->e:I

    .line 249
    .line 250
    iget v6, v15, Landroidx/fragment/app/t1;->g:I

    .line 251
    .line 252
    iput v6, v12, Landroidx/fragment/app/t1;->g:I

    .line 253
    .line 254
    invoke-virtual {v11, v8, v12}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v14, v9}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    const/4 v9, 0x1

    .line 261
    add-int/2addr v8, v9

    .line 262
    move-object/from16 v6, v25

    .line 263
    .line 264
    goto :goto_8

    .line 265
    :cond_8
    move/from16 v22, v12

    .line 266
    .line 267
    const/4 v9, 0x1

    .line 268
    :goto_8
    add-int/lit8 v10, v24, -0x1

    .line 269
    .line 270
    move v9, v10

    .line 271
    move/from16 v12, v22

    .line 272
    .line 273
    move/from16 v10, v23

    .line 274
    .line 275
    goto :goto_6

    .line 276
    :cond_9
    move/from16 v23, v10

    .line 277
    .line 278
    const/4 v9, 0x1

    .line 279
    if-eqz v21, :cond_a

    .line 280
    .line 281
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    add-int/lit8 v8, v8, -0x1

    .line 285
    .line 286
    goto :goto_a

    .line 287
    :cond_a
    iput v9, v15, Landroidx/fragment/app/t1;->a:I

    .line 288
    .line 289
    iput-boolean v9, v15, Landroidx/fragment/app/t1;->c:Z

    .line 290
    .line 291
    invoke-virtual {v14, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 292
    .line 293
    .line 294
    goto :goto_a

    .line 295
    :cond_b
    move/from16 v20, v9

    .line 296
    .line 297
    move v9, v12

    .line 298
    goto/16 :goto_5

    .line 299
    .line 300
    :goto_9
    iget-object v5, v15, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 301
    .line 302
    invoke-virtual {v14, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    :goto_a
    add-int/2addr v8, v9

    .line 306
    move v12, v9

    .line 307
    move/from16 v5, v18

    .line 308
    .line 309
    move/from16 v9, v20

    .line 310
    .line 311
    move/from16 v10, v23

    .line 312
    .line 313
    goto/16 :goto_2

    .line 314
    .line 315
    :cond_c
    move/from16 v18, v5

    .line 316
    .line 317
    move/from16 v20, v9

    .line 318
    .line 319
    move/from16 v23, v10

    .line 320
    .line 321
    goto :goto_d

    .line 322
    :cond_d
    move/from16 v18, v5

    .line 323
    .line 324
    move/from16 v20, v9

    .line 325
    .line 326
    move/from16 v23, v10

    .line 327
    .line 328
    move v9, v12

    .line 329
    iget-object v5, v0, Landroidx/fragment/app/j1;->N:Ljava/util/ArrayList;

    .line 330
    .line 331
    iget-object v8, v13, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 332
    .line 333
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 334
    .line 335
    .line 336
    move-result v10

    .line 337
    sub-int/2addr v10, v9

    .line 338
    :goto_b
    if-ltz v10, :cond_10

    .line 339
    .line 340
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v11

    .line 344
    check-cast v11, Landroidx/fragment/app/t1;

    .line 345
    .line 346
    iget v12, v11, Landroidx/fragment/app/t1;->a:I

    .line 347
    .line 348
    if-eq v12, v9, :cond_f

    .line 349
    .line 350
    const/4 v9, 0x3

    .line 351
    if-eq v12, v9, :cond_e

    .line 352
    .line 353
    packed-switch v12, :pswitch_data_0

    .line 354
    .line 355
    .line 356
    goto :goto_c

    .line 357
    :pswitch_0
    iget-object v12, v11, Landroidx/fragment/app/t1;->h:Landroidx/lifecycle/q;

    .line 358
    .line 359
    iput-object v12, v11, Landroidx/fragment/app/t1;->i:Landroidx/lifecycle/q;

    .line 360
    .line 361
    goto :goto_c

    .line 362
    :pswitch_1
    iget-object v6, v11, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 363
    .line 364
    goto :goto_c

    .line 365
    :pswitch_2
    const/4 v6, 0x0

    .line 366
    goto :goto_c

    .line 367
    :cond_e
    :pswitch_3
    iget-object v11, v11, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 368
    .line 369
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    goto :goto_c

    .line 373
    :cond_f
    const/4 v9, 0x3

    .line 374
    :pswitch_4
    iget-object v11, v11, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 375
    .line 376
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 377
    .line 378
    .line 379
    :goto_c
    add-int/lit8 v10, v10, -0x1

    .line 380
    .line 381
    const/4 v9, 0x1

    .line 382
    goto :goto_b

    .line 383
    :cond_10
    :goto_d
    if-nez v23, :cond_12

    .line 384
    .line 385
    iget-boolean v5, v13, Landroidx/fragment/app/a;->g:Z

    .line 386
    .line 387
    if-eqz v5, :cond_11

    .line 388
    .line 389
    goto :goto_e

    .line 390
    :cond_11
    const/4 v10, 0x0

    .line 391
    goto :goto_f

    .line 392
    :cond_12
    :goto_e
    const/4 v10, 0x1

    .line 393
    :goto_f
    add-int/lit8 v9, v20, 0x1

    .line 394
    .line 395
    move/from16 v5, v18

    .line 396
    .line 397
    goto/16 :goto_1

    .line 398
    .line 399
    :cond_13
    move/from16 v18, v5

    .line 400
    .line 401
    move/from16 v23, v10

    .line 402
    .line 403
    iget-object v5, v0, Landroidx/fragment/app/j1;->N:Ljava/util/ArrayList;

    .line 404
    .line 405
    invoke-virtual {v5}, Ljava/util/ArrayList;->clear()V

    .line 406
    .line 407
    .line 408
    if-nez v18, :cond_16

    .line 409
    .line 410
    iget v5, v0, Landroidx/fragment/app/j1;->v:I

    .line 411
    .line 412
    const/4 v9, 0x1

    .line 413
    if-lt v5, v9, :cond_16

    .line 414
    .line 415
    move v5, v3

    .line 416
    :goto_10
    if-ge v5, v4, :cond_16

    .line 417
    .line 418
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v6

    .line 422
    check-cast v6, Landroidx/fragment/app/a;

    .line 423
    .line 424
    iget-object v6, v6, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 425
    .line 426
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 427
    .line 428
    .line 429
    move-result-object v6

    .line 430
    :cond_14
    :goto_11
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 431
    .line 432
    .line 433
    move-result v8

    .line 434
    if-eqz v8, :cond_15

    .line 435
    .line 436
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v8

    .line 440
    check-cast v8, Landroidx/fragment/app/t1;

    .line 441
    .line 442
    iget-object v8, v8, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 443
    .line 444
    if-eqz v8, :cond_14

    .line 445
    .line 446
    iget-object v9, v8, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 447
    .line 448
    if-eqz v9, :cond_14

    .line 449
    .line 450
    invoke-virtual {v0, v8}, Landroidx/fragment/app/j1;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 451
    .line 452
    .line 453
    move-result-object v8

    .line 454
    invoke-virtual {v7, v8}, Landroidx/fragment/app/s1;->g(Landroidx/fragment/app/r1;)V

    .line 455
    .line 456
    .line 457
    goto :goto_11

    .line 458
    :cond_15
    add-int/lit8 v5, v5, 0x1

    .line 459
    .line 460
    goto :goto_10

    .line 461
    :cond_16
    move v5, v3

    .line 462
    :goto_12
    const/4 v6, -0x1

    .line 463
    if-ge v5, v4, :cond_1e

    .line 464
    .line 465
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    move-result-object v7

    .line 469
    check-cast v7, Landroidx/fragment/app/a;

    .line 470
    .line 471
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object v8

    .line 475
    check-cast v8, Ljava/lang/Boolean;

    .line 476
    .line 477
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 478
    .line 479
    .line 480
    move-result v8

    .line 481
    const-string v9, "Unknown cmd: "

    .line 482
    .line 483
    if-eqz v8, :cond_1c

    .line 484
    .line 485
    invoke-virtual {v7, v6}, Landroidx/fragment/app/a;->c(I)V

    .line 486
    .line 487
    .line 488
    iget-object v6, v7, Landroidx/fragment/app/a;->q:Landroidx/fragment/app/j1;

    .line 489
    .line 490
    iget-object v8, v7, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 491
    .line 492
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 493
    .line 494
    .line 495
    move-result v10

    .line 496
    const/4 v11, 0x1

    .line 497
    sub-int/2addr v10, v11

    .line 498
    :goto_13
    if-ltz v10, :cond_1b

    .line 499
    .line 500
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object v12

    .line 504
    check-cast v12, Landroidx/fragment/app/t1;

    .line 505
    .line 506
    iget-object v13, v12, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 507
    .line 508
    if-eqz v13, :cond_1a

    .line 509
    .line 510
    const/4 v14, 0x0

    .line 511
    iput-boolean v14, v13, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 512
    .line 513
    invoke-virtual {v13, v11}, Landroidx/fragment/app/j0;->setPopDirection(Z)V

    .line 514
    .line 515
    .line 516
    iget v11, v7, Landroidx/fragment/app/a;->f:I

    .line 517
    .line 518
    const/16 v14, 0x2002

    .line 519
    .line 520
    const/16 v15, 0x1001

    .line 521
    .line 522
    if-eq v11, v15, :cond_19

    .line 523
    .line 524
    if-eq v11, v14, :cond_18

    .line 525
    .line 526
    const/16 v14, 0x1004

    .line 527
    .line 528
    const/16 v15, 0x2005

    .line 529
    .line 530
    if-eq v11, v15, :cond_19

    .line 531
    .line 532
    const/16 v15, 0x1003

    .line 533
    .line 534
    if-eq v11, v15, :cond_18

    .line 535
    .line 536
    if-eq v11, v14, :cond_17

    .line 537
    .line 538
    const/4 v14, 0x0

    .line 539
    goto :goto_14

    .line 540
    :cond_17
    const/16 v14, 0x2005

    .line 541
    .line 542
    goto :goto_14

    .line 543
    :cond_18
    move v14, v15

    .line 544
    :cond_19
    :goto_14
    invoke-virtual {v13, v14}, Landroidx/fragment/app/j0;->setNextTransition(I)V

    .line 545
    .line 546
    .line 547
    iget-object v11, v7, Landroidx/fragment/app/a;->n:Ljava/util/ArrayList;

    .line 548
    .line 549
    iget-object v14, v7, Landroidx/fragment/app/a;->m:Ljava/util/ArrayList;

    .line 550
    .line 551
    invoke-virtual {v13, v11, v14}, Landroidx/fragment/app/j0;->setSharedElementNames(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 552
    .line 553
    .line 554
    :cond_1a
    iget v11, v12, Landroidx/fragment/app/t1;->a:I

    .line 555
    .line 556
    packed-switch v11, :pswitch_data_1

    .line 557
    .line 558
    .line 559
    :pswitch_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 560
    .line 561
    new-instance v1, Ljava/lang/StringBuilder;

    .line 562
    .line 563
    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 564
    .line 565
    .line 566
    iget v2, v12, Landroidx/fragment/app/t1;->a:I

    .line 567
    .line 568
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 569
    .line 570
    .line 571
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 572
    .line 573
    .line 574
    move-result-object v1

    .line 575
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    throw v0

    .line 579
    :pswitch_6
    iget-object v11, v13, Landroidx/fragment/app/j0;->mMaxState:Landroidx/lifecycle/q;

    .line 580
    .line 581
    iput-object v11, v12, Landroidx/fragment/app/t1;->i:Landroidx/lifecycle/q;

    .line 582
    .line 583
    iget-object v11, v12, Landroidx/fragment/app/t1;->h:Landroidx/lifecycle/q;

    .line 584
    .line 585
    invoke-virtual {v6, v13, v11}, Landroidx/fragment/app/j1;->b0(Landroidx/fragment/app/j0;Landroidx/lifecycle/q;)V

    .line 586
    .line 587
    .line 588
    :goto_15
    const/4 v11, 0x1

    .line 589
    goto/16 :goto_16

    .line 590
    .line 591
    :pswitch_7
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->c0(Landroidx/fragment/app/j0;)V

    .line 592
    .line 593
    .line 594
    goto :goto_15

    .line 595
    :pswitch_8
    const/4 v11, 0x0

    .line 596
    invoke-virtual {v6, v11}, Landroidx/fragment/app/j1;->c0(Landroidx/fragment/app/j0;)V

    .line 597
    .line 598
    .line 599
    goto :goto_15

    .line 600
    :pswitch_9
    iget v11, v12, Landroidx/fragment/app/t1;->d:I

    .line 601
    .line 602
    iget v14, v12, Landroidx/fragment/app/t1;->e:I

    .line 603
    .line 604
    iget v15, v12, Landroidx/fragment/app/t1;->f:I

    .line 605
    .line 606
    iget v12, v12, Landroidx/fragment/app/t1;->g:I

    .line 607
    .line 608
    invoke-virtual {v13, v11, v14, v15, v12}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 609
    .line 610
    .line 611
    const/4 v11, 0x1

    .line 612
    invoke-virtual {v6, v13, v11}, Landroidx/fragment/app/j1;->a0(Landroidx/fragment/app/j0;Z)V

    .line 613
    .line 614
    .line 615
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->h(Landroidx/fragment/app/j0;)V

    .line 616
    .line 617
    .line 618
    goto :goto_15

    .line 619
    :pswitch_a
    iget v11, v12, Landroidx/fragment/app/t1;->d:I

    .line 620
    .line 621
    iget v14, v12, Landroidx/fragment/app/t1;->e:I

    .line 622
    .line 623
    iget v15, v12, Landroidx/fragment/app/t1;->f:I

    .line 624
    .line 625
    iget v12, v12, Landroidx/fragment/app/t1;->g:I

    .line 626
    .line 627
    invoke-virtual {v13, v11, v14, v15, v12}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 628
    .line 629
    .line 630
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->c(Landroidx/fragment/app/j0;)V

    .line 631
    .line 632
    .line 633
    goto :goto_15

    .line 634
    :pswitch_b
    iget v11, v12, Landroidx/fragment/app/t1;->d:I

    .line 635
    .line 636
    iget v14, v12, Landroidx/fragment/app/t1;->e:I

    .line 637
    .line 638
    iget v15, v12, Landroidx/fragment/app/t1;->f:I

    .line 639
    .line 640
    iget v12, v12, Landroidx/fragment/app/t1;->g:I

    .line 641
    .line 642
    invoke-virtual {v13, v11, v14, v15, v12}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 643
    .line 644
    .line 645
    const/4 v11, 0x1

    .line 646
    invoke-virtual {v6, v13, v11}, Landroidx/fragment/app/j1;->a0(Landroidx/fragment/app/j0;Z)V

    .line 647
    .line 648
    .line 649
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->K(Landroidx/fragment/app/j0;)V

    .line 650
    .line 651
    .line 652
    goto :goto_15

    .line 653
    :pswitch_c
    iget v11, v12, Landroidx/fragment/app/t1;->d:I

    .line 654
    .line 655
    iget v14, v12, Landroidx/fragment/app/t1;->e:I

    .line 656
    .line 657
    iget v15, v12, Landroidx/fragment/app/t1;->f:I

    .line 658
    .line 659
    iget v12, v12, Landroidx/fragment/app/t1;->g:I

    .line 660
    .line 661
    invoke-virtual {v13, v11, v14, v15, v12}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 662
    .line 663
    .line 664
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 665
    .line 666
    .line 667
    invoke-static {v13}, Landroidx/fragment/app/j1;->e0(Landroidx/fragment/app/j0;)V

    .line 668
    .line 669
    .line 670
    goto :goto_15

    .line 671
    :pswitch_d
    iget v11, v12, Landroidx/fragment/app/t1;->d:I

    .line 672
    .line 673
    iget v14, v12, Landroidx/fragment/app/t1;->e:I

    .line 674
    .line 675
    iget v15, v12, Landroidx/fragment/app/t1;->f:I

    .line 676
    .line 677
    iget v12, v12, Landroidx/fragment/app/t1;->g:I

    .line 678
    .line 679
    invoke-virtual {v13, v11, v14, v15, v12}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 680
    .line 681
    .line 682
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->a(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 683
    .line 684
    .line 685
    goto :goto_15

    .line 686
    :pswitch_e
    iget v11, v12, Landroidx/fragment/app/t1;->d:I

    .line 687
    .line 688
    iget v14, v12, Landroidx/fragment/app/t1;->e:I

    .line 689
    .line 690
    iget v15, v12, Landroidx/fragment/app/t1;->f:I

    .line 691
    .line 692
    iget v12, v12, Landroidx/fragment/app/t1;->g:I

    .line 693
    .line 694
    invoke-virtual {v13, v11, v14, v15, v12}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 695
    .line 696
    .line 697
    const/4 v11, 0x1

    .line 698
    invoke-virtual {v6, v13, v11}, Landroidx/fragment/app/j1;->a0(Landroidx/fragment/app/j0;Z)V

    .line 699
    .line 700
    .line 701
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->V(Landroidx/fragment/app/j0;)V

    .line 702
    .line 703
    .line 704
    :goto_16
    add-int/lit8 v10, v10, -0x1

    .line 705
    .line 706
    goto/16 :goto_13

    .line 707
    .line 708
    :cond_1b
    move/from16 v17, v5

    .line 709
    .line 710
    goto/16 :goto_1a

    .line 711
    .line 712
    :cond_1c
    const/4 v11, 0x1

    .line 713
    invoke-virtual {v7, v11}, Landroidx/fragment/app/a;->c(I)V

    .line 714
    .line 715
    .line 716
    iget-object v6, v7, Landroidx/fragment/app/a;->q:Landroidx/fragment/app/j1;

    .line 717
    .line 718
    iget-object v8, v7, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 719
    .line 720
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 721
    .line 722
    .line 723
    move-result v10

    .line 724
    const/4 v12, 0x0

    .line 725
    :goto_17
    if-ge v12, v10, :cond_1b

    .line 726
    .line 727
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 728
    .line 729
    .line 730
    move-result-object v11

    .line 731
    check-cast v11, Landroidx/fragment/app/t1;

    .line 732
    .line 733
    iget-object v13, v11, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 734
    .line 735
    if-eqz v13, :cond_1d

    .line 736
    .line 737
    const/4 v14, 0x0

    .line 738
    iput-boolean v14, v13, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 739
    .line 740
    invoke-virtual {v13, v14}, Landroidx/fragment/app/j0;->setPopDirection(Z)V

    .line 741
    .line 742
    .line 743
    iget v14, v7, Landroidx/fragment/app/a;->f:I

    .line 744
    .line 745
    invoke-virtual {v13, v14}, Landroidx/fragment/app/j0;->setNextTransition(I)V

    .line 746
    .line 747
    .line 748
    iget-object v14, v7, Landroidx/fragment/app/a;->m:Ljava/util/ArrayList;

    .line 749
    .line 750
    iget-object v15, v7, Landroidx/fragment/app/a;->n:Ljava/util/ArrayList;

    .line 751
    .line 752
    invoke-virtual {v13, v14, v15}, Landroidx/fragment/app/j0;->setSharedElementNames(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 753
    .line 754
    .line 755
    :cond_1d
    iget v14, v11, Landroidx/fragment/app/t1;->a:I

    .line 756
    .line 757
    packed-switch v14, :pswitch_data_2

    .line 758
    .line 759
    .line 760
    :pswitch_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 761
    .line 762
    new-instance v1, Ljava/lang/StringBuilder;

    .line 763
    .line 764
    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 765
    .line 766
    .line 767
    iget v2, v11, Landroidx/fragment/app/t1;->a:I

    .line 768
    .line 769
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 770
    .line 771
    .line 772
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 773
    .line 774
    .line 775
    move-result-object v1

    .line 776
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 777
    .line 778
    .line 779
    throw v0

    .line 780
    :pswitch_10
    iget-object v14, v13, Landroidx/fragment/app/j0;->mMaxState:Landroidx/lifecycle/q;

    .line 781
    .line 782
    iput-object v14, v11, Landroidx/fragment/app/t1;->h:Landroidx/lifecycle/q;

    .line 783
    .line 784
    iget-object v11, v11, Landroidx/fragment/app/t1;->i:Landroidx/lifecycle/q;

    .line 785
    .line 786
    invoke-virtual {v6, v13, v11}, Landroidx/fragment/app/j1;->b0(Landroidx/fragment/app/j0;Landroidx/lifecycle/q;)V

    .line 787
    .line 788
    .line 789
    :goto_18
    move/from16 v17, v5

    .line 790
    .line 791
    goto/16 :goto_19

    .line 792
    .line 793
    :pswitch_11
    const/4 v11, 0x0

    .line 794
    invoke-virtual {v6, v11}, Landroidx/fragment/app/j1;->c0(Landroidx/fragment/app/j0;)V

    .line 795
    .line 796
    .line 797
    goto :goto_18

    .line 798
    :pswitch_12
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->c0(Landroidx/fragment/app/j0;)V

    .line 799
    .line 800
    .line 801
    goto :goto_18

    .line 802
    :pswitch_13
    iget v14, v11, Landroidx/fragment/app/t1;->d:I

    .line 803
    .line 804
    iget v15, v11, Landroidx/fragment/app/t1;->e:I

    .line 805
    .line 806
    move/from16 v17, v5

    .line 807
    .line 808
    iget v5, v11, Landroidx/fragment/app/t1;->f:I

    .line 809
    .line 810
    iget v11, v11, Landroidx/fragment/app/t1;->g:I

    .line 811
    .line 812
    invoke-virtual {v13, v14, v15, v5, v11}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 813
    .line 814
    .line 815
    const/4 v14, 0x0

    .line 816
    invoke-virtual {v6, v13, v14}, Landroidx/fragment/app/j1;->a0(Landroidx/fragment/app/j0;Z)V

    .line 817
    .line 818
    .line 819
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->c(Landroidx/fragment/app/j0;)V

    .line 820
    .line 821
    .line 822
    goto :goto_19

    .line 823
    :pswitch_14
    move/from16 v17, v5

    .line 824
    .line 825
    iget v5, v11, Landroidx/fragment/app/t1;->d:I

    .line 826
    .line 827
    iget v14, v11, Landroidx/fragment/app/t1;->e:I

    .line 828
    .line 829
    iget v15, v11, Landroidx/fragment/app/t1;->f:I

    .line 830
    .line 831
    iget v11, v11, Landroidx/fragment/app/t1;->g:I

    .line 832
    .line 833
    invoke-virtual {v13, v5, v14, v15, v11}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 834
    .line 835
    .line 836
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->h(Landroidx/fragment/app/j0;)V

    .line 837
    .line 838
    .line 839
    goto :goto_19

    .line 840
    :pswitch_15
    move/from16 v17, v5

    .line 841
    .line 842
    iget v5, v11, Landroidx/fragment/app/t1;->d:I

    .line 843
    .line 844
    iget v14, v11, Landroidx/fragment/app/t1;->e:I

    .line 845
    .line 846
    iget v15, v11, Landroidx/fragment/app/t1;->f:I

    .line 847
    .line 848
    iget v11, v11, Landroidx/fragment/app/t1;->g:I

    .line 849
    .line 850
    invoke-virtual {v13, v5, v14, v15, v11}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 851
    .line 852
    .line 853
    const/4 v14, 0x0

    .line 854
    invoke-virtual {v6, v13, v14}, Landroidx/fragment/app/j1;->a0(Landroidx/fragment/app/j0;Z)V

    .line 855
    .line 856
    .line 857
    invoke-static {v13}, Landroidx/fragment/app/j1;->e0(Landroidx/fragment/app/j0;)V

    .line 858
    .line 859
    .line 860
    goto :goto_19

    .line 861
    :pswitch_16
    move/from16 v17, v5

    .line 862
    .line 863
    iget v5, v11, Landroidx/fragment/app/t1;->d:I

    .line 864
    .line 865
    iget v14, v11, Landroidx/fragment/app/t1;->e:I

    .line 866
    .line 867
    iget v15, v11, Landroidx/fragment/app/t1;->f:I

    .line 868
    .line 869
    iget v11, v11, Landroidx/fragment/app/t1;->g:I

    .line 870
    .line 871
    invoke-virtual {v13, v5, v14, v15, v11}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 872
    .line 873
    .line 874
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->K(Landroidx/fragment/app/j0;)V

    .line 875
    .line 876
    .line 877
    goto :goto_19

    .line 878
    :pswitch_17
    move/from16 v17, v5

    .line 879
    .line 880
    iget v5, v11, Landroidx/fragment/app/t1;->d:I

    .line 881
    .line 882
    iget v14, v11, Landroidx/fragment/app/t1;->e:I

    .line 883
    .line 884
    iget v15, v11, Landroidx/fragment/app/t1;->f:I

    .line 885
    .line 886
    iget v11, v11, Landroidx/fragment/app/t1;->g:I

    .line 887
    .line 888
    invoke-virtual {v13, v5, v14, v15, v11}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 889
    .line 890
    .line 891
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->V(Landroidx/fragment/app/j0;)V

    .line 892
    .line 893
    .line 894
    goto :goto_19

    .line 895
    :pswitch_18
    move/from16 v17, v5

    .line 896
    .line 897
    iget v5, v11, Landroidx/fragment/app/t1;->d:I

    .line 898
    .line 899
    iget v14, v11, Landroidx/fragment/app/t1;->e:I

    .line 900
    .line 901
    iget v15, v11, Landroidx/fragment/app/t1;->f:I

    .line 902
    .line 903
    iget v11, v11, Landroidx/fragment/app/t1;->g:I

    .line 904
    .line 905
    invoke-virtual {v13, v5, v14, v15, v11}, Landroidx/fragment/app/j0;->setAnimations(IIII)V

    .line 906
    .line 907
    .line 908
    const/4 v14, 0x0

    .line 909
    invoke-virtual {v6, v13, v14}, Landroidx/fragment/app/j1;->a0(Landroidx/fragment/app/j0;Z)V

    .line 910
    .line 911
    .line 912
    invoke-virtual {v6, v13}, Landroidx/fragment/app/j1;->a(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 913
    .line 914
    .line 915
    :goto_19
    add-int/lit8 v12, v12, 0x1

    .line 916
    .line 917
    move/from16 v5, v17

    .line 918
    .line 919
    goto/16 :goto_17

    .line 920
    .line 921
    :goto_1a
    add-int/lit8 v5, v17, 0x1

    .line 922
    .line 923
    goto/16 :goto_12

    .line 924
    .line 925
    :cond_1e
    add-int/lit8 v5, v4, -0x1

    .line 926
    .line 927
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 928
    .line 929
    .line 930
    move-result-object v5

    .line 931
    check-cast v5, Ljava/lang/Boolean;

    .line 932
    .line 933
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 934
    .line 935
    .line 936
    move-result v5

    .line 937
    iget-object v7, v0, Landroidx/fragment/app/j1;->n:Ljava/util/ArrayList;

    .line 938
    .line 939
    if-eqz v23, :cond_25

    .line 940
    .line 941
    invoke-virtual {v7}, Ljava/util/ArrayList;->isEmpty()Z

    .line 942
    .line 943
    .line 944
    move-result v8

    .line 945
    if-nez v8, :cond_25

    .line 946
    .line 947
    new-instance v8, Ljava/util/LinkedHashSet;

    .line 948
    .line 949
    invoke-direct {v8}, Ljava/util/LinkedHashSet;-><init>()V

    .line 950
    .line 951
    .line 952
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 953
    .line 954
    .line 955
    move-result-object v9

    .line 956
    :goto_1b
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 957
    .line 958
    .line 959
    move-result v10

    .line 960
    if-eqz v10, :cond_1f

    .line 961
    .line 962
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 963
    .line 964
    .line 965
    move-result-object v10

    .line 966
    check-cast v10, Landroidx/fragment/app/a;

    .line 967
    .line 968
    invoke-static {v10}, Landroidx/fragment/app/j1;->G(Landroidx/fragment/app/a;)Ljava/util/HashSet;

    .line 969
    .line 970
    .line 971
    move-result-object v10

    .line 972
    invoke-interface {v8, v10}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 973
    .line 974
    .line 975
    goto :goto_1b

    .line 976
    :cond_1f
    iget-object v9, v0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 977
    .line 978
    if-nez v9, :cond_25

    .line 979
    .line 980
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 981
    .line 982
    .line 983
    move-result-object v9

    .line 984
    :goto_1c
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 985
    .line 986
    .line 987
    move-result v10

    .line 988
    if-eqz v10, :cond_22

    .line 989
    .line 990
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 991
    .line 992
    .line 993
    move-result-object v10

    .line 994
    if-nez v10, :cond_21

    .line 995
    .line 996
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 997
    .line 998
    .line 999
    move-result-object v10

    .line 1000
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 1001
    .line 1002
    .line 1003
    move-result v11

    .line 1004
    if-nez v11, :cond_20

    .line 1005
    .line 1006
    goto :goto_1c

    .line 1007
    :cond_20
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v0

    .line 1011
    check-cast v0, Landroidx/fragment/app/j0;

    .line 1012
    .line 1013
    const/16 v16, 0x0

    .line 1014
    .line 1015
    throw v16

    .line 1016
    :cond_21
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1017
    .line 1018
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1019
    .line 1020
    .line 1021
    throw v0

    .line 1022
    :cond_22
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v9

    .line 1026
    :goto_1d
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 1027
    .line 1028
    .line 1029
    move-result v10

    .line 1030
    if-eqz v10, :cond_25

    .line 1031
    .line 1032
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v10

    .line 1036
    if-nez v10, :cond_24

    .line 1037
    .line 1038
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v10

    .line 1042
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 1043
    .line 1044
    .line 1045
    move-result v11

    .line 1046
    if-nez v11, :cond_23

    .line 1047
    .line 1048
    goto :goto_1d

    .line 1049
    :cond_23
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1050
    .line 1051
    .line 1052
    move-result-object v0

    .line 1053
    check-cast v0, Landroidx/fragment/app/j0;

    .line 1054
    .line 1055
    const/16 v16, 0x0

    .line 1056
    .line 1057
    throw v16

    .line 1058
    :cond_24
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1059
    .line 1060
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1061
    .line 1062
    .line 1063
    throw v0

    .line 1064
    :cond_25
    move v8, v3

    .line 1065
    :goto_1e
    if-ge v8, v4, :cond_2a

    .line 1066
    .line 1067
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1068
    .line 1069
    .line 1070
    move-result-object v9

    .line 1071
    check-cast v9, Landroidx/fragment/app/a;

    .line 1072
    .line 1073
    if-eqz v5, :cond_27

    .line 1074
    .line 1075
    iget-object v10, v9, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 1076
    .line 1077
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 1078
    .line 1079
    .line 1080
    move-result v10

    .line 1081
    const/16 v19, 0x1

    .line 1082
    .line 1083
    add-int/lit8 v10, v10, -0x1

    .line 1084
    .line 1085
    :goto_1f
    if-ltz v10, :cond_29

    .line 1086
    .line 1087
    iget-object v11, v9, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 1088
    .line 1089
    invoke-virtual {v11, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v11

    .line 1093
    check-cast v11, Landroidx/fragment/app/t1;

    .line 1094
    .line 1095
    iget-object v11, v11, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 1096
    .line 1097
    if-eqz v11, :cond_26

    .line 1098
    .line 1099
    invoke-virtual {v0, v11}, Landroidx/fragment/app/j1;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 1100
    .line 1101
    .line 1102
    move-result-object v11

    .line 1103
    invoke-virtual {v11}, Landroidx/fragment/app/r1;->k()V

    .line 1104
    .line 1105
    .line 1106
    :cond_26
    add-int/lit8 v10, v10, -0x1

    .line 1107
    .line 1108
    goto :goto_1f

    .line 1109
    :cond_27
    iget-object v9, v9, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 1110
    .line 1111
    invoke-virtual {v9}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v9

    .line 1115
    :cond_28
    :goto_20
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 1116
    .line 1117
    .line 1118
    move-result v10

    .line 1119
    if-eqz v10, :cond_29

    .line 1120
    .line 1121
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v10

    .line 1125
    check-cast v10, Landroidx/fragment/app/t1;

    .line 1126
    .line 1127
    iget-object v10, v10, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 1128
    .line 1129
    if-eqz v10, :cond_28

    .line 1130
    .line 1131
    invoke-virtual {v0, v10}, Landroidx/fragment/app/j1;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 1132
    .line 1133
    .line 1134
    move-result-object v10

    .line 1135
    invoke-virtual {v10}, Landroidx/fragment/app/r1;->k()V

    .line 1136
    .line 1137
    .line 1138
    goto :goto_20

    .line 1139
    :cond_29
    add-int/lit8 v8, v8, 0x1

    .line 1140
    .line 1141
    goto :goto_1e

    .line 1142
    :cond_2a
    iget v8, v0, Landroidx/fragment/app/j1;->v:I

    .line 1143
    .line 1144
    const/4 v11, 0x1

    .line 1145
    invoke-virtual {v0, v8, v11}, Landroidx/fragment/app/j1;->Q(IZ)V

    .line 1146
    .line 1147
    .line 1148
    invoke-virtual {v0, v1, v3, v4}, Landroidx/fragment/app/j1;->f(Ljava/util/ArrayList;II)Ljava/util/HashSet;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v0

    .line 1152
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1153
    .line 1154
    .line 1155
    move-result-object v0

    .line 1156
    :goto_21
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1157
    .line 1158
    .line 1159
    move-result v8

    .line 1160
    if-eqz v8, :cond_2b

    .line 1161
    .line 1162
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v8

    .line 1166
    check-cast v8, Landroidx/fragment/app/r;

    .line 1167
    .line 1168
    iput-boolean v5, v8, Landroidx/fragment/app/r;->e:Z

    .line 1169
    .line 1170
    invoke-virtual {v8}, Landroidx/fragment/app/r;->l()V

    .line 1171
    .line 1172
    .line 1173
    invoke-virtual {v8}, Landroidx/fragment/app/r;->e()V

    .line 1174
    .line 1175
    .line 1176
    goto :goto_21

    .line 1177
    :cond_2b
    :goto_22
    if-ge v3, v4, :cond_2f

    .line 1178
    .line 1179
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v0

    .line 1183
    check-cast v0, Landroidx/fragment/app/a;

    .line 1184
    .line 1185
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1186
    .line 1187
    .line 1188
    move-result-object v5

    .line 1189
    check-cast v5, Ljava/lang/Boolean;

    .line 1190
    .line 1191
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1192
    .line 1193
    .line 1194
    move-result v5

    .line 1195
    if-eqz v5, :cond_2c

    .line 1196
    .line 1197
    iget v5, v0, Landroidx/fragment/app/a;->s:I

    .line 1198
    .line 1199
    if-ltz v5, :cond_2c

    .line 1200
    .line 1201
    iput v6, v0, Landroidx/fragment/app/a;->s:I

    .line 1202
    .line 1203
    :cond_2c
    iget-object v5, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 1204
    .line 1205
    if-eqz v5, :cond_2e

    .line 1206
    .line 1207
    const/4 v12, 0x0

    .line 1208
    :goto_23
    iget-object v5, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 1209
    .line 1210
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 1211
    .line 1212
    .line 1213
    move-result v5

    .line 1214
    if-ge v12, v5, :cond_2d

    .line 1215
    .line 1216
    iget-object v5, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 1217
    .line 1218
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1219
    .line 1220
    .line 1221
    move-result-object v5

    .line 1222
    check-cast v5, Ljava/lang/Runnable;

    .line 1223
    .line 1224
    invoke-interface {v5}, Ljava/lang/Runnable;->run()V

    .line 1225
    .line 1226
    .line 1227
    add-int/lit8 v12, v12, 0x1

    .line 1228
    .line 1229
    goto :goto_23

    .line 1230
    :cond_2d
    const/4 v11, 0x0

    .line 1231
    iput-object v11, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 1232
    .line 1233
    goto :goto_24

    .line 1234
    :cond_2e
    const/4 v11, 0x0

    .line 1235
    :goto_24
    add-int/lit8 v3, v3, 0x1

    .line 1236
    .line 1237
    goto :goto_22

    .line 1238
    :cond_2f
    if-eqz v23, :cond_31

    .line 1239
    .line 1240
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 1241
    .line 1242
    .line 1243
    move-result v0

    .line 1244
    if-gtz v0, :cond_30

    .line 1245
    .line 1246
    goto :goto_25

    .line 1247
    :cond_30
    const/4 v14, 0x0

    .line 1248
    invoke-virtual {v7, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1249
    .line 1250
    .line 1251
    move-result-object v0

    .line 1252
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1253
    .line 1254
    .line 1255
    new-instance v0, Ljava/lang/ClassCastException;

    .line 1256
    .line 1257
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1258
    .line 1259
    .line 1260
    throw v0

    .line 1261
    :cond_31
    :goto_25
    return-void

    .line 1262
    nop

    .line 1263
    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_3
        :pswitch_4
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 1264
    .line 1265
    .line 1266
    .line 1267
    .line 1268
    .line 1269
    .line 1270
    .line 1271
    .line 1272
    .line 1273
    .line 1274
    .line 1275
    .line 1276
    .line 1277
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_e
        :pswitch_5
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
    .end packed-switch

    .line 1278
    .line 1279
    .line 1280
    .line 1281
    .line 1282
    .line 1283
    .line 1284
    .line 1285
    .line 1286
    .line 1287
    .line 1288
    .line 1289
    .line 1290
    .line 1291
    .line 1292
    .line 1293
    .line 1294
    .line 1295
    .line 1296
    .line 1297
    .line 1298
    .line 1299
    .line 1300
    .line 1301
    :pswitch_data_2
    .packed-switch 0x1
        :pswitch_18
        :pswitch_f
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
    .end packed-switch
.end method

.method public final C(I)Landroidx/fragment/app/j0;
    .locals 4

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/lit8 v1, v1, -0x1

    .line 10
    .line 11
    :goto_0
    if-ltz v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Landroidx/fragment/app/j0;

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    iget v3, v2, Landroidx/fragment/app/j0;->mFragmentId:I

    .line 22
    .line 23
    if-ne v3, p1, :cond_0

    .line 24
    .line 25
    return-object v2

    .line 26
    :cond_0
    add-int/lit8 v1, v1, -0x1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    iget-object p0, p0, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Landroidx/fragment/app/r1;

    .line 50
    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    iget-object v0, v0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 54
    .line 55
    iget v1, v0, Landroidx/fragment/app/j0;->mFragmentId:I

    .line 56
    .line 57
    if-ne v1, p1, :cond_2

    .line 58
    .line 59
    return-object v0

    .line 60
    :cond_3
    const/4 p0, 0x0

    .line 61
    return-object p0
.end method

.method public final D(Ljava/lang/String;)Landroidx/fragment/app/j0;
    .locals 4

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    add-int/lit8 v1, v1, -0x1

    .line 10
    .line 11
    :goto_0
    if-ltz v1, :cond_1

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Landroidx/fragment/app/j0;

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    iget-object v3, v2, Landroidx/fragment/app/j0;->mTag:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    return-object v2

    .line 30
    :cond_0
    add-int/lit8 v1, v1, -0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iget-object p0, p0, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, Landroidx/fragment/app/r1;

    .line 54
    .line 55
    if-eqz v0, :cond_2

    .line 56
    .line 57
    iget-object v0, v0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 58
    .line 59
    iget-object v1, v0, Landroidx/fragment/app/j0;->mTag:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {p1, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_2

    .line 66
    .line 67
    return-object v0

    .line 68
    :cond_3
    const/4 p0, 0x0

    .line 69
    return-object p0
.end method

.method public final F()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->e()Ljava/util/HashSet;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_2

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Landroidx/fragment/app/r;

    .line 20
    .line 21
    iget-boolean v1, v0, Landroidx/fragment/app/r;->f:Z

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    const-string v1, "FragmentManager"

    .line 33
    .line 34
    const-string v2, "SpecialEffectsController: Forcing postponed operations"

    .line 35
    .line 36
    invoke-static {v1, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 37
    .line 38
    .line 39
    :cond_1
    const/4 v1, 0x0

    .line 40
    iput-boolean v1, v0, Landroidx/fragment/app/r;->f:Z

    .line 41
    .line 42
    invoke-virtual {v0}, Landroidx/fragment/app/r;->e()V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    return-void
.end method

.method public final H(Landroidx/fragment/app/j0;)Landroid/view/ViewGroup;
    .locals 1

    .line 1
    iget-object v0, p1, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    iget v0, p1, Landroidx/fragment/app/j0;->mContainerId:I

    .line 7
    .line 8
    if-gtz v0, :cond_1

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_1
    iget-object v0, p0, Landroidx/fragment/app/j1;->x:Landroidx/fragment/app/r0;

    .line 12
    .line 13
    invoke-virtual {v0}, Landroidx/fragment/app/r0;->c()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    iget-object p0, p0, Landroidx/fragment/app/j1;->x:Landroidx/fragment/app/r0;

    .line 20
    .line 21
    iget p1, p1, Landroidx/fragment/app/j0;->mContainerId:I

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Landroidx/fragment/app/r0;->b(I)Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    instance-of p1, p0, Landroid/view/ViewGroup;

    .line 28
    .line 29
    if-eqz p1, :cond_2

    .line 30
    .line 31
    check-cast p0, Landroid/view/ViewGroup;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 35
    return-object p0
.end method

.method public final I()Landroidx/fragment/app/b1;
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, v0, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->I()Landroidx/fragment/app/b1;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->A:Landroidx/fragment/app/b1;

    .line 13
    .line 14
    return-object p0
.end method

.method public final J()Lip/v;
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, v0, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->J()Lip/v;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->B:Lip/v;

    .line 13
    .line 14
    return-object p0
.end method

.method public final K(Landroidx/fragment/app/j0;)V
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "hide: "

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "FragmentManager"

    .line 23
    .line 24
    invoke-static {v1, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-boolean v0, p1, Landroidx/fragment/app/j0;->mHidden:Z

    .line 28
    .line 29
    if-nez v0, :cond_1

    .line 30
    .line 31
    const/4 v0, 0x1

    .line 32
    iput-boolean v0, p1, Landroidx/fragment/app/j0;->mHidden:Z

    .line 33
    .line 34
    iget-boolean v1, p1, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 35
    .line 36
    xor-int/2addr v0, v1

    .line 37
    iput-boolean v0, p1, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->d0(Landroidx/fragment/app/j0;)V

    .line 40
    .line 41
    .line 42
    :cond_1
    return-void
.end method

.method public final N()Z
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->isAdded()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->N()Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    return v1

    .line 26
    :cond_1
    const/4 p0, 0x0

    .line 27
    return p0
.end method

.method public final P()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Landroidx/fragment/app/j1;->H:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean p0, p0, Landroidx/fragment/app/j1;->I:Z

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 13
    return p0
.end method

.method public final Q(IZ)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, -0x1

    .line 6
    if-ne p1, v0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 10
    .line 11
    const-string p1, "No activity"

    .line 12
    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0

    .line 17
    :cond_1
    :goto_0
    if-nez p2, :cond_2

    .line 18
    .line 19
    iget p2, p0, Landroidx/fragment/app/j1;->v:I

    .line 20
    .line 21
    if-ne p1, p2, :cond_2

    .line 22
    .line 23
    goto/16 :goto_4

    .line 24
    .line 25
    :cond_2
    iput p1, p0, Landroidx/fragment/app/j1;->v:I

    .line 26
    .line 27
    iget-object p1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 28
    .line 29
    iget-object p2, p1, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 30
    .line 31
    iget-object v0, p1, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :cond_3
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_4

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Landroidx/fragment/app/j0;

    .line 48
    .line 49
    iget-object v1, v1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {p2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    check-cast v1, Landroidx/fragment/app/r1;

    .line 56
    .line 57
    if-eqz v1, :cond_3

    .line 58
    .line 59
    invoke-virtual {v1}, Landroidx/fragment/app/r1;->k()V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_4
    invoke-virtual {p2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    :cond_5
    :goto_2
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_7

    .line 76
    .line 77
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    check-cast v0, Landroidx/fragment/app/r1;

    .line 82
    .line 83
    if-eqz v0, :cond_5

    .line 84
    .line 85
    invoke-virtual {v0}, Landroidx/fragment/app/r1;->k()V

    .line 86
    .line 87
    .line 88
    iget-object v1, v0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 89
    .line 90
    iget-boolean v2, v1, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 91
    .line 92
    if-eqz v2, :cond_5

    .line 93
    .line 94
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->isInBackStack()Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-nez v2, :cond_5

    .line 99
    .line 100
    iget-boolean v2, v1, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 101
    .line 102
    if-eqz v2, :cond_6

    .line 103
    .line 104
    iget-object v2, p1, Landroidx/fragment/app/s1;->c:Ljava/util/HashMap;

    .line 105
    .line 106
    iget-object v3, v1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 107
    .line 108
    invoke-virtual {v2, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    if-nez v2, :cond_6

    .line 113
    .line 114
    iget-object v1, v1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 115
    .line 116
    invoke-virtual {v0}, Landroidx/fragment/app/r1;->n()Landroid/os/Bundle;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {p1, v1, v2}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 121
    .line 122
    .line 123
    :cond_6
    invoke-virtual {p1, v0}, Landroidx/fragment/app/s1;->h(Landroidx/fragment/app/r1;)V

    .line 124
    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_7
    invoke-virtual {p1}, Landroidx/fragment/app/s1;->d()Ljava/util/ArrayList;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    :cond_8
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    if-eqz p2, :cond_a

    .line 140
    .line 141
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object p2

    .line 145
    check-cast p2, Landroidx/fragment/app/r1;

    .line 146
    .line 147
    iget-object v0, p2, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 148
    .line 149
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 150
    .line 151
    if-eqz v1, :cond_8

    .line 152
    .line 153
    iget-boolean v1, p0, Landroidx/fragment/app/j1;->b:Z

    .line 154
    .line 155
    if-eqz v1, :cond_9

    .line 156
    .line 157
    const/4 p2, 0x1

    .line 158
    iput-boolean p2, p0, Landroidx/fragment/app/j1;->K:Z

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_9
    const/4 v1, 0x0

    .line 162
    iput-boolean v1, v0, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 163
    .line 164
    invoke-virtual {p2}, Landroidx/fragment/app/r1;->k()V

    .line 165
    .line 166
    .line 167
    goto :goto_3

    .line 168
    :cond_a
    iget-boolean p1, p0, Landroidx/fragment/app/j1;->G:Z

    .line 169
    .line 170
    if-eqz p1, :cond_b

    .line 171
    .line 172
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 173
    .line 174
    if-eqz p1, :cond_b

    .line 175
    .line 176
    iget p2, p0, Landroidx/fragment/app/j1;->v:I

    .line 177
    .line 178
    const/4 v0, 0x7

    .line 179
    if-ne p2, v0, :cond_b

    .line 180
    .line 181
    check-cast p1, Landroidx/fragment/app/n0;

    .line 182
    .line 183
    iget-object p1, p1, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 184
    .line 185
    invoke-virtual {p1}, Lb/r;->invalidateMenu()V

    .line 186
    .line 187
    .line 188
    const/4 p1, 0x0

    .line 189
    iput-boolean p1, p0, Landroidx/fragment/app/j1;->G:Z

    .line 190
    .line 191
    :cond_b
    :goto_4
    return-void
.end method

.method public final R()V
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    const/4 v0, 0x0

    .line 7
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->H:Z

    .line 8
    .line 9
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->I:Z

    .line 10
    .line 11
    iget-object v1, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 12
    .line 13
    iput-boolean v0, v1, Landroidx/fragment/app/n1;->i:Z

    .line 14
    .line 15
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 16
    .line 17
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Landroidx/fragment/app/j0;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->noteStateNotSaved()V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    :goto_1
    return-void
.end method

.method public final S()Z
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    invoke-virtual {p0, v0, v1}, Landroidx/fragment/app/j1;->T(II)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final T(II)Z
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 3
    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-virtual {p0, v1}, Landroidx/fragment/app/j1;->y(Z)V

    .line 7
    .line 8
    .line 9
    iget-object v2, p0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    if-gez p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {v2}, Landroidx/fragment/app/j0;->getChildFragmentManager()Landroidx/fragment/app/j1;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-virtual {v2}, Landroidx/fragment/app/j1;->S()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    return v1

    .line 26
    :cond_0
    iget-object v2, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 27
    .line 28
    iget-object v3, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {p0, v2, v3, p1, p2}, Landroidx/fragment/app/j1;->U(Ljava/util/ArrayList;Ljava/util/ArrayList;II)Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-eqz p1, :cond_1

    .line 35
    .line 36
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->b:Z

    .line 37
    .line 38
    :try_start_0
    iget-object p2, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 39
    .line 40
    iget-object v2, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-virtual {p0, p2, v2}, Landroidx/fragment/app/j1;->W(Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->d()V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p1

    .line 50
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->d()V

    .line 51
    .line 52
    .line 53
    throw p1

    .line 54
    :cond_1
    :goto_0
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->g0()V

    .line 55
    .line 56
    .line 57
    iget-boolean p2, p0, Landroidx/fragment/app/j1;->K:Z

    .line 58
    .line 59
    iget-object v2, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 60
    .line 61
    if-eqz p2, :cond_4

    .line 62
    .line 63
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->K:Z

    .line 64
    .line 65
    invoke-virtual {v2}, Landroidx/fragment/app/s1;->d()Ljava/util/ArrayList;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    :cond_2
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    if-eqz v3, :cond_4

    .line 78
    .line 79
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    check-cast v3, Landroidx/fragment/app/r1;

    .line 84
    .line 85
    iget-object v4, v3, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 86
    .line 87
    iget-boolean v5, v4, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 88
    .line 89
    if-eqz v5, :cond_2

    .line 90
    .line 91
    iget-boolean v5, p0, Landroidx/fragment/app/j1;->b:Z

    .line 92
    .line 93
    if-eqz v5, :cond_3

    .line 94
    .line 95
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->K:Z

    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_3
    iput-boolean v0, v4, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 99
    .line 100
    invoke-virtual {v3}, Landroidx/fragment/app/r1;->k()V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_4
    iget-object p0, v2, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    const/4 p2, 0x0

    .line 111
    invoke-static {p2}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    invoke-interface {p0, p2}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 116
    .line 117
    .line 118
    return p1
.end method

.method public final U(Ljava/util/ArrayList;Ljava/util/ArrayList;II)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    and-int/2addr p4, v0

    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    move p4, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move p4, v1

    .line 9
    :goto_0
    iget-object v2, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/4 v3, -0x1

    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    goto :goto_4

    .line 19
    :cond_1
    if-gez p3, :cond_3

    .line 20
    .line 21
    if-eqz p4, :cond_2

    .line 22
    .line 23
    move v3, v1

    .line 24
    goto :goto_4

    .line 25
    :cond_2
    iget-object p3, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-virtual {p3}, Ljava/util/ArrayList;->size()I

    .line 28
    .line 29
    .line 30
    move-result p3

    .line 31
    add-int/lit8 v3, p3, -0x1

    .line 32
    .line 33
    goto :goto_4

    .line 34
    :cond_3
    iget-object v2, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    sub-int/2addr v2, v0

    .line 41
    :goto_1
    if-ltz v2, :cond_5

    .line 42
    .line 43
    iget-object v4, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    check-cast v4, Landroidx/fragment/app/a;

    .line 50
    .line 51
    if-ltz p3, :cond_4

    .line 52
    .line 53
    iget v4, v4, Landroidx/fragment/app/a;->s:I

    .line 54
    .line 55
    if-ne p3, v4, :cond_4

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_4
    add-int/lit8 v2, v2, -0x1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_5
    :goto_2
    if-gez v2, :cond_6

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_4

    .line 65
    :cond_6
    if-eqz p4, :cond_7

    .line 66
    .line 67
    move v3, v2

    .line 68
    :goto_3
    if-lez v3, :cond_9

    .line 69
    .line 70
    iget-object p4, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 71
    .line 72
    add-int/lit8 v2, v3, -0x1

    .line 73
    .line 74
    invoke-virtual {p4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p4

    .line 78
    check-cast p4, Landroidx/fragment/app/a;

    .line 79
    .line 80
    if-ltz p3, :cond_9

    .line 81
    .line 82
    iget p4, p4, Landroidx/fragment/app/a;->s:I

    .line 83
    .line 84
    if-ne p3, p4, :cond_9

    .line 85
    .line 86
    add-int/lit8 v3, v3, -0x1

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_7
    iget-object p3, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {p3}, Ljava/util/ArrayList;->size()I

    .line 92
    .line 93
    .line 94
    move-result p3

    .line 95
    sub-int/2addr p3, v0

    .line 96
    if-ne v2, p3, :cond_8

    .line 97
    .line 98
    goto :goto_4

    .line 99
    :cond_8
    add-int/lit8 v3, v2, 0x1

    .line 100
    .line 101
    :cond_9
    :goto_4
    if-gez v3, :cond_a

    .line 102
    .line 103
    return v1

    .line 104
    :cond_a
    iget-object p3, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 105
    .line 106
    invoke-virtual {p3}, Ljava/util/ArrayList;->size()I

    .line 107
    .line 108
    .line 109
    move-result p3

    .line 110
    sub-int/2addr p3, v0

    .line 111
    :goto_5
    if-lt p3, v3, :cond_b

    .line 112
    .line 113
    iget-object p4, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-virtual {p4, p3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p4

    .line 119
    check-cast p4, Landroidx/fragment/app/a;

    .line 120
    .line 121
    invoke-virtual {p1, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    sget-object p4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {p2, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    add-int/lit8 p3, p3, -0x1

    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_b
    return v0
.end method

.method public final V(Landroidx/fragment/app/j0;)V
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    const-string v0, "FragmentManager"

    .line 9
    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "remove: "

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v2, " nesting="

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget v2, p1, Landroidx/fragment/app/j0;->mBackStackNesting:I

    .line 26
    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-static {v0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    :cond_0
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->isInBackStack()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    iget-boolean v1, p1, Landroidx/fragment/app/j0;->mDetached:Z

    .line 42
    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    if-nez v0, :cond_1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    return-void

    .line 49
    :cond_2
    :goto_0
    iget-object v0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 50
    .line 51
    iget-object v1, v0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 52
    .line 53
    monitor-enter v1

    .line 54
    :try_start_0
    iget-object v0, v0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    const/4 v0, 0x0

    .line 61
    iput-boolean v0, p1, Landroidx/fragment/app/j0;->mAdded:Z

    .line 62
    .line 63
    invoke-static {p1}, Landroidx/fragment/app/j1;->M(Landroidx/fragment/app/j0;)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    const/4 v1, 0x1

    .line 68
    if-eqz v0, :cond_3

    .line 69
    .line 70
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->G:Z

    .line 71
    .line 72
    :cond_3
    iput-boolean v1, p1, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->d0(Landroidx/fragment/app/j0;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :catchall_0
    move-exception p0

    .line 79
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 80
    throw p0
.end method

.method public final W(Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 4

    .line 1
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_2

    .line 8
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-ne v0, v1, :cond_6

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, 0x0

    .line 23
    move v2, v1

    .line 24
    :goto_0
    if-ge v1, v0, :cond_4

    .line 25
    .line 26
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    check-cast v3, Landroidx/fragment/app/a;

    .line 31
    .line 32
    iget-boolean v3, v3, Landroidx/fragment/app/a;->o:Z

    .line 33
    .line 34
    if-nez v3, :cond_3

    .line 35
    .line 36
    if-eq v2, v1, :cond_1

    .line 37
    .line 38
    invoke-virtual {p0, p1, p2, v2, v1}, Landroidx/fragment/app/j1;->B(Ljava/util/ArrayList;Ljava/util/ArrayList;II)V

    .line 39
    .line 40
    .line 41
    :cond_1
    add-int/lit8 v2, v1, 0x1

    .line 42
    .line 43
    invoke-virtual {p2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Ljava/lang/Boolean;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_2

    .line 54
    .line 55
    :goto_1
    if-ge v2, v0, :cond_2

    .line 56
    .line 57
    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    check-cast v3, Ljava/lang/Boolean;

    .line 62
    .line 63
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eqz v3, :cond_2

    .line 68
    .line 69
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    check-cast v3, Landroidx/fragment/app/a;

    .line 74
    .line 75
    iget-boolean v3, v3, Landroidx/fragment/app/a;->o:Z

    .line 76
    .line 77
    if-nez v3, :cond_2

    .line 78
    .line 79
    add-int/lit8 v2, v2, 0x1

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_2
    invoke-virtual {p0, p1, p2, v1, v2}, Landroidx/fragment/app/j1;->B(Ljava/util/ArrayList;Ljava/util/ArrayList;II)V

    .line 83
    .line 84
    .line 85
    add-int/lit8 v1, v2, -0x1

    .line 86
    .line 87
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_4
    if-eq v2, v0, :cond_5

    .line 91
    .line 92
    invoke-virtual {p0, p1, p2, v2, v0}, Landroidx/fragment/app/j1;->B(Ljava/util/ArrayList;Ljava/util/ArrayList;II)V

    .line 93
    .line 94
    .line 95
    :cond_5
    :goto_2
    return-void

    .line 96
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 97
    .line 98
    const-string p1, "Internal error with the back stack records"

    .line 99
    .line 100
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0
.end method

.method public final X(Landroid/os/Bundle;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Ljava/lang/String;

    .line 24
    .line 25
    const-string v4, "result_"

    .line 26
    .line 27
    invoke-virtual {v3, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_0

    .line 32
    .line 33
    invoke-virtual {v1, v3}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    if-eqz v4, :cond_0

    .line 38
    .line 39
    iget-object v5, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 40
    .line 41
    iget-object v5, v5, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 42
    .line 43
    invoke-virtual {v5}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 44
    .line 45
    .line 46
    move-result-object v5

    .line 47
    invoke-virtual {v4, v5}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 48
    .line 49
    .line 50
    const/4 v5, 0x7

    .line 51
    invoke-virtual {v3, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    iget-object v5, v0, Landroidx/fragment/app/j1;->m:Ljava/util/Map;

    .line 56
    .line 57
    invoke-interface {v5, v3, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    new-instance v2, Ljava/util/HashMap;

    .line 62
    .line 63
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v1}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    :cond_2
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    if-eqz v4, :cond_3

    .line 79
    .line 80
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    check-cast v4, Ljava/lang/String;

    .line 85
    .line 86
    const-string v5, "fragment_"

    .line 87
    .line 88
    invoke-virtual {v4, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 89
    .line 90
    .line 91
    move-result v5

    .line 92
    if-eqz v5, :cond_2

    .line 93
    .line 94
    invoke-virtual {v1, v4}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    if-eqz v5, :cond_2

    .line 99
    .line 100
    iget-object v6, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 101
    .line 102
    iget-object v6, v6, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 103
    .line 104
    invoke-virtual {v6}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    invoke-virtual {v5, v6}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 109
    .line 110
    .line 111
    const/16 v6, 0x9

    .line 112
    .line 113
    invoke-virtual {v4, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-virtual {v2, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_3
    iget-object v3, v0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 122
    .line 123
    iget-object v4, v3, Landroidx/fragment/app/s1;->c:Ljava/util/HashMap;

    .line 124
    .line 125
    iget-object v5, v3, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 126
    .line 127
    invoke-virtual {v4}, Ljava/util/HashMap;->clear()V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v4, v2}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    .line 131
    .line 132
    .line 133
    const-string v2, "state"

    .line 134
    .line 135
    invoke-virtual {v1, v2}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    check-cast v1, Landroidx/fragment/app/l1;

    .line 140
    .line 141
    if-nez v1, :cond_4

    .line 142
    .line 143
    return-void

    .line 144
    :cond_4
    invoke-virtual {v5}, Ljava/util/HashMap;->clear()V

    .line 145
    .line 146
    .line 147
    iget-object v4, v1, Landroidx/fragment/app/l1;->d:Ljava/util/ArrayList;

    .line 148
    .line 149
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    :cond_5
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    iget-object v7, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 158
    .line 159
    const-string v8, "): "

    .line 160
    .line 161
    const/4 v9, 0x2

    .line 162
    const-string v10, "FragmentManager"

    .line 163
    .line 164
    if-eqz v6, :cond_9

    .line 165
    .line 166
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    check-cast v6, Ljava/lang/String;

    .line 171
    .line 172
    const/4 v11, 0x0

    .line 173
    invoke-virtual {v3, v6, v11}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 174
    .line 175
    .line 176
    move-result-object v6

    .line 177
    if-eqz v6, :cond_5

    .line 178
    .line 179
    invoke-virtual {v6, v2}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 180
    .line 181
    .line 182
    move-result-object v11

    .line 183
    check-cast v11, Landroidx/fragment/app/p1;

    .line 184
    .line 185
    iget-object v12, v0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 186
    .line 187
    iget-object v11, v11, Landroidx/fragment/app/p1;->e:Ljava/lang/String;

    .line 188
    .line 189
    iget-object v12, v12, Landroidx/fragment/app/n1;->d:Ljava/util/HashMap;

    .line 190
    .line 191
    invoke-virtual {v12, v11}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v11

    .line 195
    check-cast v11, Landroidx/fragment/app/j0;

    .line 196
    .line 197
    if-eqz v11, :cond_7

    .line 198
    .line 199
    invoke-static {v9}, Landroidx/fragment/app/j1;->L(I)Z

    .line 200
    .line 201
    .line 202
    move-result v12

    .line 203
    if-eqz v12, :cond_6

    .line 204
    .line 205
    new-instance v12, Ljava/lang/StringBuilder;

    .line 206
    .line 207
    const-string v13, "restoreSaveState: re-attaching retained "

    .line 208
    .line 209
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v12, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v12

    .line 219
    invoke-static {v10, v12}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 220
    .line 221
    .line 222
    :cond_6
    new-instance v12, Landroidx/fragment/app/r1;

    .line 223
    .line 224
    invoke-direct {v12, v7, v3, v11, v6}, Landroidx/fragment/app/r1;-><init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Landroidx/fragment/app/j0;Landroid/os/Bundle;)V

    .line 225
    .line 226
    .line 227
    goto :goto_3

    .line 228
    :cond_7
    new-instance v12, Landroidx/fragment/app/r1;

    .line 229
    .line 230
    iget-object v7, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 231
    .line 232
    iget-object v7, v7, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 233
    .line 234
    invoke-virtual {v7}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 235
    .line 236
    .line 237
    move-result-object v15

    .line 238
    invoke-virtual {v0}, Landroidx/fragment/app/j1;->I()Landroidx/fragment/app/b1;

    .line 239
    .line 240
    .line 241
    move-result-object v16

    .line 242
    iget-object v13, v0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 243
    .line 244
    iget-object v14, v0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 245
    .line 246
    move-object/from16 v17, v6

    .line 247
    .line 248
    invoke-direct/range {v12 .. v17}, Landroidx/fragment/app/r1;-><init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Ljava/lang/ClassLoader;Landroidx/fragment/app/b1;Landroid/os/Bundle;)V

    .line 249
    .line 250
    .line 251
    :goto_3
    iget-object v7, v12, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 252
    .line 253
    iput-object v6, v7, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 254
    .line 255
    iput-object v0, v7, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 256
    .line 257
    invoke-static {v9}, Landroidx/fragment/app/j1;->L(I)Z

    .line 258
    .line 259
    .line 260
    move-result v6

    .line 261
    if-eqz v6, :cond_8

    .line 262
    .line 263
    new-instance v6, Ljava/lang/StringBuilder;

    .line 264
    .line 265
    const-string v9, "restoreSaveState: active ("

    .line 266
    .line 267
    invoke-direct {v6, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    iget-object v9, v7, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 271
    .line 272
    invoke-virtual {v6, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    invoke-static {v10, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 286
    .line 287
    .line 288
    :cond_8
    iget-object v6, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 289
    .line 290
    iget-object v6, v6, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 291
    .line 292
    invoke-virtual {v6}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 293
    .line 294
    .line 295
    move-result-object v6

    .line 296
    invoke-virtual {v12, v6}, Landroidx/fragment/app/r1;->l(Ljava/lang/ClassLoader;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v3, v12}, Landroidx/fragment/app/s1;->g(Landroidx/fragment/app/r1;)V

    .line 300
    .line 301
    .line 302
    iget v6, v0, Landroidx/fragment/app/j1;->v:I

    .line 303
    .line 304
    iput v6, v12, Landroidx/fragment/app/r1;->e:I

    .line 305
    .line 306
    goto/16 :goto_2

    .line 307
    .line 308
    :cond_9
    iget-object v2, v0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 309
    .line 310
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 311
    .line 312
    .line 313
    new-instance v4, Ljava/util/ArrayList;

    .line 314
    .line 315
    iget-object v2, v2, Landroidx/fragment/app/n1;->d:Ljava/util/HashMap;

    .line 316
    .line 317
    invoke-virtual {v2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 318
    .line 319
    .line 320
    move-result-object v2

    .line 321
    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 325
    .line 326
    .line 327
    move-result-object v2

    .line 328
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 329
    .line 330
    .line 331
    move-result v4

    .line 332
    const/4 v6, 0x1

    .line 333
    if-eqz v4, :cond_c

    .line 334
    .line 335
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v4

    .line 339
    check-cast v4, Landroidx/fragment/app/j0;

    .line 340
    .line 341
    iget-object v11, v4, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 342
    .line 343
    invoke-virtual {v5, v11}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v11

    .line 347
    if-eqz v11, :cond_a

    .line 348
    .line 349
    goto :goto_4

    .line 350
    :cond_a
    invoke-static {v9}, Landroidx/fragment/app/j1;->L(I)Z

    .line 351
    .line 352
    .line 353
    move-result v11

    .line 354
    if-eqz v11, :cond_b

    .line 355
    .line 356
    new-instance v11, Ljava/lang/StringBuilder;

    .line 357
    .line 358
    const-string v12, "Discarding retained Fragment "

    .line 359
    .line 360
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    invoke-virtual {v11, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 364
    .line 365
    .line 366
    const-string v12, " that was not found in the set of active Fragments "

    .line 367
    .line 368
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 369
    .line 370
    .line 371
    iget-object v12, v1, Landroidx/fragment/app/l1;->d:Ljava/util/ArrayList;

    .line 372
    .line 373
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 374
    .line 375
    .line 376
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v11

    .line 380
    invoke-static {v10, v11}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 381
    .line 382
    .line 383
    :cond_b
    iget-object v11, v0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 384
    .line 385
    invoke-virtual {v11, v4}, Landroidx/fragment/app/n1;->g(Landroidx/fragment/app/j0;)V

    .line 386
    .line 387
    .line 388
    iput-object v0, v4, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 389
    .line 390
    new-instance v11, Landroidx/fragment/app/r1;

    .line 391
    .line 392
    invoke-direct {v11, v7, v3, v4}, Landroidx/fragment/app/r1;-><init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Landroidx/fragment/app/j0;)V

    .line 393
    .line 394
    .line 395
    iput v6, v11, Landroidx/fragment/app/r1;->e:I

    .line 396
    .line 397
    invoke-virtual {v11}, Landroidx/fragment/app/r1;->k()V

    .line 398
    .line 399
    .line 400
    iput-boolean v6, v4, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 401
    .line 402
    invoke-virtual {v11}, Landroidx/fragment/app/r1;->k()V

    .line 403
    .line 404
    .line 405
    goto :goto_4

    .line 406
    :cond_c
    iget-object v2, v1, Landroidx/fragment/app/l1;->e:Ljava/util/ArrayList;

    .line 407
    .line 408
    iget-object v4, v3, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 409
    .line 410
    invoke-virtual {v4}, Ljava/util/ArrayList;->clear()V

    .line 411
    .line 412
    .line 413
    if-eqz v2, :cond_f

    .line 414
    .line 415
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 416
    .line 417
    .line 418
    move-result-object v2

    .line 419
    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 420
    .line 421
    .line 422
    move-result v4

    .line 423
    if-eqz v4, :cond_f

    .line 424
    .line 425
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v4

    .line 429
    check-cast v4, Ljava/lang/String;

    .line 430
    .line 431
    invoke-virtual {v3, v4}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 432
    .line 433
    .line 434
    move-result-object v5

    .line 435
    if-eqz v5, :cond_e

    .line 436
    .line 437
    invoke-static {v9}, Landroidx/fragment/app/j1;->L(I)Z

    .line 438
    .line 439
    .line 440
    move-result v7

    .line 441
    if-eqz v7, :cond_d

    .line 442
    .line 443
    new-instance v7, Ljava/lang/StringBuilder;

    .line 444
    .line 445
    const-string v11, "restoreSaveState: added ("

    .line 446
    .line 447
    invoke-direct {v7, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 448
    .line 449
    .line 450
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 451
    .line 452
    .line 453
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 454
    .line 455
    .line 456
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 457
    .line 458
    .line 459
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 460
    .line 461
    .line 462
    move-result-object v4

    .line 463
    invoke-static {v10, v4}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 464
    .line 465
    .line 466
    :cond_d
    invoke-virtual {v3, v5}, Landroidx/fragment/app/s1;->a(Landroidx/fragment/app/j0;)V

    .line 467
    .line 468
    .line 469
    goto :goto_5

    .line 470
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 471
    .line 472
    const-string v1, "No instantiated fragment for ("

    .line 473
    .line 474
    const-string v2, ")"

    .line 475
    .line 476
    invoke-static {v1, v4, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    throw v0

    .line 484
    :cond_f
    iget-object v2, v1, Landroidx/fragment/app/l1;->f:[Landroidx/fragment/app/b;

    .line 485
    .line 486
    if-eqz v2, :cond_17

    .line 487
    .line 488
    new-instance v2, Ljava/util/ArrayList;

    .line 489
    .line 490
    iget-object v5, v1, Landroidx/fragment/app/l1;->f:[Landroidx/fragment/app/b;

    .line 491
    .line 492
    array-length v5, v5

    .line 493
    invoke-direct {v2, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 494
    .line 495
    .line 496
    iput-object v2, v0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 497
    .line 498
    const/4 v2, 0x0

    .line 499
    :goto_6
    iget-object v5, v1, Landroidx/fragment/app/l1;->f:[Landroidx/fragment/app/b;

    .line 500
    .line 501
    array-length v7, v5

    .line 502
    if-ge v2, v7, :cond_16

    .line 503
    .line 504
    aget-object v5, v5, v2

    .line 505
    .line 506
    iget-object v7, v5, Landroidx/fragment/app/b;->e:Ljava/util/ArrayList;

    .line 507
    .line 508
    new-instance v11, Landroidx/fragment/app/a;

    .line 509
    .line 510
    invoke-direct {v11, v0}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 511
    .line 512
    .line 513
    iget-object v12, v5, Landroidx/fragment/app/b;->d:[I

    .line 514
    .line 515
    const/4 v13, 0x0

    .line 516
    const/4 v14, 0x0

    .line 517
    :goto_7
    array-length v15, v12

    .line 518
    if-ge v13, v15, :cond_12

    .line 519
    .line 520
    new-instance v15, Landroidx/fragment/app/t1;

    .line 521
    .line 522
    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    .line 523
    .line 524
    .line 525
    add-int/lit8 v16, v13, 0x1

    .line 526
    .line 527
    move/from16 p1, v9

    .line 528
    .line 529
    aget v9, v12, v13

    .line 530
    .line 531
    iput v9, v15, Landroidx/fragment/app/t1;->a:I

    .line 532
    .line 533
    invoke-static/range {p1 .. p1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 534
    .line 535
    .line 536
    move-result v9

    .line 537
    if-eqz v9, :cond_10

    .line 538
    .line 539
    new-instance v9, Ljava/lang/StringBuilder;

    .line 540
    .line 541
    const-string v4, "Instantiate "

    .line 542
    .line 543
    invoke-direct {v9, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 544
    .line 545
    .line 546
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 547
    .line 548
    .line 549
    const-string v4, " op #"

    .line 550
    .line 551
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 552
    .line 553
    .line 554
    invoke-virtual {v9, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 555
    .line 556
    .line 557
    const-string v4, " base fragment #"

    .line 558
    .line 559
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 560
    .line 561
    .line 562
    aget v4, v12, v16

    .line 563
    .line 564
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 565
    .line 566
    .line 567
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 568
    .line 569
    .line 570
    move-result-object v4

    .line 571
    invoke-static {v10, v4}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 572
    .line 573
    .line 574
    :cond_10
    invoke-static {}, Landroidx/lifecycle/q;->values()[Landroidx/lifecycle/q;

    .line 575
    .line 576
    .line 577
    move-result-object v4

    .line 578
    iget-object v9, v5, Landroidx/fragment/app/b;->f:[I

    .line 579
    .line 580
    aget v9, v9, v14

    .line 581
    .line 582
    aget-object v4, v4, v9

    .line 583
    .line 584
    iput-object v4, v15, Landroidx/fragment/app/t1;->h:Landroidx/lifecycle/q;

    .line 585
    .line 586
    invoke-static {}, Landroidx/lifecycle/q;->values()[Landroidx/lifecycle/q;

    .line 587
    .line 588
    .line 589
    move-result-object v4

    .line 590
    iget-object v9, v5, Landroidx/fragment/app/b;->g:[I

    .line 591
    .line 592
    aget v9, v9, v14

    .line 593
    .line 594
    aget-object v4, v4, v9

    .line 595
    .line 596
    iput-object v4, v15, Landroidx/fragment/app/t1;->i:Landroidx/lifecycle/q;

    .line 597
    .line 598
    add-int/lit8 v4, v13, 0x2

    .line 599
    .line 600
    aget v9, v12, v16

    .line 601
    .line 602
    if-eqz v9, :cond_11

    .line 603
    .line 604
    move v9, v6

    .line 605
    goto :goto_8

    .line 606
    :cond_11
    const/4 v9, 0x0

    .line 607
    :goto_8
    iput-boolean v9, v15, Landroidx/fragment/app/t1;->c:Z

    .line 608
    .line 609
    add-int/lit8 v9, v13, 0x3

    .line 610
    .line 611
    aget v4, v12, v4

    .line 612
    .line 613
    iput v4, v15, Landroidx/fragment/app/t1;->d:I

    .line 614
    .line 615
    add-int/lit8 v16, v13, 0x4

    .line 616
    .line 617
    aget v9, v12, v9

    .line 618
    .line 619
    iput v9, v15, Landroidx/fragment/app/t1;->e:I

    .line 620
    .line 621
    add-int/lit8 v18, v13, 0x5

    .line 622
    .line 623
    aget v6, v12, v16

    .line 624
    .line 625
    iput v6, v15, Landroidx/fragment/app/t1;->f:I

    .line 626
    .line 627
    add-int/lit8 v13, v13, 0x6

    .line 628
    .line 629
    move-object/from16 v16, v12

    .line 630
    .line 631
    aget v12, v16, v18

    .line 632
    .line 633
    iput v12, v15, Landroidx/fragment/app/t1;->g:I

    .line 634
    .line 635
    iput v4, v11, Landroidx/fragment/app/a;->b:I

    .line 636
    .line 637
    iput v9, v11, Landroidx/fragment/app/a;->c:I

    .line 638
    .line 639
    iput v6, v11, Landroidx/fragment/app/a;->d:I

    .line 640
    .line 641
    iput v12, v11, Landroidx/fragment/app/a;->e:I

    .line 642
    .line 643
    invoke-virtual {v11, v15}, Landroidx/fragment/app/a;->b(Landroidx/fragment/app/t1;)V

    .line 644
    .line 645
    .line 646
    add-int/lit8 v14, v14, 0x1

    .line 647
    .line 648
    move/from16 v9, p1

    .line 649
    .line 650
    move-object/from16 v12, v16

    .line 651
    .line 652
    const/4 v6, 0x1

    .line 653
    goto/16 :goto_7

    .line 654
    .line 655
    :cond_12
    move/from16 p1, v9

    .line 656
    .line 657
    iget v4, v5, Landroidx/fragment/app/b;->h:I

    .line 658
    .line 659
    iput v4, v11, Landroidx/fragment/app/a;->f:I

    .line 660
    .line 661
    iget-object v4, v5, Landroidx/fragment/app/b;->i:Ljava/lang/String;

    .line 662
    .line 663
    iput-object v4, v11, Landroidx/fragment/app/a;->h:Ljava/lang/String;

    .line 664
    .line 665
    const/4 v4, 0x1

    .line 666
    iput-boolean v4, v11, Landroidx/fragment/app/a;->g:Z

    .line 667
    .line 668
    iget v4, v5, Landroidx/fragment/app/b;->k:I

    .line 669
    .line 670
    iput v4, v11, Landroidx/fragment/app/a;->i:I

    .line 671
    .line 672
    iget-object v4, v5, Landroidx/fragment/app/b;->l:Ljava/lang/CharSequence;

    .line 673
    .line 674
    iput-object v4, v11, Landroidx/fragment/app/a;->j:Ljava/lang/CharSequence;

    .line 675
    .line 676
    iget v4, v5, Landroidx/fragment/app/b;->m:I

    .line 677
    .line 678
    iput v4, v11, Landroidx/fragment/app/a;->k:I

    .line 679
    .line 680
    iget-object v4, v5, Landroidx/fragment/app/b;->n:Ljava/lang/CharSequence;

    .line 681
    .line 682
    iput-object v4, v11, Landroidx/fragment/app/a;->l:Ljava/lang/CharSequence;

    .line 683
    .line 684
    iget-object v4, v5, Landroidx/fragment/app/b;->o:Ljava/util/ArrayList;

    .line 685
    .line 686
    iput-object v4, v11, Landroidx/fragment/app/a;->m:Ljava/util/ArrayList;

    .line 687
    .line 688
    iget-object v4, v5, Landroidx/fragment/app/b;->p:Ljava/util/ArrayList;

    .line 689
    .line 690
    iput-object v4, v11, Landroidx/fragment/app/a;->n:Ljava/util/ArrayList;

    .line 691
    .line 692
    iget-boolean v4, v5, Landroidx/fragment/app/b;->q:Z

    .line 693
    .line 694
    iput-boolean v4, v11, Landroidx/fragment/app/a;->o:Z

    .line 695
    .line 696
    iget v4, v5, Landroidx/fragment/app/b;->j:I

    .line 697
    .line 698
    iput v4, v11, Landroidx/fragment/app/a;->s:I

    .line 699
    .line 700
    const/4 v4, 0x0

    .line 701
    :goto_9
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 702
    .line 703
    .line 704
    move-result v5

    .line 705
    if-ge v4, v5, :cond_14

    .line 706
    .line 707
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v5

    .line 711
    check-cast v5, Ljava/lang/String;

    .line 712
    .line 713
    if-eqz v5, :cond_13

    .line 714
    .line 715
    iget-object v6, v11, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 716
    .line 717
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 718
    .line 719
    .line 720
    move-result-object v6

    .line 721
    check-cast v6, Landroidx/fragment/app/t1;

    .line 722
    .line 723
    invoke-virtual {v3, v5}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 724
    .line 725
    .line 726
    move-result-object v5

    .line 727
    iput-object v5, v6, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 728
    .line 729
    :cond_13
    add-int/lit8 v4, v4, 0x1

    .line 730
    .line 731
    goto :goto_9

    .line 732
    :cond_14
    const/4 v4, 0x1

    .line 733
    invoke-virtual {v11, v4}, Landroidx/fragment/app/a;->c(I)V

    .line 734
    .line 735
    .line 736
    invoke-static/range {p1 .. p1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 737
    .line 738
    .line 739
    move-result v5

    .line 740
    if-eqz v5, :cond_15

    .line 741
    .line 742
    const-string v5, "restoreAllState: back stack #"

    .line 743
    .line 744
    const-string v6, " (index "

    .line 745
    .line 746
    invoke-static {v5, v2, v6}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 747
    .line 748
    .line 749
    move-result-object v5

    .line 750
    iget v6, v11, Landroidx/fragment/app/a;->s:I

    .line 751
    .line 752
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 753
    .line 754
    .line 755
    invoke-virtual {v5, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 756
    .line 757
    .line 758
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 759
    .line 760
    .line 761
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 762
    .line 763
    .line 764
    move-result-object v5

    .line 765
    invoke-static {v10, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 766
    .line 767
    .line 768
    new-instance v5, Landroidx/fragment/app/d2;

    .line 769
    .line 770
    invoke-direct {v5}, Landroidx/fragment/app/d2;-><init>()V

    .line 771
    .line 772
    .line 773
    new-instance v6, Ljava/io/PrintWriter;

    .line 774
    .line 775
    invoke-direct {v6, v5}, Ljava/io/PrintWriter;-><init>(Ljava/io/Writer;)V

    .line 776
    .line 777
    .line 778
    const-string v5, "  "

    .line 779
    .line 780
    const/4 v7, 0x0

    .line 781
    invoke-virtual {v11, v5, v6, v7}, Landroidx/fragment/app/a;->g(Ljava/lang/String;Ljava/io/PrintWriter;Z)V

    .line 782
    .line 783
    .line 784
    invoke-virtual {v6}, Ljava/io/PrintWriter;->close()V

    .line 785
    .line 786
    .line 787
    goto :goto_a

    .line 788
    :cond_15
    const/4 v7, 0x0

    .line 789
    :goto_a
    iget-object v5, v0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 790
    .line 791
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 792
    .line 793
    .line 794
    add-int/lit8 v2, v2, 0x1

    .line 795
    .line 796
    move/from16 v9, p1

    .line 797
    .line 798
    move v6, v4

    .line 799
    goto/16 :goto_6

    .line 800
    .line 801
    :cond_16
    const/4 v7, 0x0

    .line 802
    goto :goto_b

    .line 803
    :cond_17
    const/4 v7, 0x0

    .line 804
    new-instance v2, Ljava/util/ArrayList;

    .line 805
    .line 806
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 807
    .line 808
    .line 809
    iput-object v2, v0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 810
    .line 811
    :goto_b
    iget-object v2, v0, Landroidx/fragment/app/j1;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 812
    .line 813
    iget v4, v1, Landroidx/fragment/app/l1;->g:I

    .line 814
    .line 815
    invoke-virtual {v2, v4}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 816
    .line 817
    .line 818
    iget-object v2, v1, Landroidx/fragment/app/l1;->h:Ljava/lang/String;

    .line 819
    .line 820
    if-eqz v2, :cond_18

    .line 821
    .line 822
    invoke-virtual {v3, v2}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 823
    .line 824
    .line 825
    move-result-object v2

    .line 826
    iput-object v2, v0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 827
    .line 828
    invoke-virtual {v0, v2}, Landroidx/fragment/app/j1;->r(Landroidx/fragment/app/j0;)V

    .line 829
    .line 830
    .line 831
    :cond_18
    iget-object v2, v1, Landroidx/fragment/app/l1;->i:Ljava/util/ArrayList;

    .line 832
    .line 833
    if-eqz v2, :cond_19

    .line 834
    .line 835
    move v4, v7

    .line 836
    :goto_c
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 837
    .line 838
    .line 839
    move-result v3

    .line 840
    if-ge v4, v3, :cond_19

    .line 841
    .line 842
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 843
    .line 844
    .line 845
    move-result-object v3

    .line 846
    check-cast v3, Ljava/lang/String;

    .line 847
    .line 848
    iget-object v5, v1, Landroidx/fragment/app/l1;->j:Ljava/util/ArrayList;

    .line 849
    .line 850
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 851
    .line 852
    .line 853
    move-result-object v5

    .line 854
    check-cast v5, Landroidx/fragment/app/c;

    .line 855
    .line 856
    iget-object v6, v0, Landroidx/fragment/app/j1;->l:Ljava/util/Map;

    .line 857
    .line 858
    invoke-interface {v6, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 859
    .line 860
    .line 861
    add-int/lit8 v4, v4, 0x1

    .line 862
    .line 863
    goto :goto_c

    .line 864
    :cond_19
    new-instance v2, Ljava/util/ArrayDeque;

    .line 865
    .line 866
    iget-object v1, v1, Landroidx/fragment/app/l1;->k:Ljava/util/ArrayList;

    .line 867
    .line 868
    invoke-direct {v2, v1}, Ljava/util/ArrayDeque;-><init>(Ljava/util/Collection;)V

    .line 869
    .line 870
    .line 871
    iput-object v2, v0, Landroidx/fragment/app/j1;->F:Ljava/util/ArrayDeque;

    .line 872
    .line 873
    return-void
.end method

.method public final Y()Landroid/os/Bundle;
    .locals 12

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->F()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->w()V

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-virtual {p0, v1}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 14
    .line 15
    .line 16
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->H:Z

    .line 17
    .line 18
    iget-object v2, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 19
    .line 20
    iput-boolean v1, v2, Landroidx/fragment/app/n1;->i:Z

    .line 21
    .line 22
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 23
    .line 24
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    new-instance v2, Ljava/util/ArrayList;

    .line 28
    .line 29
    iget-object v3, v1, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 30
    .line 31
    invoke-virtual {v3}, Ljava/util/HashMap;->size()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    :cond_0
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    const/4 v5, 0x2

    .line 51
    if-eqz v4, :cond_1

    .line 52
    .line 53
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    check-cast v4, Landroidx/fragment/app/r1;

    .line 58
    .line 59
    if-eqz v4, :cond_0

    .line 60
    .line 61
    iget-object v6, v4, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 62
    .line 63
    iget-object v7, v6, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {v4}, Landroidx/fragment/app/r1;->n()Landroid/os/Bundle;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    invoke-virtual {v1, v7, v4}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 70
    .line 71
    .line 72
    iget-object v4, v6, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    invoke-static {v5}, Landroidx/fragment/app/j1;->L(I)Z

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    if-eqz v4, :cond_0

    .line 82
    .line 83
    const-string v4, "FragmentManager"

    .line 84
    .line 85
    new-instance v5, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string v7, "Saved state of "

    .line 88
    .line 89
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v7, ": "

    .line 96
    .line 97
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    iget-object v6, v6, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 101
    .line 102
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v5

    .line 109
    invoke-static {v4, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_1
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 114
    .line 115
    iget-object v1, v1, Landroidx/fragment/app/s1;->c:Ljava/util/HashMap;

    .line 116
    .line 117
    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-eqz v3, :cond_2

    .line 122
    .line 123
    invoke-static {v5}, Landroidx/fragment/app/j1;->L(I)Z

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-eqz p0, :cond_b

    .line 128
    .line 129
    const-string p0, "FragmentManager"

    .line 130
    .line 131
    const-string v1, "saveAllState: no fragments!"

    .line 132
    .line 133
    invoke-static {p0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 134
    .line 135
    .line 136
    return-object v0

    .line 137
    :cond_2
    iget-object v3, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 138
    .line 139
    iget-object v4, v3, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 140
    .line 141
    monitor-enter v4

    .line 142
    :try_start_0
    iget-object v6, v3, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 143
    .line 144
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    .line 145
    .line 146
    .line 147
    move-result v6

    .line 148
    const/4 v7, 0x0

    .line 149
    if-eqz v6, :cond_3

    .line 150
    .line 151
    monitor-exit v4

    .line 152
    move-object v6, v7

    .line 153
    goto :goto_2

    .line 154
    :catchall_0
    move-exception p0

    .line 155
    goto/16 :goto_6

    .line 156
    .line 157
    :cond_3
    new-instance v6, Ljava/util/ArrayList;

    .line 158
    .line 159
    iget-object v8, v3, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 160
    .line 161
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 162
    .line 163
    .line 164
    move-result v8

    .line 165
    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 166
    .line 167
    .line 168
    iget-object v3, v3, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 169
    .line 170
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    :cond_4
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 175
    .line 176
    .line 177
    move-result v8

    .line 178
    if-eqz v8, :cond_5

    .line 179
    .line 180
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v8

    .line 184
    check-cast v8, Landroidx/fragment/app/j0;

    .line 185
    .line 186
    iget-object v9, v8, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 187
    .line 188
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    invoke-static {v5}, Landroidx/fragment/app/j1;->L(I)Z

    .line 192
    .line 193
    .line 194
    move-result v9

    .line 195
    if-eqz v9, :cond_4

    .line 196
    .line 197
    const-string v9, "FragmentManager"

    .line 198
    .line 199
    new-instance v10, Ljava/lang/StringBuilder;

    .line 200
    .line 201
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 202
    .line 203
    .line 204
    const-string v11, "saveAllState: adding fragment ("

    .line 205
    .line 206
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    iget-object v11, v8, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 210
    .line 211
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    const-string v11, "): "

    .line 215
    .line 216
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v8

    .line 226
    invoke-static {v9, v8}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 227
    .line 228
    .line 229
    goto :goto_1

    .line 230
    :cond_5
    monitor-exit v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 231
    :goto_2
    iget-object v3, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 232
    .line 233
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 234
    .line 235
    .line 236
    move-result v3

    .line 237
    if-lez v3, :cond_7

    .line 238
    .line 239
    new-array v4, v3, [Landroidx/fragment/app/b;

    .line 240
    .line 241
    const/4 v8, 0x0

    .line 242
    :goto_3
    if-ge v8, v3, :cond_8

    .line 243
    .line 244
    new-instance v9, Landroidx/fragment/app/b;

    .line 245
    .line 246
    iget-object v10, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 247
    .line 248
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v10

    .line 252
    check-cast v10, Landroidx/fragment/app/a;

    .line 253
    .line 254
    invoke-direct {v9, v10}, Landroidx/fragment/app/b;-><init>(Landroidx/fragment/app/a;)V

    .line 255
    .line 256
    .line 257
    aput-object v9, v4, v8

    .line 258
    .line 259
    invoke-static {v5}, Landroidx/fragment/app/j1;->L(I)Z

    .line 260
    .line 261
    .line 262
    move-result v9

    .line 263
    if-eqz v9, :cond_6

    .line 264
    .line 265
    const-string v9, "FragmentManager"

    .line 266
    .line 267
    const-string v10, "saveAllState: adding back stack #"

    .line 268
    .line 269
    const-string v11, ": "

    .line 270
    .line 271
    invoke-static {v10, v8, v11}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 272
    .line 273
    .line 274
    move-result-object v10

    .line 275
    iget-object v11, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 276
    .line 277
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v11

    .line 281
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 282
    .line 283
    .line 284
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v10

    .line 288
    invoke-static {v9, v10}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 289
    .line 290
    .line 291
    :cond_6
    add-int/lit8 v8, v8, 0x1

    .line 292
    .line 293
    goto :goto_3

    .line 294
    :cond_7
    move-object v4, v7

    .line 295
    :cond_8
    new-instance v3, Landroidx/fragment/app/l1;

    .line 296
    .line 297
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 298
    .line 299
    .line 300
    iput-object v7, v3, Landroidx/fragment/app/l1;->h:Ljava/lang/String;

    .line 301
    .line 302
    new-instance v5, Ljava/util/ArrayList;

    .line 303
    .line 304
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 305
    .line 306
    .line 307
    iput-object v5, v3, Landroidx/fragment/app/l1;->i:Ljava/util/ArrayList;

    .line 308
    .line 309
    new-instance v7, Ljava/util/ArrayList;

    .line 310
    .line 311
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 312
    .line 313
    .line 314
    iput-object v7, v3, Landroidx/fragment/app/l1;->j:Ljava/util/ArrayList;

    .line 315
    .line 316
    iput-object v2, v3, Landroidx/fragment/app/l1;->d:Ljava/util/ArrayList;

    .line 317
    .line 318
    iput-object v6, v3, Landroidx/fragment/app/l1;->e:Ljava/util/ArrayList;

    .line 319
    .line 320
    iput-object v4, v3, Landroidx/fragment/app/l1;->f:[Landroidx/fragment/app/b;

    .line 321
    .line 322
    iget-object v2, p0, Landroidx/fragment/app/j1;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 323
    .line 324
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 325
    .line 326
    .line 327
    move-result v2

    .line 328
    iput v2, v3, Landroidx/fragment/app/l1;->g:I

    .line 329
    .line 330
    iget-object v2, p0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 331
    .line 332
    if-eqz v2, :cond_9

    .line 333
    .line 334
    iget-object v2, v2, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 335
    .line 336
    iput-object v2, v3, Landroidx/fragment/app/l1;->h:Ljava/lang/String;

    .line 337
    .line 338
    :cond_9
    iget-object v2, p0, Landroidx/fragment/app/j1;->l:Ljava/util/Map;

    .line 339
    .line 340
    invoke-interface {v2}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 341
    .line 342
    .line 343
    move-result-object v2

    .line 344
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 345
    .line 346
    .line 347
    iget-object v2, p0, Landroidx/fragment/app/j1;->l:Ljava/util/Map;

    .line 348
    .line 349
    invoke-interface {v2}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 350
    .line 351
    .line 352
    move-result-object v2

    .line 353
    invoke-virtual {v7, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 354
    .line 355
    .line 356
    new-instance v2, Ljava/util/ArrayList;

    .line 357
    .line 358
    iget-object v4, p0, Landroidx/fragment/app/j1;->F:Ljava/util/ArrayDeque;

    .line 359
    .line 360
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 361
    .line 362
    .line 363
    iput-object v2, v3, Landroidx/fragment/app/l1;->k:Ljava/util/ArrayList;

    .line 364
    .line 365
    const-string v2, "state"

    .line 366
    .line 367
    invoke-virtual {v0, v2, v3}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 368
    .line 369
    .line 370
    iget-object v2, p0, Landroidx/fragment/app/j1;->m:Ljava/util/Map;

    .line 371
    .line 372
    invoke-interface {v2}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 373
    .line 374
    .line 375
    move-result-object v2

    .line 376
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 377
    .line 378
    .line 379
    move-result-object v2

    .line 380
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 381
    .line 382
    .line 383
    move-result v3

    .line 384
    if-eqz v3, :cond_a

    .line 385
    .line 386
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v3

    .line 390
    check-cast v3, Ljava/lang/String;

    .line 391
    .line 392
    const-string v4, "result_"

    .line 393
    .line 394
    invoke-static {v4, v3}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 395
    .line 396
    .line 397
    move-result-object v4

    .line 398
    iget-object v5, p0, Landroidx/fragment/app/j1;->m:Ljava/util/Map;

    .line 399
    .line 400
    invoke-interface {v5, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v3

    .line 404
    check-cast v3, Landroid/os/Bundle;

    .line 405
    .line 406
    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 407
    .line 408
    .line 409
    goto :goto_4

    .line 410
    :cond_a
    invoke-virtual {v1}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 411
    .line 412
    .line 413
    move-result-object p0

    .line 414
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 415
    .line 416
    .line 417
    move-result-object p0

    .line 418
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 419
    .line 420
    .line 421
    move-result v2

    .line 422
    if-eqz v2, :cond_b

    .line 423
    .line 424
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    move-result-object v2

    .line 428
    check-cast v2, Ljava/lang/String;

    .line 429
    .line 430
    const-string v3, "fragment_"

    .line 431
    .line 432
    invoke-static {v3, v2}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 433
    .line 434
    .line 435
    move-result-object v3

    .line 436
    invoke-virtual {v1, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 437
    .line 438
    .line 439
    move-result-object v2

    .line 440
    check-cast v2, Landroid/os/Bundle;

    .line 441
    .line 442
    invoke-virtual {v0, v3, v2}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 443
    .line 444
    .line 445
    goto :goto_5

    .line 446
    :cond_b
    return-object v0

    .line 447
    :goto_6
    :try_start_1
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 448
    throw p0
.end method

.method public final Z()V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x1

    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 14
    .line 15
    iget-object v1, v1, Landroidx/fragment/app/t0;->f:Landroid/os/Handler;

    .line 16
    .line 17
    iget-object v2, p0, Landroidx/fragment/app/j1;->P:Landroidx/fragment/app/s;

    .line 18
    .line 19
    invoke-virtual {v1, v2}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 23
    .line 24
    iget-object v1, v1, Landroidx/fragment/app/t0;->f:Landroid/os/Handler;

    .line 25
    .line 26
    iget-object v2, p0, Landroidx/fragment/app/j1;->P:Landroidx/fragment/app/s;

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->g0()V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    :goto_0
    monitor-exit v0

    .line 38
    return-void

    .line 39
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0
.end method

.method public final a(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;
    .locals 3

    .line 1
    iget-object v0, p1, Landroidx/fragment/app/j0;->mPreviousWho:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1, v0}, Lx6/c;->c(Landroidx/fragment/app/j0;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 v0, 0x2

    .line 9
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v1, "add: "

    .line 18
    .line 19
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v1, "FragmentManager"

    .line 30
    .line 31
    invoke-static {v1, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 32
    .line 33
    .line 34
    :cond_1
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    iput-object p0, p1, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 39
    .line 40
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 41
    .line 42
    invoke-virtual {v1, v0}, Landroidx/fragment/app/s1;->g(Landroidx/fragment/app/r1;)V

    .line 43
    .line 44
    .line 45
    iget-boolean v2, p1, Landroidx/fragment/app/j0;->mDetached:Z

    .line 46
    .line 47
    if-nez v2, :cond_3

    .line 48
    .line 49
    invoke-virtual {v1, p1}, Landroidx/fragment/app/s1;->a(Landroidx/fragment/app/j0;)V

    .line 50
    .line 51
    .line 52
    const/4 v1, 0x0

    .line 53
    iput-boolean v1, p1, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 54
    .line 55
    iget-object v2, p1, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 56
    .line 57
    if-nez v2, :cond_2

    .line 58
    .line 59
    iput-boolean v1, p1, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 60
    .line 61
    :cond_2
    invoke-static {p1}, Landroidx/fragment/app/j1;->M(Landroidx/fragment/app/j0;)Z

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    if-eqz p1, :cond_3

    .line 66
    .line 67
    const/4 p1, 0x1

    .line 68
    iput-boolean p1, p0, Landroidx/fragment/app/j1;->G:Z

    .line 69
    .line 70
    :cond_3
    return-object v0
.end method

.method public final a0(Landroidx/fragment/app/j0;Z)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->H(Landroidx/fragment/app/j0;)Landroid/view/ViewGroup;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    instance-of p1, p0, Landroidx/fragment/app/FragmentContainerView;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    check-cast p0, Landroidx/fragment/app/FragmentContainerView;

    .line 12
    .line 13
    xor-int/lit8 p1, p2, 0x1

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Landroidx/fragment/app/FragmentContainerView;->setDrawDisappearingViewsLast(Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final b(Landroidx/fragment/app/t0;Landroidx/fragment/app/r0;Landroidx/fragment/app/j0;)V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 2
    .line 3
    if-nez v0, :cond_11

    .line 4
    .line 5
    iput-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 6
    .line 7
    iput-object p2, p0, Landroidx/fragment/app/j1;->x:Landroidx/fragment/app/r0;

    .line 8
    .line 9
    iput-object p3, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 10
    .line 11
    iget-object p2, p0, Landroidx/fragment/app/j1;->p:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 12
    .line 13
    if-eqz p3, :cond_0

    .line 14
    .line 15
    new-instance v0, Landroidx/fragment/app/c1;

    .line 16
    .line 17
    invoke-direct {v0, p3}, Landroidx/fragment/app/c1;-><init>(Landroidx/fragment/app/j0;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    instance-of v0, p1, Landroidx/fragment/app/o1;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    move-object v0, p1

    .line 29
    check-cast v0, Landroidx/fragment/app/o1;

    .line 30
    .line 31
    invoke-virtual {p2, v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    :cond_1
    :goto_0
    iget-object p2, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 35
    .line 36
    if-eqz p2, :cond_2

    .line 37
    .line 38
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->g0()V

    .line 39
    .line 40
    .line 41
    :cond_2
    instance-of p2, p1, Lb/j0;

    .line 42
    .line 43
    if-eqz p2, :cond_4

    .line 44
    .line 45
    move-object p2, p1

    .line 46
    check-cast p2, Lb/j0;

    .line 47
    .line 48
    invoke-interface {p2}, Lb/j0;->getOnBackPressedDispatcher()Lb/h0;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    iput-object v0, p0, Landroidx/fragment/app/j1;->g:Lb/h0;

    .line 53
    .line 54
    if-eqz p3, :cond_3

    .line 55
    .line 56
    move-object p2, p3

    .line 57
    :cond_3
    iget-object v1, p0, Landroidx/fragment/app/j1;->j:Landroidx/fragment/app/z0;

    .line 58
    .line 59
    invoke-virtual {v0, p2, v1}, Lb/h0;->a(Landroidx/lifecycle/x;Lb/a0;)V

    .line 60
    .line 61
    .line 62
    :cond_4
    if-eqz p3, :cond_6

    .line 63
    .line 64
    iget-object p1, p3, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 65
    .line 66
    iget-object p1, p1, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 67
    .line 68
    iget-object p2, p1, Landroidx/fragment/app/n1;->e:Ljava/util/HashMap;

    .line 69
    .line 70
    iget-object v0, p3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {p2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    check-cast v0, Landroidx/fragment/app/n1;

    .line 77
    .line 78
    if-nez v0, :cond_5

    .line 79
    .line 80
    new-instance v0, Landroidx/fragment/app/n1;

    .line 81
    .line 82
    iget-boolean p1, p1, Landroidx/fragment/app/n1;->g:Z

    .line 83
    .line 84
    invoke-direct {v0, p1}, Landroidx/fragment/app/n1;-><init>(Z)V

    .line 85
    .line 86
    .line 87
    iget-object p1, p3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 88
    .line 89
    invoke-virtual {p2, p1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    :cond_5
    iput-object v0, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_6
    instance-of p2, p1, Landroidx/lifecycle/i1;

    .line 96
    .line 97
    if-eqz p2, :cond_8

    .line 98
    .line 99
    check-cast p1, Landroidx/lifecycle/i1;

    .line 100
    .line 101
    invoke-interface {p1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    const-string p2, "store"

    .line 106
    .line 107
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    sget-object p2, Lp7/a;->b:Lp7/a;

    .line 111
    .line 112
    const-string v0, "defaultCreationExtras"

    .line 113
    .line 114
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 118
    .line 119
    sget-object v1, Landroidx/fragment/app/n1;->j:Landroidx/fragment/app/m1;

    .line 120
    .line 121
    invoke-direct {v0, p1, v1, p2}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 122
    .line 123
    .line 124
    const-class p1, Landroidx/fragment/app/n1;

    .line 125
    .line 126
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    const-string p2, "modelClass"

    .line 131
    .line 132
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    invoke-interface {p1}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p2

    .line 139
    if-eqz p2, :cond_7

    .line 140
    .line 141
    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 142
    .line 143
    invoke-virtual {v1, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p2

    .line 147
    invoke-virtual {v0, p1, p2}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    check-cast p1, Landroidx/fragment/app/n1;

    .line 152
    .line 153
    iput-object p1, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 157
    .line 158
    const-string p1, "Local and anonymous classes can not be ViewModels"

    .line 159
    .line 160
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :cond_8
    new-instance p1, Landroidx/fragment/app/n1;

    .line 165
    .line 166
    const/4 p2, 0x0

    .line 167
    invoke-direct {p1, p2}, Landroidx/fragment/app/n1;-><init>(Z)V

    .line 168
    .line 169
    .line 170
    iput-object p1, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 171
    .line 172
    :goto_1
    iget-object p1, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 173
    .line 174
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->P()Z

    .line 175
    .line 176
    .line 177
    move-result p2

    .line 178
    iput-boolean p2, p1, Landroidx/fragment/app/n1;->i:Z

    .line 179
    .line 180
    iget-object p1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 181
    .line 182
    iget-object p2, p0, Landroidx/fragment/app/j1;->O:Landroidx/fragment/app/n1;

    .line 183
    .line 184
    iput-object p2, p1, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 185
    .line 186
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 187
    .line 188
    instance-of p2, p1, Lra/f;

    .line 189
    .line 190
    if-eqz p2, :cond_9

    .line 191
    .line 192
    if-nez p3, :cond_9

    .line 193
    .line 194
    check-cast p1, Lra/f;

    .line 195
    .line 196
    invoke-interface {p1}, Lra/f;->getSavedStateRegistry()Lra/d;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    new-instance p2, Landroidx/fragment/app/k0;

    .line 201
    .line 202
    const/4 v0, 0x1

    .line 203
    invoke-direct {p2, p0, v0}, Landroidx/fragment/app/k0;-><init>(Ljava/lang/Object;I)V

    .line 204
    .line 205
    .line 206
    const-string v0, "android:support:fragments"

    .line 207
    .line 208
    invoke-virtual {p1, v0, p2}, Lra/d;->c(Ljava/lang/String;Lra/c;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {p1, v0}, Lra/d;->a(Ljava/lang/String;)Landroid/os/Bundle;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    if-eqz p1, :cond_9

    .line 216
    .line 217
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->X(Landroid/os/Bundle;)V

    .line 218
    .line 219
    .line 220
    :cond_9
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 221
    .line 222
    instance-of p2, p1, Le/i;

    .line 223
    .line 224
    if-eqz p2, :cond_b

    .line 225
    .line 226
    check-cast p1, Le/i;

    .line 227
    .line 228
    invoke-interface {p1}, Le/i;->getActivityResultRegistry()Le/h;

    .line 229
    .line 230
    .line 231
    move-result-object p1

    .line 232
    if-eqz p3, :cond_a

    .line 233
    .line 234
    new-instance p2, Ljava/lang/StringBuilder;

    .line 235
    .line 236
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 237
    .line 238
    .line 239
    iget-object v0, p3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 240
    .line 241
    const-string v1, ":"

    .line 242
    .line 243
    invoke-static {p2, v0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 244
    .line 245
    .line 246
    move-result-object p2

    .line 247
    goto :goto_2

    .line 248
    :cond_a
    const-string p2, ""

    .line 249
    .line 250
    :goto_2
    const-string v0, "FragmentManager:"

    .line 251
    .line 252
    invoke-static {v0, p2}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object p2

    .line 256
    const-string v0, "StartActivityForResult"

    .line 257
    .line 258
    invoke-static {p2, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    new-instance v1, Landroidx/fragment/app/d1;

    .line 263
    .line 264
    const/4 v2, 0x4

    .line 265
    invoke-direct {v1, v2}, Landroidx/fragment/app/d1;-><init>(I)V

    .line 266
    .line 267
    .line 268
    new-instance v2, Landroidx/fragment/app/y0;

    .line 269
    .line 270
    const/4 v3, 0x1

    .line 271
    invoke-direct {v2, p0, v3}, Landroidx/fragment/app/y0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {p1, v0, v1, v2}, Le/h;->d(Ljava/lang/String;Lf/a;Le/b;)Le/g;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    iput-object v0, p0, Landroidx/fragment/app/j1;->C:Le/g;

    .line 279
    .line 280
    const-string v0, "StartIntentSenderForResult"

    .line 281
    .line 282
    invoke-static {p2, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    new-instance v1, Landroidx/fragment/app/d1;

    .line 287
    .line 288
    const/4 v2, 0x0

    .line 289
    invoke-direct {v1, v2}, Landroidx/fragment/app/d1;-><init>(I)V

    .line 290
    .line 291
    .line 292
    new-instance v2, Landroidx/fragment/app/y0;

    .line 293
    .line 294
    const/4 v3, 0x2

    .line 295
    invoke-direct {v2, p0, v3}, Landroidx/fragment/app/y0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {p1, v0, v1, v2}, Le/h;->d(Ljava/lang/String;Lf/a;Le/b;)Le/g;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    iput-object v0, p0, Landroidx/fragment/app/j1;->D:Le/g;

    .line 303
    .line 304
    const-string v0, "RequestPermissions"

    .line 305
    .line 306
    invoke-static {p2, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object p2

    .line 310
    new-instance v0, Landroidx/fragment/app/d1;

    .line 311
    .line 312
    const/4 v1, 0x2

    .line 313
    invoke-direct {v0, v1}, Landroidx/fragment/app/d1;-><init>(I)V

    .line 314
    .line 315
    .line 316
    new-instance v1, Landroidx/fragment/app/y0;

    .line 317
    .line 318
    const/4 v2, 0x0

    .line 319
    invoke-direct {v1, p0, v2}, Landroidx/fragment/app/y0;-><init>(Landroidx/fragment/app/j1;I)V

    .line 320
    .line 321
    .line 322
    invoke-virtual {p1, p2, v0, v1}, Le/h;->d(Ljava/lang/String;Lf/a;Le/b;)Le/g;

    .line 323
    .line 324
    .line 325
    move-result-object p1

    .line 326
    iput-object p1, p0, Landroidx/fragment/app/j1;->E:Le/g;

    .line 327
    .line 328
    :cond_b
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 329
    .line 330
    instance-of p2, p1, Ln5/c;

    .line 331
    .line 332
    if-eqz p2, :cond_c

    .line 333
    .line 334
    check-cast p1, Ln5/c;

    .line 335
    .line 336
    iget-object p2, p0, Landroidx/fragment/app/j1;->q:Landroidx/fragment/app/x0;

    .line 337
    .line 338
    invoke-interface {p1, p2}, Ln5/c;->addOnConfigurationChangedListener(Lc6/a;)V

    .line 339
    .line 340
    .line 341
    :cond_c
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 342
    .line 343
    instance-of p2, p1, Ln5/d;

    .line 344
    .line 345
    if-eqz p2, :cond_d

    .line 346
    .line 347
    check-cast p1, Ln5/d;

    .line 348
    .line 349
    iget-object p2, p0, Landroidx/fragment/app/j1;->r:Landroidx/fragment/app/x0;

    .line 350
    .line 351
    invoke-interface {p1, p2}, Ln5/d;->addOnTrimMemoryListener(Lc6/a;)V

    .line 352
    .line 353
    .line 354
    :cond_d
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 355
    .line 356
    instance-of p2, p1, Landroidx/core/app/i0;

    .line 357
    .line 358
    if-eqz p2, :cond_e

    .line 359
    .line 360
    check-cast p1, Landroidx/core/app/i0;

    .line 361
    .line 362
    iget-object p2, p0, Landroidx/fragment/app/j1;->s:Landroidx/fragment/app/x0;

    .line 363
    .line 364
    invoke-interface {p1, p2}, Landroidx/core/app/i0;->addOnMultiWindowModeChangedListener(Lc6/a;)V

    .line 365
    .line 366
    .line 367
    :cond_e
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 368
    .line 369
    instance-of p2, p1, Landroidx/core/app/j0;

    .line 370
    .line 371
    if-eqz p2, :cond_f

    .line 372
    .line 373
    check-cast p1, Landroidx/core/app/j0;

    .line 374
    .line 375
    iget-object p2, p0, Landroidx/fragment/app/j1;->t:Landroidx/fragment/app/x0;

    .line 376
    .line 377
    invoke-interface {p1, p2}, Landroidx/core/app/j0;->addOnPictureInPictureModeChangedListener(Lc6/a;)V

    .line 378
    .line 379
    .line 380
    :cond_f
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 381
    .line 382
    instance-of p2, p1, Ld6/k;

    .line 383
    .line 384
    if-eqz p2, :cond_10

    .line 385
    .line 386
    if-nez p3, :cond_10

    .line 387
    .line 388
    check-cast p1, Ld6/k;

    .line 389
    .line 390
    iget-object p0, p0, Landroidx/fragment/app/j1;->u:Landroidx/fragment/app/a1;

    .line 391
    .line 392
    invoke-interface {p1, p0}, Ld6/k;->addMenuProvider(Ld6/o;)V

    .line 393
    .line 394
    .line 395
    :cond_10
    return-void

    .line 396
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 397
    .line 398
    const-string p1, "Already attached"

    .line 399
    .line 400
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    throw p0
.end method

.method public final b0(Landroidx/fragment/app/j0;Landroidx/lifecycle/q;)V
    .locals 2

    .line 1
    iget-object v0, p1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p1, v0}, Landroidx/fragment/app/j0;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget-object v0, p1, Landroidx/fragment/app/j0;->mHost:Landroidx/fragment/app/t0;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p1, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 20
    .line 21
    if-ne v0, p0, :cond_1

    .line 22
    .line 23
    :cond_0
    iput-object p2, p1, Landroidx/fragment/app/j0;->mMaxState:Landroidx/lifecycle/q;

    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 27
    .line 28
    new-instance v0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v1, "Fragment "

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p1, " is not an active fragment of FragmentManager "

    .line 39
    .line 40
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p2
.end method

.method public final c(Landroidx/fragment/app/j0;)V
    .locals 4

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    const-string v2, "FragmentManager"

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v3, "attach: "

    .line 13
    .line 14
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-boolean v1, p1, Landroidx/fragment/app/j0;->mDetached:Z

    .line 28
    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    iput-boolean v1, p1, Landroidx/fragment/app/j0;->mDetached:Z

    .line 33
    .line 34
    iget-boolean v1, p1, Landroidx/fragment/app/j0;->mAdded:Z

    .line 35
    .line 36
    if-nez v1, :cond_2

    .line 37
    .line 38
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 39
    .line 40
    invoke-virtual {v1, p1}, Landroidx/fragment/app/s1;->a(Landroidx/fragment/app/j0;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_1

    .line 48
    .line 49
    new-instance v0, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v1, "add from attach: "

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-static {v2, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    :cond_1
    invoke-static {p1}, Landroidx/fragment/app/j1;->M(Landroidx/fragment/app/j0;)Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-eqz p1, :cond_2

    .line 71
    .line 72
    const/4 p1, 0x1

    .line 73
    iput-boolean p1, p0, Landroidx/fragment/app/j1;->G:Z

    .line 74
    .line 75
    :cond_2
    return-void
.end method

.method public final c0(Landroidx/fragment/app/j0;)V
    .locals 3

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p1, v0}, Landroidx/fragment/app/j0;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p1, Landroidx/fragment/app/j0;->mHost:Landroidx/fragment/app/t0;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iget-object v0, p1, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 22
    .line 23
    if-ne v0, p0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 27
    .line 28
    new-instance v1, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v2, "Fragment "

    .line 31
    .line 32
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p1, " is not an active fragment of FragmentManager "

    .line 39
    .line 40
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 55
    .line 56
    iput-object p1, p0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j1;->r(Landroidx/fragment/app/j0;)V

    .line 59
    .line 60
    .line 61
    iget-object p1, p0, Landroidx/fragment/app/j1;->z:Landroidx/fragment/app/j0;

    .line 62
    .line 63
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->r(Landroidx/fragment/app/j0;)V

    .line 64
    .line 65
    .line 66
    return-void
.end method

.method public final d()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->b:Z

    .line 3
    .line 4
    iget-object v0, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final d0(Landroidx/fragment/app/j0;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->H(Landroidx/fragment/app/j0;)Landroid/view/ViewGroup;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getEnterAnim()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getExitAnim()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getPopEnterAnim()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    add-int/2addr v0, v1

    .line 21
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getPopExitAnim()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    add-int/2addr v1, v0

    .line 26
    if-lez v1, :cond_1

    .line 27
    .line 28
    const v0, 0x7f0a0307

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-nez v1, :cond_0

    .line 36
    .line 37
    invoke-virtual {p0, v0, p1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    invoke-virtual {p0, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Landroidx/fragment/app/j0;

    .line 45
    .line 46
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->getPopDirection()Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j0;->setPopDirection(Z)V

    .line 51
    .line 52
    .line 53
    :cond_1
    return-void
.end method

.method public final e()Ljava/util/HashSet;
    .locals 6

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 7
    .line 8
    invoke-virtual {v1}, Landroidx/fragment/app/s1;->d()Ljava/util/ArrayList;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_2

    .line 21
    .line 22
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    check-cast v2, Landroidx/fragment/app/r1;

    .line 27
    .line 28
    iget-object v2, v2, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 29
    .line 30
    iget-object v2, v2, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 31
    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->J()Lip/v;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    const-string v4, "factory"

    .line 39
    .line 40
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const v3, 0x7f0a02a4

    .line 44
    .line 45
    .line 46
    invoke-virtual {v2, v3}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    instance-of v5, v4, Landroidx/fragment/app/r;

    .line 51
    .line 52
    if-eqz v5, :cond_1

    .line 53
    .line 54
    check-cast v4, Landroidx/fragment/app/r;

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    new-instance v4, Landroidx/fragment/app/r;

    .line 58
    .line 59
    invoke-direct {v4, v2}, Landroidx/fragment/app/r;-><init>(Landroid/view/ViewGroup;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v2, v3, v4}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :goto_1
    invoke-virtual {v0, v4}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    return-object v0
.end method

.method public final f(Ljava/util/ArrayList;II)Ljava/util/HashSet;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    :goto_0
    if-ge p2, p3, :cond_2

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Landroidx/fragment/app/a;

    .line 13
    .line 14
    iget-object v1, v1, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :cond_0
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Landroidx/fragment/app/t1;

    .line 31
    .line 32
    iget-object v2, v2, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 33
    .line 34
    if-eqz v2, :cond_0

    .line 35
    .line 36
    iget-object v2, v2, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    invoke-static {v2, p0}, Landroidx/fragment/app/r;->j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-virtual {v0, v2}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    add-int/lit8 p2, p2, 0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    return-object v0
.end method

.method public final f0(Ljava/lang/IllegalStateException;)V
    .locals 7

    .line 1
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "FragmentManager"

    .line 6
    .line 7
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 8
    .line 9
    .line 10
    const-string v0, "Activity state:"

    .line 11
    .line 12
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    new-instance v0, Landroidx/fragment/app/d2;

    .line 16
    .line 17
    invoke-direct {v0}, Landroidx/fragment/app/d2;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance v2, Ljava/io/PrintWriter;

    .line 21
    .line 22
    invoke-direct {v2, v0}, Ljava/io/PrintWriter;-><init>(Ljava/io/Writer;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 26
    .line 27
    const-string v3, "Failed dumping state"

    .line 28
    .line 29
    const/4 v4, 0x0

    .line 30
    const/4 v5, 0x0

    .line 31
    const-string v6, "  "

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    :try_start_0
    new-array p0, v4, [Ljava/lang/String;

    .line 36
    .line 37
    check-cast v0, Landroidx/fragment/app/n0;

    .line 38
    .line 39
    iget-object v0, v0, Landroidx/fragment/app/n0;->h:Landroidx/fragment/app/o0;

    .line 40
    .line 41
    invoke-virtual {v0, v6, v5, v2, p0}, Landroidx/fragment/app/o0;->dump(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catch_0
    move-exception p0

    .line 46
    invoke-static {v1, v3, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    :try_start_1
    new-array v0, v4, [Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {p0, v6, v5, v2, v0}, Landroidx/fragment/app/j1;->v(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :catch_1
    move-exception p0

    .line 57
    invoke-static {v1, v3, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 58
    .line 59
    .line 60
    :goto_0
    throw p1
.end method

.method public final g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;
    .locals 3

    .line 1
    iget-object v0, p1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 4
    .line 5
    iget-object v2, v1, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-virtual {v2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Landroidx/fragment/app/r1;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    new-instance v0, Landroidx/fragment/app/r1;

    .line 17
    .line 18
    iget-object v2, p0, Landroidx/fragment/app/j1;->o:Landroidx/fragment/app/p0;

    .line 19
    .line 20
    invoke-direct {v0, v2, v1, p1}, Landroidx/fragment/app/r1;-><init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Landroidx/fragment/app/j0;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 24
    .line 25
    iget-object p1, p1, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 26
    .line 27
    invoke-virtual {p1}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {v0, p1}, Landroidx/fragment/app/r1;->l(Ljava/lang/ClassLoader;)V

    .line 32
    .line 33
    .line 34
    iget p0, p0, Landroidx/fragment/app/j1;->v:I

    .line 35
    .line 36
    iput p0, v0, Landroidx/fragment/app/r1;->e:I

    .line 37
    .line 38
    return-object v0
.end method

.method public final g0()V
    .locals 5

    .line 1
    const-string v0, "FragmentManager "

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget-object v2, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/4 v3, 0x3

    .line 13
    const/4 v4, 0x1

    .line 14
    if-nez v2, :cond_1

    .line 15
    .line 16
    iget-object v2, p0, Landroidx/fragment/app/j1;->j:Landroidx/fragment/app/z0;

    .line 17
    .line 18
    invoke-virtual {v2, v4}, Lb/a0;->setEnabled(Z)V

    .line 19
    .line 20
    .line 21
    invoke-static {v3}, Landroidx/fragment/app/j1;->L(I)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    const-string v2, "FragmentManager"

    .line 28
    .line 29
    new-instance v3, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p0, " enabling OnBackPressedCallback, caused by non-empty pending actions"

    .line 38
    .line 39
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-static {v2, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_0
    move-exception p0

    .line 51
    goto :goto_3

    .line 52
    :cond_0
    :goto_0
    monitor-exit v1

    .line 53
    return-void

    .line 54
    :cond_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    iget-object v0, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    iget-object v1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 62
    .line 63
    const/4 v2, 0x0

    .line 64
    if-eqz v1, :cond_2

    .line 65
    .line 66
    move v1, v4

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    move v1, v2

    .line 69
    :goto_1
    add-int/2addr v0, v1

    .line 70
    if-lez v0, :cond_3

    .line 71
    .line 72
    iget-object v0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 73
    .line 74
    invoke-static {v0}, Landroidx/fragment/app/j1;->O(Landroidx/fragment/app/j0;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-eqz v0, :cond_3

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_3
    move v4, v2

    .line 82
    :goto_2
    invoke-static {v3}, Landroidx/fragment/app/j1;->L(I)Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-eqz v0, :cond_4

    .line 87
    .line 88
    const-string v0, "FragmentManager"

    .line 89
    .line 90
    new-instance v1, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    const-string v2, "OnBackPressedCallback for FragmentManager "

    .line 93
    .line 94
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v2, " enabled state is "

    .line 101
    .line 102
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 113
    .line 114
    .line 115
    :cond_4
    iget-object p0, p0, Landroidx/fragment/app/j1;->j:Landroidx/fragment/app/z0;

    .line 116
    .line 117
    invoke-virtual {p0, v4}, Lb/a0;->setEnabled(Z)V

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :goto_3
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 122
    throw p0
.end method

.method public final h(Landroidx/fragment/app/j0;)V
    .locals 4

    .line 1
    const-string v0, "FragmentManager"

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    new-instance v2, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v3, "detach: "

    .line 13
    .line 14
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    invoke-static {v0, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-boolean v2, p1, Landroidx/fragment/app/j0;->mDetached:Z

    .line 28
    .line 29
    if-nez v2, :cond_3

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    iput-boolean v2, p1, Landroidx/fragment/app/j0;->mDetached:Z

    .line 33
    .line 34
    iget-boolean v3, p1, Landroidx/fragment/app/j0;->mAdded:Z

    .line 35
    .line 36
    if-eqz v3, :cond_3

    .line 37
    .line 38
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    new-instance v1, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    const-string v3, "remove from detach: "

    .line 47
    .line 48
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-static {v0, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 59
    .line 60
    .line 61
    :cond_1
    iget-object v0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 62
    .line 63
    iget-object v1, v0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 64
    .line 65
    monitor-enter v1

    .line 66
    :try_start_0
    iget-object v0, v0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 67
    .line 68
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 72
    const/4 v0, 0x0

    .line 73
    iput-boolean v0, p1, Landroidx/fragment/app/j0;->mAdded:Z

    .line 74
    .line 75
    invoke-static {p1}, Landroidx/fragment/app/j1;->M(Landroidx/fragment/app/j0;)Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    if-eqz v0, :cond_2

    .line 80
    .line 81
    iput-boolean v2, p0, Landroidx/fragment/app/j1;->G:Z

    .line 82
    .line 83
    :cond_2
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->d0(Landroidx/fragment/app/j0;)V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :catchall_0
    move-exception p0

    .line 88
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 89
    throw p0

    .line 90
    :cond_3
    return-void
.end method

.method public final i(ZLandroid/content/res/Configuration;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 4
    .line 5
    instance-of v0, v0, Ln5/c;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string p2, "Do not call dispatchConfigurationChanged() on host. Host implements OnConfigurationChangedProvider and automatically dispatches configuration changes to fragments."

    .line 13
    .line 14
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->f0(Ljava/lang/IllegalStateException;)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    :cond_1
    :goto_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 23
    .line 24
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Landroidx/fragment/app/j0;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {v0, p2}, Landroidx/fragment/app/j0;->performConfigurationChanged(Landroid/content/res/Configuration;)V

    .line 47
    .line 48
    .line 49
    if-eqz p1, :cond_2

    .line 50
    .line 51
    iget-object v0, v0, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    invoke-virtual {v0, v1, p2}, Landroidx/fragment/app/j1;->i(ZLandroid/content/res/Configuration;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    return-void
.end method

.method public final j(Landroid/view/MenuItem;)Z
    .locals 3

    .line 1
    iget v0, p0, Landroidx/fragment/app/j1;->v:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ge v0, v2, :cond_0

    .line 6
    .line 7
    return v1

    .line 8
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Landroidx/fragment/app/j0;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j0;->performContextItemSelected(Landroid/view/MenuItem;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_1

    .line 37
    .line 38
    return v2

    .line 39
    :cond_2
    return v1
.end method

.method public final k(Landroid/view/Menu;Landroid/view/MenuInflater;)Z
    .locals 7

    .line 1
    iget v0, p0, Landroidx/fragment/app/j1;->v:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ge v0, v2, :cond_0

    .line 6
    .line 7
    return v1

    .line 8
    :cond_0
    iget-object v0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 9
    .line 10
    invoke-virtual {v0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v3, 0x0

    .line 19
    move v4, v1

    .line 20
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    if-eqz v5, :cond_3

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    check-cast v5, Landroidx/fragment/app/j0;

    .line 31
    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    invoke-virtual {v5}, Landroidx/fragment/app/j0;->isMenuVisible()Z

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    if-eqz v6, :cond_1

    .line 39
    .line 40
    invoke-virtual {v5, p1, p2}, Landroidx/fragment/app/j0;->performCreateOptionsMenu(Landroid/view/Menu;Landroid/view/MenuInflater;)Z

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    if-eqz v6, :cond_1

    .line 45
    .line 46
    if-nez v3, :cond_2

    .line 47
    .line 48
    new-instance v3, Ljava/util/ArrayList;

    .line 49
    .line 50
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 51
    .line 52
    .line 53
    :cond_2
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move v4, v2

    .line 57
    goto :goto_0

    .line 58
    :cond_3
    iget-object p1, p0, Landroidx/fragment/app/j1;->e:Ljava/util/ArrayList;

    .line 59
    .line 60
    if-eqz p1, :cond_6

    .line 61
    .line 62
    :goto_1
    iget-object p1, p0, Landroidx/fragment/app/j1;->e:Ljava/util/ArrayList;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-ge v1, p1, :cond_6

    .line 69
    .line 70
    iget-object p1, p0, Landroidx/fragment/app/j1;->e:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    check-cast p1, Landroidx/fragment/app/j0;

    .line 77
    .line 78
    if-eqz v3, :cond_4

    .line 79
    .line 80
    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    if-nez p2, :cond_5

    .line 85
    .line 86
    :cond_4
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->onDestroyOptionsMenu()V

    .line 87
    .line 88
    .line 89
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_6
    iput-object v3, p0, Landroidx/fragment/app/j1;->e:Ljava/util/ArrayList;

    .line 93
    .line 94
    return v4
.end method

.method public final l()V
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->J:Z

    .line 3
    .line 4
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->w()V

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 11
    .line 12
    instance-of v2, v1, Landroidx/lifecycle/i1;

    .line 13
    .line 14
    iget-object v3, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    iget-object v0, v3, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 19
    .line 20
    iget-boolean v0, v0, Landroidx/fragment/app/n1;->h:Z

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object v1, v1, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    invoke-virtual {v1}, Landroid/app/Activity;->isChangingConfigurations()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    xor-int/2addr v0, v1

    .line 32
    :cond_1
    :goto_0
    if-eqz v0, :cond_3

    .line 33
    .line 34
    iget-object v0, p0, Landroidx/fragment/app/j1;->l:Ljava/util/Map;

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_3

    .line 49
    .line 50
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Landroidx/fragment/app/c;

    .line 55
    .line 56
    iget-object v1, v1, Landroidx/fragment/app/c;->d:Ljava/util/ArrayList;

    .line 57
    .line 58
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eqz v2, :cond_2

    .line 67
    .line 68
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Ljava/lang/String;

    .line 73
    .line 74
    iget-object v4, v3, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 75
    .line 76
    const/4 v5, 0x0

    .line 77
    invoke-virtual {v4, v2, v5}, Landroidx/fragment/app/n1;->d(Ljava/lang/String;Z)V

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    const/4 v0, -0x1

    .line 82
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j1;->u(I)V

    .line 83
    .line 84
    .line 85
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 86
    .line 87
    instance-of v1, v0, Ln5/d;

    .line 88
    .line 89
    if-eqz v1, :cond_4

    .line 90
    .line 91
    check-cast v0, Ln5/d;

    .line 92
    .line 93
    iget-object v1, p0, Landroidx/fragment/app/j1;->r:Landroidx/fragment/app/x0;

    .line 94
    .line 95
    invoke-interface {v0, v1}, Ln5/d;->removeOnTrimMemoryListener(Lc6/a;)V

    .line 96
    .line 97
    .line 98
    :cond_4
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 99
    .line 100
    instance-of v1, v0, Ln5/c;

    .line 101
    .line 102
    if-eqz v1, :cond_5

    .line 103
    .line 104
    check-cast v0, Ln5/c;

    .line 105
    .line 106
    iget-object v1, p0, Landroidx/fragment/app/j1;->q:Landroidx/fragment/app/x0;

    .line 107
    .line 108
    invoke-interface {v0, v1}, Ln5/c;->removeOnConfigurationChangedListener(Lc6/a;)V

    .line 109
    .line 110
    .line 111
    :cond_5
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 112
    .line 113
    instance-of v1, v0, Landroidx/core/app/i0;

    .line 114
    .line 115
    if-eqz v1, :cond_6

    .line 116
    .line 117
    check-cast v0, Landroidx/core/app/i0;

    .line 118
    .line 119
    iget-object v1, p0, Landroidx/fragment/app/j1;->s:Landroidx/fragment/app/x0;

    .line 120
    .line 121
    invoke-interface {v0, v1}, Landroidx/core/app/i0;->removeOnMultiWindowModeChangedListener(Lc6/a;)V

    .line 122
    .line 123
    .line 124
    :cond_6
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 125
    .line 126
    instance-of v1, v0, Landroidx/core/app/j0;

    .line 127
    .line 128
    if-eqz v1, :cond_7

    .line 129
    .line 130
    check-cast v0, Landroidx/core/app/j0;

    .line 131
    .line 132
    iget-object v1, p0, Landroidx/fragment/app/j1;->t:Landroidx/fragment/app/x0;

    .line 133
    .line 134
    invoke-interface {v0, v1}, Landroidx/core/app/j0;->removeOnPictureInPictureModeChangedListener(Lc6/a;)V

    .line 135
    .line 136
    .line 137
    :cond_7
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 138
    .line 139
    instance-of v1, v0, Ld6/k;

    .line 140
    .line 141
    if-eqz v1, :cond_8

    .line 142
    .line 143
    iget-object v1, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 144
    .line 145
    if-nez v1, :cond_8

    .line 146
    .line 147
    check-cast v0, Ld6/k;

    .line 148
    .line 149
    iget-object v1, p0, Landroidx/fragment/app/j1;->u:Landroidx/fragment/app/a1;

    .line 150
    .line 151
    invoke-interface {v0, v1}, Ld6/k;->removeMenuProvider(Ld6/o;)V

    .line 152
    .line 153
    .line 154
    :cond_8
    const/4 v0, 0x0

    .line 155
    iput-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 156
    .line 157
    iput-object v0, p0, Landroidx/fragment/app/j1;->x:Landroidx/fragment/app/r0;

    .line 158
    .line 159
    iput-object v0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 160
    .line 161
    iget-object v1, p0, Landroidx/fragment/app/j1;->g:Lb/h0;

    .line 162
    .line 163
    if-eqz v1, :cond_9

    .line 164
    .line 165
    iget-object v1, p0, Landroidx/fragment/app/j1;->j:Landroidx/fragment/app/z0;

    .line 166
    .line 167
    invoke-virtual {v1}, Lb/a0;->remove()V

    .line 168
    .line 169
    .line 170
    iput-object v0, p0, Landroidx/fragment/app/j1;->g:Lb/h0;

    .line 171
    .line 172
    :cond_9
    iget-object v0, p0, Landroidx/fragment/app/j1;->C:Le/g;

    .line 173
    .line 174
    if-eqz v0, :cond_a

    .line 175
    .line 176
    invoke-virtual {v0}, Le/g;->b()V

    .line 177
    .line 178
    .line 179
    iget-object v0, p0, Landroidx/fragment/app/j1;->D:Le/g;

    .line 180
    .line 181
    invoke-virtual {v0}, Le/g;->b()V

    .line 182
    .line 183
    .line 184
    iget-object p0, p0, Landroidx/fragment/app/j1;->E:Le/g;

    .line 185
    .line 186
    invoke-virtual {p0}, Le/g;->b()V

    .line 187
    .line 188
    .line 189
    :cond_a
    return-void
.end method

.method public final m(Z)V
    .locals 2

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 4
    .line 5
    instance-of v0, v0, Ln5/d;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Do not call dispatchLowMemory() on host. Host implements OnTrimMemoryProvider and automatically dispatches low memory callbacks to fragments."

    .line 13
    .line 14
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->f0(Ljava/lang/IllegalStateException;)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    :cond_1
    :goto_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 23
    .line 24
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Landroidx/fragment/app/j0;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->performLowMemory()V

    .line 47
    .line 48
    .line 49
    if-eqz p1, :cond_2

    .line 50
    .line 51
    iget-object v0, v0, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    invoke-virtual {v0, v1}, Landroidx/fragment/app/j1;->m(Z)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    return-void
.end method

.method public final n(ZZ)V
    .locals 2

    .line 1
    if-eqz p2, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 4
    .line 5
    instance-of v0, v0, Landroidx/core/app/i0;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string p2, "Do not call dispatchMultiWindowModeChanged() on host. Host implements OnMultiWindowModeChangedProvider and automatically dispatches multi-window mode changes to fragments."

    .line 13
    .line 14
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->f0(Ljava/lang/IllegalStateException;)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    :cond_1
    :goto_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 23
    .line 24
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Landroidx/fragment/app/j0;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j0;->performMultiWindowModeChanged(Z)V

    .line 47
    .line 48
    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    iget-object v0, v0, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/j1;->n(ZZ)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    return-void
.end method

.method public final o()V
    .locals 2

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->e()Ljava/util/ArrayList;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Landroidx/fragment/app/j0;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->isHidden()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-virtual {v0, v1}, Landroidx/fragment/app/j0;->onHiddenChanged(Z)V

    .line 30
    .line 31
    .line 32
    iget-object v0, v0, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroidx/fragment/app/j1;->o()V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    return-void
.end method

.method public final p(Landroid/view/MenuItem;)Z
    .locals 3

    .line 1
    iget v0, p0, Landroidx/fragment/app/j1;->v:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ge v0, v2, :cond_0

    .line 6
    .line 7
    return v1

    .line 8
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Landroidx/fragment/app/j0;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j0;->performOptionsItemSelected(Landroid/view/MenuItem;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_1

    .line 37
    .line 38
    return v2

    .line 39
    :cond_2
    return v1
.end method

.method public final q(Landroid/view/Menu;)V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/fragment/app/j1;->v:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ge v0, v1, :cond_0

    .line 5
    .line 6
    goto :goto_1

    .line 7
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Landroidx/fragment/app/j0;

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j0;->performOptionsMenuClosed(Landroid/view/Menu;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    :goto_1
    return-void
.end method

.method public final r(Landroidx/fragment/app/j0;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p1, p0}, Landroidx/fragment/app/j0;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1}, Landroidx/fragment/app/j0;->performPrimaryNavigationFragmentChanged()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public final s(ZZ)V
    .locals 2

    .line 1
    if-eqz p2, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 4
    .line 5
    instance-of v0, v0, Landroidx/core/app/j0;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string p2, "Do not call dispatchPictureInPictureModeChanged() on host. Host implements OnPictureInPictureModeChangedProvider and automatically dispatches picture-in-picture mode changes to fragments."

    .line 13
    .line 14
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->f0(Ljava/lang/IllegalStateException;)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    :cond_1
    :goto_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 23
    .line 24
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Landroidx/fragment/app/j0;

    .line 43
    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j0;->performPictureInPictureModeChanged(Z)V

    .line 47
    .line 48
    .line 49
    if-eqz p2, :cond_2

    .line 50
    .line 51
    iget-object v0, v0, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    invoke-virtual {v0, p1, v1}, Landroidx/fragment/app/j1;->s(ZZ)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    return-void
.end method

.method public final t(Landroid/view/Menu;)Z
    .locals 4

    .line 1
    iget v0, p0, Landroidx/fragment/app/j1;->v:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ge v0, v2, :cond_0

    .line 6
    .line 7
    return v1

    .line 8
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 9
    .line 10
    invoke-virtual {p0}, Landroidx/fragment/app/s1;->f()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Landroidx/fragment/app/j0;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->isMenuVisible()Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j0;->performPrepareOptionsMenu(Landroid/view/Menu;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    move v1, v2

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const/16 v1, 0x80

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "FragmentManager{"

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string v1, " in "

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    iget-object v1, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 30
    .line 31
    const-string v2, "}"

    .line 32
    .line 33
    const-string v3, "{"

    .line 34
    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 52
    .line 53
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    iget-object v1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 69
    .line 70
    if-eqz v1, :cond_1

    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    iget-object p0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 87
    .line 88
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_1
    const-string p0, "null"

    .line 104
    .line 105
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    :goto_0
    const-string p0, "}}"

    .line 109
    .line 110
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    return-object p0
.end method

.method public final u(I)V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    :try_start_0
    iput-boolean v0, p0, Landroidx/fragment/app/j1;->b:Z

    .line 4
    .line 5
    iget-object v2, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 6
    .line 7
    iget-object v2, v2, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_1

    .line 22
    .line 23
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Landroidx/fragment/app/r1;

    .line 28
    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    iput p1, v3, Landroidx/fragment/app/r1;->e:I

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    invoke-virtual {p0, p1, v1}, Landroidx/fragment/app/j1;->Q(IZ)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->e()Ljava/util/HashSet;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_2

    .line 50
    .line 51
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    check-cast v2, Landroidx/fragment/app/r;

    .line 56
    .line 57
    invoke-virtual {v2}, Landroidx/fragment/app/r;->i()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :catchall_0
    move-exception p1

    .line 62
    goto :goto_2

    .line 63
    :cond_2
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->b:Z

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :goto_2
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->b:Z

    .line 70
    .line 71
    throw p1
.end method

.method public final v(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V
    .locals 5

    .line 1
    const-string v0, "    "

    .line 2
    .line 3
    invoke-static {p1, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 8
    .line 9
    iget-object v2, v1, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 10
    .line 11
    const-string v3, "    "

    .line 12
    .line 13
    invoke-static {p1, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    iget-object v1, v1, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    if-nez v4, :cond_1

    .line 24
    .line 25
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v4, "Active Fragments:"

    .line 29
    .line 30
    invoke-virtual {p3, v4}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_1

    .line 46
    .line 47
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Landroidx/fragment/app/r1;

    .line 52
    .line 53
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    if-eqz v4, :cond_0

    .line 57
    .line 58
    iget-object v4, v4, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 59
    .line 60
    invoke-virtual {p3, v4}, Ljava/io/PrintWriter;->println(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v4, v3, p2, p3, p4}, Landroidx/fragment/app/j0;->dump(Ljava/lang/String;Ljava/io/FileDescriptor;Ljava/io/PrintWriter;[Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_0
    const-string v4, "null"

    .line 68
    .line 69
    invoke-virtual {p3, v4}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    const/4 p4, 0x0

    .line 78
    if-lez p2, :cond_2

    .line 79
    .line 80
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    const-string v1, "Added Fragments:"

    .line 84
    .line 85
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    move v1, p4

    .line 89
    :goto_1
    if-ge v1, p2, :cond_2

    .line 90
    .line 91
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Landroidx/fragment/app/j0;

    .line 96
    .line 97
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    const-string v4, "  #"

    .line 101
    .line 102
    invoke-virtual {p3, v4}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->print(I)V

    .line 106
    .line 107
    .line 108
    const-string v4, ": "

    .line 109
    .line 110
    invoke-virtual {p3, v4}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    invoke-virtual {p3, v3}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    add-int/lit8 v1, v1, 0x1

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_2
    iget-object p2, p0, Landroidx/fragment/app/j1;->e:Ljava/util/ArrayList;

    .line 124
    .line 125
    if-eqz p2, :cond_3

    .line 126
    .line 127
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-lez p2, :cond_3

    .line 132
    .line 133
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    const-string v1, "Fragments Created Menus:"

    .line 137
    .line 138
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    move v1, p4

    .line 142
    :goto_2
    if-ge v1, p2, :cond_3

    .line 143
    .line 144
    iget-object v2, p0, Landroidx/fragment/app/j1;->e:Ljava/util/ArrayList;

    .line 145
    .line 146
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    check-cast v2, Landroidx/fragment/app/j0;

    .line 151
    .line 152
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    const-string v3, "  #"

    .line 156
    .line 157
    invoke-virtual {p3, v3}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->print(I)V

    .line 161
    .line 162
    .line 163
    const-string v3, ": "

    .line 164
    .line 165
    invoke-virtual {p3, v3}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v2}, Landroidx/fragment/app/j0;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    invoke-virtual {p3, v2}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    add-int/lit8 v1, v1, 0x1

    .line 176
    .line 177
    goto :goto_2

    .line 178
    :cond_3
    iget-object p2, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 179
    .line 180
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 181
    .line 182
    .line 183
    move-result p2

    .line 184
    if-lez p2, :cond_4

    .line 185
    .line 186
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    const-string v1, "Back Stack:"

    .line 190
    .line 191
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    move v1, p4

    .line 195
    :goto_3
    if-ge v1, p2, :cond_4

    .line 196
    .line 197
    iget-object v2, p0, Landroidx/fragment/app/j1;->d:Ljava/util/ArrayList;

    .line 198
    .line 199
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    check-cast v2, Landroidx/fragment/app/a;

    .line 204
    .line 205
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    const-string v3, "  #"

    .line 209
    .line 210
    invoke-virtual {p3, v3}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->print(I)V

    .line 214
    .line 215
    .line 216
    const-string v3, ": "

    .line 217
    .line 218
    invoke-virtual {p3, v3}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v2}, Landroidx/fragment/app/a;->toString()Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v3

    .line 225
    invoke-virtual {p3, v3}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    const/4 v3, 0x1

    .line 229
    invoke-virtual {v2, v0, p3, v3}, Landroidx/fragment/app/a;->g(Ljava/lang/String;Ljava/io/PrintWriter;Z)V

    .line 230
    .line 231
    .line 232
    add-int/lit8 v1, v1, 0x1

    .line 233
    .line 234
    goto :goto_3

    .line 235
    :cond_4
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    new-instance p2, Ljava/lang/StringBuilder;

    .line 239
    .line 240
    const-string v0, "Back Stack Index: "

    .line 241
    .line 242
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    iget-object v0, p0, Landroidx/fragment/app/j1;->k:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 246
    .line 247
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 248
    .line 249
    .line 250
    move-result v0

    .line 251
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 252
    .line 253
    .line 254
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object p2

    .line 258
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    iget-object p2, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 262
    .line 263
    monitor-enter p2

    .line 264
    :try_start_0
    iget-object v0, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 265
    .line 266
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 267
    .line 268
    .line 269
    move-result v0

    .line 270
    if-lez v0, :cond_5

    .line 271
    .line 272
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    const-string v1, "Pending Actions:"

    .line 276
    .line 277
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    :goto_4
    if-ge p4, v0, :cond_5

    .line 281
    .line 282
    iget-object v1, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 283
    .line 284
    invoke-virtual {v1, p4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    check-cast v1, Landroidx/fragment/app/g1;

    .line 289
    .line 290
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    const-string v2, "  #"

    .line 294
    .line 295
    invoke-virtual {p3, v2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {p3, p4}, Ljava/io/PrintWriter;->print(I)V

    .line 299
    .line 300
    .line 301
    const-string v2, ": "

    .line 302
    .line 303
    invoke-virtual {p3, v2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    invoke-virtual {p3, v1}, Ljava/io/PrintWriter;->println(Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    add-int/lit8 p4, p4, 0x1

    .line 310
    .line 311
    goto :goto_4

    .line 312
    :catchall_0
    move-exception p0

    .line 313
    goto :goto_5

    .line 314
    :cond_5
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 315
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    const-string p2, "FragmentManager misc state:"

    .line 319
    .line 320
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->println(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    const-string p2, "  mHost="

    .line 327
    .line 328
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 329
    .line 330
    .line 331
    iget-object p2, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 332
    .line 333
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->println(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 337
    .line 338
    .line 339
    const-string p2, "  mContainer="

    .line 340
    .line 341
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    iget-object p2, p0, Landroidx/fragment/app/j1;->x:Landroidx/fragment/app/r0;

    .line 345
    .line 346
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->println(Ljava/lang/Object;)V

    .line 347
    .line 348
    .line 349
    iget-object p2, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 350
    .line 351
    if-eqz p2, :cond_6

    .line 352
    .line 353
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    const-string p2, "  mParent="

    .line 357
    .line 358
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    iget-object p2, p0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 362
    .line 363
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->println(Ljava/lang/Object;)V

    .line 364
    .line 365
    .line 366
    :cond_6
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    const-string p2, "  mCurState="

    .line 370
    .line 371
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 372
    .line 373
    .line 374
    iget p2, p0, Landroidx/fragment/app/j1;->v:I

    .line 375
    .line 376
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(I)V

    .line 377
    .line 378
    .line 379
    const-string p2, " mStateSaved="

    .line 380
    .line 381
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    iget-boolean p2, p0, Landroidx/fragment/app/j1;->H:Z

    .line 385
    .line 386
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Z)V

    .line 387
    .line 388
    .line 389
    const-string p2, " mStopped="

    .line 390
    .line 391
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    iget-boolean p2, p0, Landroidx/fragment/app/j1;->I:Z

    .line 395
    .line 396
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Z)V

    .line 397
    .line 398
    .line 399
    const-string p2, " mDestroyed="

    .line 400
    .line 401
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    iget-boolean p2, p0, Landroidx/fragment/app/j1;->J:Z

    .line 405
    .line 406
    invoke-virtual {p3, p2}, Ljava/io/PrintWriter;->println(Z)V

    .line 407
    .line 408
    .line 409
    iget-boolean p2, p0, Landroidx/fragment/app/j1;->G:Z

    .line 410
    .line 411
    if-eqz p2, :cond_7

    .line 412
    .line 413
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    const-string p1, "  mNeedMenuInvalidate="

    .line 417
    .line 418
    invoke-virtual {p3, p1}, Ljava/io/PrintWriter;->print(Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    iget-boolean p0, p0, Landroidx/fragment/app/j1;->G:Z

    .line 422
    .line 423
    invoke-virtual {p3, p0}, Ljava/io/PrintWriter;->println(Z)V

    .line 424
    .line 425
    .line 426
    :cond_7
    return-void

    .line 427
    :goto_5
    :try_start_1
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 428
    throw p0
.end method

.method public final w()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->e()Ljava/util/HashSet;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Landroidx/fragment/app/r;

    .line 20
    .line 21
    invoke-virtual {v0}, Landroidx/fragment/app/r;->i()V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public final x(Landroidx/fragment/app/g1;Z)V
    .locals 2

    .line 1
    if-nez p2, :cond_3

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-boolean p0, p0, Landroidx/fragment/app/j1;->J:Z

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 12
    .line 13
    const-string p1, "FragmentManager has been destroyed"

    .line 14
    .line 15
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "FragmentManager has not been attached to a host."

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->P()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_2

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string p1, "Can not perform this action after onSaveInstanceState"

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_3
    :goto_0
    iget-object v0, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 43
    .line 44
    monitor-enter v0

    .line 45
    :try_start_0
    iget-object v1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 46
    .line 47
    if-nez v1, :cond_5

    .line 48
    .line 49
    if-eqz p2, :cond_4

    .line 50
    .line 51
    monitor-exit v0

    .line 52
    return-void

    .line 53
    :catchall_0
    move-exception p0

    .line 54
    goto :goto_1

    .line 55
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "Activity has been destroyed"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_5
    iget-object p2, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->Z()V

    .line 69
    .line 70
    .line 71
    monitor-exit v0

    .line 72
    return-void

    .line 73
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 74
    throw p0
.end method

.method public final y(Z)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Landroidx/fragment/app/j1;->b:Z

    .line 2
    .line 3
    if-nez v0, :cond_6

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean p0, p0, Landroidx/fragment/app/j1;->J:Z

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 14
    .line 15
    const-string p1, "FragmentManager has been destroyed"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "FragmentManager has not been attached to a host."

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iget-object v1, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 34
    .line 35
    iget-object v1, v1, Landroidx/fragment/app/t0;->f:Landroid/os/Handler;

    .line 36
    .line 37
    invoke-virtual {v1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    if-ne v0, v1, :cond_5

    .line 42
    .line 43
    if-nez p1, :cond_3

    .line 44
    .line 45
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->P()Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-nez p1, :cond_2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "Can not perform this action after onSaveInstanceState"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_3
    :goto_0
    iget-object p1, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 61
    .line 62
    if-nez p1, :cond_4

    .line 63
    .line 64
    new-instance p1, Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 70
    .line 71
    new-instance p1, Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 74
    .line 75
    .line 76
    iput-object p1, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 77
    .line 78
    :cond_4
    return-void

    .line 79
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 80
    .line 81
    const-string p1, "Must be called from main thread of fragment host"

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 88
    .line 89
    const-string p1, "FragmentManager is already executing transactions"

    .line 90
    .line 91
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p0
.end method

.method public final z(Z)Z
    .locals 9

    .line 1
    invoke-virtual {p0, p1}, Landroidx/fragment/app/j1;->y(Z)V

    .line 2
    .line 3
    .line 4
    iget-boolean p1, p0, Landroidx/fragment/app/j1;->i:Z

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez p1, :cond_3

    .line 9
    .line 10
    iget-object p1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 11
    .line 12
    if-eqz p1, :cond_3

    .line 13
    .line 14
    iput-boolean v1, p1, Landroidx/fragment/app/a;->r:Z

    .line 15
    .line 16
    invoke-virtual {p1}, Landroidx/fragment/app/a;->d()V

    .line 17
    .line 18
    .line 19
    const/4 p1, 0x3

    .line 20
    invoke-static {p1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-eqz p1, :cond_0

    .line 25
    .line 26
    const-string p1, "FragmentManager"

    .line 27
    .line 28
    new-instance v2, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v3, "Reversing mTransitioningOp "

    .line 31
    .line 32
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object v3, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 36
    .line 37
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v3, " as part of execPendingActions for actions "

    .line 41
    .line 42
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v3, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-static {p1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 55
    .line 56
    .line 57
    :cond_0
    iget-object p1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 58
    .line 59
    invoke-virtual {p1, v1, v1}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 63
    .line 64
    iget-object v2, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 65
    .line 66
    invoke-virtual {p1, v1, v2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object p1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 70
    .line 71
    iget-object p1, p1, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    :cond_1
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    if-eqz v2, :cond_2

    .line 82
    .line 83
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    check-cast v2, Landroidx/fragment/app/t1;

    .line 88
    .line 89
    iget-object v2, v2, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 90
    .line 91
    if-eqz v2, :cond_1

    .line 92
    .line 93
    iput-boolean v1, v2, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_2
    iput-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 97
    .line 98
    :cond_3
    move p1, v1

    .line 99
    :goto_1
    iget-object v2, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 100
    .line 101
    iget-object v3, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 102
    .line 103
    iget-object v4, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 104
    .line 105
    monitor-enter v4

    .line 106
    :try_start_0
    iget-object v5, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 109
    .line 110
    .line 111
    move-result v5

    .line 112
    if-eqz v5, :cond_4

    .line 113
    .line 114
    monitor-exit v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 115
    move v7, v1

    .line 116
    goto :goto_3

    .line 117
    :catchall_0
    move-exception p0

    .line 118
    goto/16 :goto_6

    .line 119
    .line 120
    :cond_4
    :try_start_1
    iget-object v5, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 121
    .line 122
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 123
    .line 124
    .line 125
    move-result v5

    .line 126
    move v6, v1

    .line 127
    move v7, v6

    .line 128
    :goto_2
    if-ge v6, v5, :cond_5

    .line 129
    .line 130
    iget-object v8, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 131
    .line 132
    invoke-virtual {v8, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v8

    .line 136
    check-cast v8, Landroidx/fragment/app/g1;

    .line 137
    .line 138
    invoke-interface {v8, v2, v3}, Landroidx/fragment/app/g1;->a(Ljava/util/ArrayList;Ljava/util/ArrayList;)Z

    .line 139
    .line 140
    .line 141
    move-result v8
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 142
    or-int/2addr v7, v8

    .line 143
    add-int/lit8 v6, v6, 0x1

    .line 144
    .line 145
    goto :goto_2

    .line 146
    :catchall_1
    move-exception p1

    .line 147
    goto :goto_5

    .line 148
    :cond_5
    :try_start_2
    iget-object v2, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 149
    .line 150
    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    .line 151
    .line 152
    .line 153
    iget-object v2, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 154
    .line 155
    iget-object v2, v2, Landroidx/fragment/app/t0;->f:Landroid/os/Handler;

    .line 156
    .line 157
    iget-object v3, p0, Landroidx/fragment/app/j1;->P:Landroidx/fragment/app/s;

    .line 158
    .line 159
    invoke-virtual {v2, v3}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 160
    .line 161
    .line 162
    monitor-exit v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 163
    :goto_3
    const/4 v2, 0x1

    .line 164
    if-eqz v7, :cond_6

    .line 165
    .line 166
    iput-boolean v2, p0, Landroidx/fragment/app/j1;->b:Z

    .line 167
    .line 168
    :try_start_3
    iget-object p1, p0, Landroidx/fragment/app/j1;->L:Ljava/util/ArrayList;

    .line 169
    .line 170
    iget-object v3, p0, Landroidx/fragment/app/j1;->M:Ljava/util/ArrayList;

    .line 171
    .line 172
    invoke-virtual {p0, p1, v3}, Landroidx/fragment/app/j1;->W(Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 173
    .line 174
    .line 175
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->d()V

    .line 176
    .line 177
    .line 178
    move p1, v2

    .line 179
    goto :goto_1

    .line 180
    :catchall_2
    move-exception p1

    .line 181
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->d()V

    .line 182
    .line 183
    .line 184
    throw p1

    .line 185
    :cond_6
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->g0()V

    .line 186
    .line 187
    .line 188
    iget-boolean v3, p0, Landroidx/fragment/app/j1;->K:Z

    .line 189
    .line 190
    if-eqz v3, :cond_9

    .line 191
    .line 192
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->K:Z

    .line 193
    .line 194
    iget-object v3, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 195
    .line 196
    invoke-virtual {v3}, Landroidx/fragment/app/s1;->d()Ljava/util/ArrayList;

    .line 197
    .line 198
    .line 199
    move-result-object v3

    .line 200
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 201
    .line 202
    .line 203
    move-result-object v3

    .line 204
    :cond_7
    :goto_4
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 205
    .line 206
    .line 207
    move-result v4

    .line 208
    if-eqz v4, :cond_9

    .line 209
    .line 210
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    check-cast v4, Landroidx/fragment/app/r1;

    .line 215
    .line 216
    iget-object v5, v4, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 217
    .line 218
    iget-boolean v6, v5, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 219
    .line 220
    if-eqz v6, :cond_7

    .line 221
    .line 222
    iget-boolean v6, p0, Landroidx/fragment/app/j1;->b:Z

    .line 223
    .line 224
    if-eqz v6, :cond_8

    .line 225
    .line 226
    iput-boolean v2, p0, Landroidx/fragment/app/j1;->K:Z

    .line 227
    .line 228
    goto :goto_4

    .line 229
    :cond_8
    iput-boolean v1, v5, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 230
    .line 231
    invoke-virtual {v4}, Landroidx/fragment/app/r1;->k()V

    .line 232
    .line 233
    .line 234
    goto :goto_4

    .line 235
    :cond_9
    iget-object p0, p0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 236
    .line 237
    iget-object p0, p0, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 238
    .line 239
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 240
    .line 241
    .line 242
    move-result-object p0

    .line 243
    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    invoke-interface {p0, v0}, Ljava/util/Collection;->removeAll(Ljava/util/Collection;)Z

    .line 248
    .line 249
    .line 250
    return p1

    .line 251
    :goto_5
    :try_start_4
    iget-object v0, p0, Landroidx/fragment/app/j1;->a:Ljava/util/ArrayList;

    .line 252
    .line 253
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 254
    .line 255
    .line 256
    iget-object v0, p0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 257
    .line 258
    iget-object v0, v0, Landroidx/fragment/app/t0;->f:Landroid/os/Handler;

    .line 259
    .line 260
    iget-object p0, p0, Landroidx/fragment/app/j1;->P:Landroidx/fragment/app/s;

    .line 261
    .line 262
    invoke-virtual {v0, p0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 263
    .line 264
    .line 265
    throw p1

    .line 266
    :goto_6
    monitor-exit v4
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 267
    throw p0
.end method
