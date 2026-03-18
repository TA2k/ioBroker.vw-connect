.class public abstract Lbb/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Cloneable;


# static fields
.field public static final D:[Landroid/animation/Animator;

.field public static final E:[I

.field public static final F:Lgv/a;

.field public static final G:Ljava/lang/ThreadLocal;


# instance fields
.field public A:J

.field public B:Lbb/u;

.field public C:J

.field public final d:Ljava/lang/String;

.field public e:J

.field public f:J

.field public g:Landroid/animation/TimeInterpolator;

.field public final h:Ljava/util/ArrayList;

.field public final i:Ljava/util/ArrayList;

.field public j:Lcom/google/firebase/messaging/w;

.field public k:Lcom/google/firebase/messaging/w;

.field public l:Lbb/d0;

.field public final m:[I

.field public n:Ljava/util/ArrayList;

.field public o:Ljava/util/ArrayList;

.field public p:[Lbb/v;

.field public final q:Ljava/util/ArrayList;

.field public r:[Landroid/animation/Animator;

.field public s:I

.field public t:Z

.field public u:Z

.field public v:Lbb/x;

.field public w:Ljava/util/ArrayList;

.field public x:Ljava/util/ArrayList;

.field public y:Ljp/na;

.field public z:Lgv/a;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Landroid/animation/Animator;

    .line 3
    .line 4
    sput-object v0, Lbb/x;->D:[Landroid/animation/Animator;

    .line 5
    .line 6
    const/4 v0, 0x3

    .line 7
    const/4 v1, 0x4

    .line 8
    const/4 v2, 0x2

    .line 9
    const/4 v3, 0x1

    .line 10
    filled-new-array {v2, v3, v0, v1}, [I

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lbb/x;->E:[I

    .line 15
    .line 16
    new-instance v0, Lgv/a;

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lbb/x;->F:Lgv/a;

    .line 23
    .line 24
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 25
    .line 26
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lbb/x;->G:Ljava/lang/ThreadLocal;

    .line 30
    .line 31
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lbb/x;->d:Ljava/lang/String;

    .line 13
    .line 14
    const-wide/16 v0, -0x1

    .line 15
    .line 16
    iput-wide v0, p0, Lbb/x;->e:J

    .line 17
    .line 18
    iput-wide v0, p0, Lbb/x;->f:J

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput-object v0, p0, Lbb/x;->g:Landroid/animation/TimeInterpolator;

    .line 22
    .line 23
    new-instance v1, Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v1, p0, Lbb/x;->h:Ljava/util/ArrayList;

    .line 29
    .line 30
    new-instance v1, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v1, p0, Lbb/x;->i:Ljava/util/ArrayList;

    .line 36
    .line 37
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 38
    .line 39
    const/4 v2, 0x4

    .line 40
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 41
    .line 42
    .line 43
    iput-object v1, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 44
    .line 45
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 46
    .line 47
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 48
    .line 49
    .line 50
    iput-object v1, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 51
    .line 52
    iput-object v0, p0, Lbb/x;->l:Lbb/d0;

    .line 53
    .line 54
    sget-object v1, Lbb/x;->E:[I

    .line 55
    .line 56
    iput-object v1, p0, Lbb/x;->m:[I

    .line 57
    .line 58
    new-instance v1, Ljava/util/ArrayList;

    .line 59
    .line 60
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 61
    .line 62
    .line 63
    iput-object v1, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 64
    .line 65
    sget-object v1, Lbb/x;->D:[Landroid/animation/Animator;

    .line 66
    .line 67
    iput-object v1, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 68
    .line 69
    const/4 v1, 0x0

    .line 70
    iput v1, p0, Lbb/x;->s:I

    .line 71
    .line 72
    iput-boolean v1, p0, Lbb/x;->t:Z

    .line 73
    .line 74
    iput-boolean v1, p0, Lbb/x;->u:Z

    .line 75
    .line 76
    iput-object v0, p0, Lbb/x;->v:Lbb/x;

    .line 77
    .line 78
    iput-object v0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 79
    .line 80
    new-instance v0, Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 83
    .line 84
    .line 85
    iput-object v0, p0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 86
    .line 87
    sget-object v0, Lbb/x;->F:Lgv/a;

    .line 88
    .line 89
    iput-object v0, p0, Lbb/x;->z:Lgv/a;

    .line 90
    .line 91
    return-void
.end method

.method public static c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/collection/f;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroidx/collection/f;

    .line 8
    .line 9
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Landroid/util/SparseArray;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Landroidx/collection/u;

    .line 16
    .line 17
    invoke-virtual {v0, p1, p2}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    const/4 v0, 0x0

    .line 25
    if-ltz p2, :cond_1

    .line 26
    .line 27
    invoke-virtual {v2, p2}, Landroid/util/SparseArray;->indexOfKey(I)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-ltz v3, :cond_0

    .line 32
    .line 33
    invoke-virtual {v2, p2, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-virtual {v2, p2, p1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    :goto_0
    sget-object p2, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 41
    .line 42
    invoke-static {p1}, Ld6/k0;->e(Landroid/view/View;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    if-eqz p2, :cond_3

    .line 47
    .line 48
    invoke-virtual {v1, p2}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    invoke-virtual {v1, p2, v0}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    invoke-virtual {v1, p2, p1}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    :cond_3
    :goto_1
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    instance-of p2, p2, Landroid/widget/ListView;

    .line 66
    .line 67
    if-eqz p2, :cond_5

    .line 68
    .line 69
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    check-cast p2, Landroid/widget/ListView;

    .line 74
    .line 75
    invoke-virtual {p2}, Landroid/widget/ListView;->getAdapter()Landroid/widget/ListAdapter;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-interface {v1}, Landroid/widget/Adapter;->hasStableIds()Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-eqz v1, :cond_5

    .line 84
    .line 85
    invoke-virtual {p2, p1}, Landroid/widget/AdapterView;->getPositionForView(Landroid/view/View;)I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    invoke-virtual {p2, v1}, Landroid/widget/AdapterView;->getItemIdAtPosition(I)J

    .line 90
    .line 91
    .line 92
    move-result-wide v1

    .line 93
    invoke-virtual {p0, v1, v2}, Landroidx/collection/u;->c(J)I

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    if-ltz p2, :cond_4

    .line 98
    .line 99
    invoke-virtual {p0, v1, v2}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    check-cast p1, Landroid/view/View;

    .line 104
    .line 105
    if-eqz p1, :cond_5

    .line 106
    .line 107
    const/4 p2, 0x0

    .line 108
    invoke-virtual {p1, p2}, Landroid/view/View;->setHasTransientState(Z)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, v1, v2, v0}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    return-void

    .line 115
    :cond_4
    const/4 p2, 0x1

    .line 116
    invoke-virtual {p1, p2}, Landroid/view/View;->setHasTransientState(Z)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p0, v1, v2, p1}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_5
    return-void
.end method

.method public static q()Landroidx/collection/f;
    .locals 3

    .line 1
    sget-object v0, Lbb/x;->G:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Landroidx/collection/f;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    new-instance v1, Landroidx/collection/f;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-direct {v1, v2}, Landroidx/collection/a1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-object v1
.end method

.method public static x(Lbb/f0;Lbb/f0;Ljava/lang/String;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lbb/f0;->a:Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p1, p1, Lbb/f0;->a:Ljava/util/HashMap;

    .line 8
    .line 9
    invoke-virtual {p1, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p2, 0x1

    .line 20
    if-eqz p0, :cond_2

    .line 21
    .line 22
    if-nez p1, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    xor-int/2addr p0, p2

    .line 30
    return p0

    .line 31
    :cond_2
    :goto_0
    return p2
.end method


# virtual methods
.method public A()V
    .locals 10

    .line 1
    invoke-static {}, Lbb/x;->q()Landroidx/collection/f;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    iput-wide v1, p0, Lbb/x;->A:J

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    :goto_0
    iget-object v4, p0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    if-ge v3, v4, :cond_4

    .line 17
    .line 18
    iget-object v4, p0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Landroid/animation/Animator;

    .line 25
    .line 26
    invoke-virtual {v0, v4}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    check-cast v5, Lbb/r;

    .line 31
    .line 32
    if-eqz v4, :cond_3

    .line 33
    .line 34
    if-eqz v5, :cond_3

    .line 35
    .line 36
    iget-object v5, v5, Lbb/r;->f:Landroid/animation/Animator;

    .line 37
    .line 38
    iget-wide v6, p0, Lbb/x;->f:J

    .line 39
    .line 40
    cmp-long v8, v6, v1

    .line 41
    .line 42
    if-ltz v8, :cond_0

    .line 43
    .line 44
    invoke-virtual {v5, v6, v7}, Landroid/animation/Animator;->setDuration(J)Landroid/animation/Animator;

    .line 45
    .line 46
    .line 47
    :cond_0
    iget-wide v6, p0, Lbb/x;->e:J

    .line 48
    .line 49
    cmp-long v8, v6, v1

    .line 50
    .line 51
    if-ltz v8, :cond_1

    .line 52
    .line 53
    invoke-virtual {v5}, Landroid/animation/Animator;->getStartDelay()J

    .line 54
    .line 55
    .line 56
    move-result-wide v8

    .line 57
    add-long/2addr v8, v6

    .line 58
    invoke-virtual {v5, v8, v9}, Landroid/animation/Animator;->setStartDelay(J)V

    .line 59
    .line 60
    .line 61
    :cond_1
    iget-object v6, p0, Lbb/x;->g:Landroid/animation/TimeInterpolator;

    .line 62
    .line 63
    if-eqz v6, :cond_2

    .line 64
    .line 65
    invoke-virtual {v5, v6}, Landroid/animation/Animator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 66
    .line 67
    .line 68
    :cond_2
    iget-object v5, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    iget-wide v5, p0, Lbb/x;->A:J

    .line 74
    .line 75
    invoke-static {v4}, Lbb/s;->a(Landroid/animation/Animator;)J

    .line 76
    .line 77
    .line 78
    move-result-wide v7

    .line 79
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 80
    .line 81
    .line 82
    move-result-wide v4

    .line 83
    iput-wide v4, p0, Lbb/x;->A:J

    .line 84
    .line 85
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_4
    iget-object p0, p0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 89
    .line 90
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 91
    .line 92
    .line 93
    return-void
.end method

.method public B(Lbb/v;)Lbb/x;
    .locals 1

    .line 1
    iget-object v0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Lbb/x;->v:Lbb/x;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lbb/x;->B(Lbb/v;)Lbb/x;

    .line 17
    .line 18
    .line 19
    :cond_1
    iget-object p1, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 20
    .line 21
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-nez p1, :cond_2

    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    iput-object p1, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 29
    .line 30
    :cond_2
    :goto_0
    return-object p0
.end method

.method public C(Landroid/view/View;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lbb/x;->i:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public D(Landroid/view/View;)V
    .locals 4

    .line 1
    iget-boolean p1, p0, Lbb/x;->t:Z

    .line 2
    .line 3
    if-eqz p1, :cond_2

    .line 4
    .line 5
    iget-boolean p1, p0, Lbb/x;->u:Z

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    if-nez p1, :cond_1

    .line 9
    .line 10
    iget-object p1, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    iget-object v2, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 17
    .line 18
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    check-cast p1, [Landroid/animation/Animator;

    .line 23
    .line 24
    sget-object v2, Lbb/x;->D:[Landroid/animation/Animator;

    .line 25
    .line 26
    iput-object v2, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 27
    .line 28
    add-int/lit8 v1, v1, -0x1

    .line 29
    .line 30
    :goto_0
    if-ltz v1, :cond_0

    .line 31
    .line 32
    aget-object v2, p1, v1

    .line 33
    .line 34
    const/4 v3, 0x0

    .line 35
    aput-object v3, p1, v1

    .line 36
    .line 37
    invoke-virtual {v2}, Landroid/animation/Animator;->resume()V

    .line 38
    .line 39
    .line 40
    add-int/lit8 v1, v1, -0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    iput-object p1, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 44
    .line 45
    sget-object p1, Lbb/w;->l0:Lb8/b;

    .line 46
    .line 47
    invoke-virtual {p0, p0, p1, v0}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 48
    .line 49
    .line 50
    :cond_1
    iput-boolean v0, p0, Lbb/x;->t:Z

    .line 51
    .line 52
    :cond_2
    return-void
.end method

.method public E()V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lbb/x;->M()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lbb/x;->q()Landroidx/collection/f;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iget-object v1, p0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_4

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Landroid/animation/Animator;

    .line 25
    .line 26
    invoke-virtual {v0, v2}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0}, Lbb/x;->M()V

    .line 33
    .line 34
    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    new-instance v3, Lbb/p;

    .line 38
    .line 39
    invoke-direct {v3, p0, v0}, Lbb/p;-><init>(Lbb/x;Landroidx/collection/f;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2, v3}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 43
    .line 44
    .line 45
    iget-wide v3, p0, Lbb/x;->f:J

    .line 46
    .line 47
    const-wide/16 v5, 0x0

    .line 48
    .line 49
    cmp-long v7, v3, v5

    .line 50
    .line 51
    if-ltz v7, :cond_1

    .line 52
    .line 53
    invoke-virtual {v2, v3, v4}, Landroid/animation/Animator;->setDuration(J)Landroid/animation/Animator;

    .line 54
    .line 55
    .line 56
    :cond_1
    iget-wide v3, p0, Lbb/x;->e:J

    .line 57
    .line 58
    cmp-long v5, v3, v5

    .line 59
    .line 60
    if-ltz v5, :cond_2

    .line 61
    .line 62
    invoke-virtual {v2}, Landroid/animation/Animator;->getStartDelay()J

    .line 63
    .line 64
    .line 65
    move-result-wide v5

    .line 66
    add-long/2addr v5, v3

    .line 67
    invoke-virtual {v2, v5, v6}, Landroid/animation/Animator;->setStartDelay(J)V

    .line 68
    .line 69
    .line 70
    :cond_2
    iget-object v3, p0, Lbb/x;->g:Landroid/animation/TimeInterpolator;

    .line 71
    .line 72
    if-eqz v3, :cond_3

    .line 73
    .line 74
    invoke-virtual {v2, v3}, Landroid/animation/Animator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 75
    .line 76
    .line 77
    :cond_3
    new-instance v3, Lbb/q;

    .line 78
    .line 79
    const/4 v4, 0x0

    .line 80
    invoke-direct {v3, p0, v4}, Lbb/q;-><init>(Ljava/lang/Object;I)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v2, v3}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2}, Landroid/animation/Animator;->start()V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_4
    iget-object v0, p0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p0}, Lbb/x;->n()V

    .line 96
    .line 97
    .line 98
    return-void
.end method

.method public F(JJ)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    iget-wide v3, v0, Lbb/x;->A:J

    .line 6
    .line 7
    cmp-long v5, v1, p3

    .line 8
    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v7, 0x1

    .line 11
    if-gez v5, :cond_0

    .line 12
    .line 13
    move v5, v7

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v5, v6

    .line 16
    :goto_0
    const-wide/16 v8, 0x0

    .line 17
    .line 18
    cmp-long v10, p3, v8

    .line 19
    .line 20
    if-gez v10, :cond_1

    .line 21
    .line 22
    cmp-long v11, v1, v8

    .line 23
    .line 24
    if-gez v11, :cond_2

    .line 25
    .line 26
    :cond_1
    cmp-long v11, p3, v3

    .line 27
    .line 28
    if-lez v11, :cond_3

    .line 29
    .line 30
    cmp-long v11, v1, v3

    .line 31
    .line 32
    if-gtz v11, :cond_3

    .line 33
    .line 34
    :cond_2
    iput-boolean v6, v0, Lbb/x;->u:Z

    .line 35
    .line 36
    sget-object v11, Lbb/w;->h0:Lb8/b;

    .line 37
    .line 38
    invoke-virtual {v0, v0, v11, v5}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 39
    .line 40
    .line 41
    :cond_3
    iget-object v11, v0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 44
    .line 45
    .line 46
    move-result v12

    .line 47
    iget-object v13, v0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 48
    .line 49
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v11

    .line 53
    check-cast v11, [Landroid/animation/Animator;

    .line 54
    .line 55
    sget-object v13, Lbb/x;->D:[Landroid/animation/Animator;

    .line 56
    .line 57
    iput-object v13, v0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 58
    .line 59
    :goto_1
    if-ge v6, v12, :cond_4

    .line 60
    .line 61
    aget-object v13, v11, v6

    .line 62
    .line 63
    const/4 v14, 0x0

    .line 64
    aput-object v14, v11, v6

    .line 65
    .line 66
    invoke-static {v13}, Lbb/s;->a(Landroid/animation/Animator;)J

    .line 67
    .line 68
    .line 69
    move-result-wide v14

    .line 70
    move-wide/from16 v16, v3

    .line 71
    .line 72
    invoke-static {v8, v9, v1, v2}, Ljava/lang/Math;->max(JJ)J

    .line 73
    .line 74
    .line 75
    move-result-wide v3

    .line 76
    invoke-static {v3, v4, v14, v15}, Ljava/lang/Math;->min(JJ)J

    .line 77
    .line 78
    .line 79
    move-result-wide v3

    .line 80
    invoke-static {v13, v3, v4}, Lbb/s;->b(Landroid/animation/Animator;J)V

    .line 81
    .line 82
    .line 83
    add-int/lit8 v6, v6, 0x1

    .line 84
    .line 85
    move-wide/from16 v3, v16

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_4
    move-wide/from16 v16, v3

    .line 89
    .line 90
    iput-object v11, v0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 91
    .line 92
    cmp-long v3, v1, v16

    .line 93
    .line 94
    if-lez v3, :cond_5

    .line 95
    .line 96
    cmp-long v4, p3, v16

    .line 97
    .line 98
    if-lez v4, :cond_6

    .line 99
    .line 100
    :cond_5
    cmp-long v1, v1, v8

    .line 101
    .line 102
    if-gez v1, :cond_8

    .line 103
    .line 104
    if-ltz v10, :cond_8

    .line 105
    .line 106
    :cond_6
    if-lez v3, :cond_7

    .line 107
    .line 108
    iput-boolean v7, v0, Lbb/x;->u:Z

    .line 109
    .line 110
    :cond_7
    sget-object v1, Lbb/w;->i0:Lb8/b;

    .line 111
    .line 112
    invoke-virtual {v0, v0, v1, v5}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 113
    .line 114
    .line 115
    :cond_8
    return-void
.end method

.method public G(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lbb/x;->f:J

    .line 2
    .line 3
    return-void
.end method

.method public H(Ljp/na;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lbb/x;->y:Ljp/na;

    .line 2
    .line 3
    return-void
.end method

.method public I(Landroid/animation/TimeInterpolator;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lbb/x;->g:Landroid/animation/TimeInterpolator;

    .line 2
    .line 3
    return-void
.end method

.method public J(Lgv/a;)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p1, Lbb/x;->F:Lgv/a;

    .line 4
    .line 5
    iput-object p1, p0, Lbb/x;->z:Lgv/a;

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iput-object p1, p0, Lbb/x;->z:Lgv/a;

    .line 9
    .line 10
    return-void
.end method

.method public K()V
    .locals 0

    .line 1
    return-void
.end method

.method public L(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lbb/x;->e:J

    .line 2
    .line 3
    return-void
.end method

.method public final M()V
    .locals 2

    .line 1
    iget v0, p0, Lbb/x;->s:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lbb/w;->h0:Lb8/b;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-virtual {p0, p0, v0, v1}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 9
    .line 10
    .line 11
    iput-boolean v1, p0, Lbb/x;->u:Z

    .line 12
    .line 13
    :cond_0
    iget v0, p0, Lbb/x;->s:I

    .line 14
    .line 15
    add-int/lit8 v0, v0, 0x1

    .line 16
    .line 17
    iput v0, p0, Lbb/x;->s:I

    .line 18
    .line 19
    return-void
.end method

.method public N(Ljava/lang/String;)Ljava/lang/String;
    .locals 7

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p1, "@"

    .line 18
    .line 19
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    invoke-static {p1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p1, ": "

    .line 34
    .line 35
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lbb/x;->f:J

    .line 39
    .line 40
    const-wide/16 v3, -0x1

    .line 41
    .line 42
    cmp-long p1, v1, v3

    .line 43
    .line 44
    const-string v1, ") "

    .line 45
    .line 46
    if-eqz p1, :cond_0

    .line 47
    .line 48
    const-string p1, "dur("

    .line 49
    .line 50
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    iget-wide v5, p0, Lbb/x;->f:J

    .line 54
    .line 55
    invoke-virtual {v0, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    :cond_0
    iget-wide v5, p0, Lbb/x;->e:J

    .line 62
    .line 63
    cmp-long p1, v5, v3

    .line 64
    .line 65
    if-eqz p1, :cond_1

    .line 66
    .line 67
    const-string p1, "dly("

    .line 68
    .line 69
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    iget-wide v2, p0, Lbb/x;->e:J

    .line 73
    .line 74
    invoke-virtual {v0, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    :cond_1
    iget-object p1, p0, Lbb/x;->g:Landroid/animation/TimeInterpolator;

    .line 81
    .line 82
    if-eqz p1, :cond_2

    .line 83
    .line 84
    const-string p1, "interp("

    .line 85
    .line 86
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object p1, p0, Lbb/x;->g:Landroid/animation/TimeInterpolator;

    .line 90
    .line 91
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    :cond_2
    iget-object p1, p0, Lbb/x;->h:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    iget-object p0, p0, Lbb/x;->i:Ljava/util/ArrayList;

    .line 104
    .line 105
    if-gtz v1, :cond_3

    .line 106
    .line 107
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-lez v1, :cond_8

    .line 112
    .line 113
    :cond_3
    const-string v1, "tgts("

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    const-string v2, ", "

    .line 123
    .line 124
    const/4 v3, 0x0

    .line 125
    if-lez v1, :cond_5

    .line 126
    .line 127
    move v1, v3

    .line 128
    :goto_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    if-ge v1, v4, :cond_5

    .line 133
    .line 134
    if-lez v1, :cond_4

    .line 135
    .line 136
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    :cond_4
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    add-int/lit8 v1, v1, 0x1

    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_5
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-lez p1, :cond_7

    .line 154
    .line 155
    :goto_1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 156
    .line 157
    .line 158
    move-result p1

    .line 159
    if-ge v3, p1, :cond_7

    .line 160
    .line 161
    if-lez v3, :cond_6

    .line 162
    .line 163
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    :cond_6
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    add-int/lit8 v3, v3, 0x1

    .line 174
    .line 175
    goto :goto_1

    .line 176
    :cond_7
    const-string p0, ")"

    .line 177
    .line 178
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    :cond_8
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    return-object p0
.end method

.method public a(Lbb/v;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public b(Landroid/view/View;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lbb/x;->i:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public cancel()V
    .locals 4

    .line 1
    iget-object v0, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget-object v2, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, [Landroid/animation/Animator;

    .line 14
    .line 15
    sget-object v2, Lbb/x;->D:[Landroid/animation/Animator;

    .line 16
    .line 17
    iput-object v2, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 18
    .line 19
    add-int/lit8 v1, v1, -0x1

    .line 20
    .line 21
    :goto_0
    if-ltz v1, :cond_0

    .line 22
    .line 23
    aget-object v2, v0, v1

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    aput-object v3, v0, v1

    .line 27
    .line 28
    invoke-virtual {v2}, Landroid/animation/Animator;->cancel()V

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, -0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    iput-object v0, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 35
    .line 36
    sget-object v0, Lbb/w;->j0:Lb8/b;

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    invoke-virtual {p0, p0, v0, v1}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lbb/x;->k()Lbb/x;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public abstract d(Lbb/f0;)V
.end method

.method public final e(Landroid/view/View;Z)V
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_3

    .line 4
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 5
    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    instance-of v0, v0, Landroid/view/ViewGroup;

    .line 12
    .line 13
    if-eqz v0, :cond_3

    .line 14
    .line 15
    new-instance v0, Lbb/f0;

    .line 16
    .line 17
    invoke-direct {v0, p1}, Lbb/f0;-><init>(Landroid/view/View;)V

    .line 18
    .line 19
    .line 20
    if-eqz p2, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lbb/x;->h(Lbb/f0;)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {p0, v0}, Lbb/x;->d(Lbb/f0;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v0, Lbb/f0;->c:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v0}, Lbb/x;->f(Lbb/f0;)V

    .line 35
    .line 36
    .line 37
    if-eqz p2, :cond_2

    .line 38
    .line 39
    iget-object v1, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 40
    .line 41
    invoke-static {v1, p1, v0}, Lbb/x;->c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    iget-object v1, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 46
    .line 47
    invoke-static {v1, p1, v0}, Lbb/x;->c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V

    .line 48
    .line 49
    .line 50
    :cond_3
    :goto_1
    instance-of v0, p1, Landroid/view/ViewGroup;

    .line 51
    .line 52
    if-eqz v0, :cond_4

    .line 53
    .line 54
    check-cast p1, Landroid/view/ViewGroup;

    .line 55
    .line 56
    const/4 v0, 0x0

    .line 57
    :goto_2
    invoke-virtual {p1}, Landroid/view/ViewGroup;->getChildCount()I

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-ge v0, v1, :cond_4

    .line 62
    .line 63
    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {p0, v1, p2}, Lbb/x;->e(Landroid/view/View;Z)V

    .line 68
    .line 69
    .line 70
    add-int/lit8 v0, v0, 0x1

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_3
    return-void
.end method

.method public f(Lbb/f0;)V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract h(Lbb/f0;)V
.end method

.method public final i(Landroid/view/ViewGroup;Z)V
    .locals 7

    .line 1
    invoke-virtual {p0, p2}, Lbb/x;->j(Z)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lbb/x;->h:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    iget-object v2, p0, Lbb/x;->i:Ljava/util/ArrayList;

    .line 11
    .line 12
    if-gtz v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-lez v1, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p0, p1, p2}, Lbb/x;->e(Landroid/view/View;Z)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 26
    move v3, v1

    .line 27
    :goto_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-ge v3, v4, :cond_5

    .line 32
    .line 33
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    check-cast v4, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    invoke-virtual {p1, v4}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    if-eqz v4, :cond_4

    .line 48
    .line 49
    new-instance v5, Lbb/f0;

    .line 50
    .line 51
    invoke-direct {v5, v4}, Lbb/f0;-><init>(Landroid/view/View;)V

    .line 52
    .line 53
    .line 54
    if-eqz p2, :cond_2

    .line 55
    .line 56
    invoke-virtual {p0, v5}, Lbb/x;->h(Lbb/f0;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    invoke-virtual {p0, v5}, Lbb/x;->d(Lbb/f0;)V

    .line 61
    .line 62
    .line 63
    :goto_2
    iget-object v6, v5, Lbb/f0;->c:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {v6, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    invoke-virtual {p0, v5}, Lbb/x;->f(Lbb/f0;)V

    .line 69
    .line 70
    .line 71
    if-eqz p2, :cond_3

    .line 72
    .line 73
    iget-object v6, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 74
    .line 75
    invoke-static {v6, v4, v5}, Lbb/x;->c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V

    .line 76
    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_3
    iget-object v6, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 80
    .line 81
    invoke-static {v6, v4, v5}, Lbb/x;->c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V

    .line 82
    .line 83
    .line 84
    :cond_4
    :goto_3
    add-int/lit8 v3, v3, 0x1

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_5
    :goto_4
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    if-ge v1, p1, :cond_8

    .line 92
    .line 93
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    check-cast p1, Landroid/view/View;

    .line 98
    .line 99
    new-instance v0, Lbb/f0;

    .line 100
    .line 101
    invoke-direct {v0, p1}, Lbb/f0;-><init>(Landroid/view/View;)V

    .line 102
    .line 103
    .line 104
    if-eqz p2, :cond_6

    .line 105
    .line 106
    invoke-virtual {p0, v0}, Lbb/x;->h(Lbb/f0;)V

    .line 107
    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_6
    invoke-virtual {p0, v0}, Lbb/x;->d(Lbb/f0;)V

    .line 111
    .line 112
    .line 113
    :goto_5
    iget-object v3, v0, Lbb/f0;->c:Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-virtual {v3, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    invoke-virtual {p0, v0}, Lbb/x;->f(Lbb/f0;)V

    .line 119
    .line 120
    .line 121
    if-eqz p2, :cond_7

    .line 122
    .line 123
    iget-object v3, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 124
    .line 125
    invoke-static {v3, p1, v0}, Lbb/x;->c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V

    .line 126
    .line 127
    .line 128
    goto :goto_6

    .line 129
    :cond_7
    iget-object v3, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 130
    .line 131
    invoke-static {v3, p1, v0}, Lbb/x;->c(Lcom/google/firebase/messaging/w;Landroid/view/View;Lbb/f0;)V

    .line 132
    .line 133
    .line 134
    :goto_6
    add-int/lit8 v1, v1, 0x1

    .line 135
    .line 136
    goto :goto_4

    .line 137
    :cond_8
    return-void
.end method

.method public final j(Z)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p1, Landroidx/collection/f;

    .line 8
    .line 9
    invoke-virtual {p1}, Landroidx/collection/a1;->clear()V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 13
    .line 14
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Landroid/util/SparseArray;

    .line 17
    .line 18
    invoke-virtual {p1}, Landroid/util/SparseArray;->clear()V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 22
    .line 23
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Landroidx/collection/u;

    .line 26
    .line 27
    invoke-virtual {p0}, Landroidx/collection/u;->a()V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    iget-object p1, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 32
    .line 33
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Landroidx/collection/f;

    .line 36
    .line 37
    invoke-virtual {p1}, Landroidx/collection/a1;->clear()V

    .line 38
    .line 39
    .line 40
    iget-object p1, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 41
    .line 42
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p1, Landroid/util/SparseArray;

    .line 45
    .line 46
    invoke-virtual {p1}, Landroid/util/SparseArray;->clear()V

    .line 47
    .line 48
    .line 49
    iget-object p0, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 50
    .line 51
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, Landroidx/collection/u;

    .line 54
    .line 55
    invoke-virtual {p0}, Landroidx/collection/u;->a()V

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public k()Lbb/x;
    .locals 3

    .line 1
    :try_start_0
    invoke-super {p0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lbb/x;

    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, v0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 13
    .line 14
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 15
    .line 16
    const/4 v2, 0x4

    .line 17
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iput-object v1, v0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 21
    .line 22
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 23
    .line 24
    const/4 v2, 0x4

    .line 25
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 26
    .line 27
    .line 28
    iput-object v1, v0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 29
    .line 30
    const/4 v1, 0x0

    .line 31
    iput-object v1, v0, Lbb/x;->n:Ljava/util/ArrayList;

    .line 32
    .line 33
    iput-object v1, v0, Lbb/x;->o:Ljava/util/ArrayList;

    .line 34
    .line 35
    iput-object v1, v0, Lbb/x;->B:Lbb/u;

    .line 36
    .line 37
    iput-object p0, v0, Lbb/x;->v:Lbb/x;

    .line 38
    .line 39
    iput-object v1, v0, Lbb/x;->w:Ljava/util/ArrayList;
    :try_end_0
    .catch Ljava/lang/CloneNotSupportedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    return-object v0

    .line 42
    :catch_0
    move-exception p0

    .line 43
    new-instance v0, Ljava/lang/RuntimeException;

    .line 44
    .line 45
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 46
    .line 47
    .line 48
    throw v0
.end method

.method public l(Landroid/view/ViewGroup;Lbb/f0;Lbb/f0;)Landroid/animation/Animator;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public m(Landroid/view/ViewGroup;Lcom/google/firebase/messaging/w;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static {}, Lbb/x;->q()Landroidx/collection/f;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    new-instance v2, Landroid/util/SparseIntArray;

    .line 8
    .line 9
    invoke-direct {v2}, Landroid/util/SparseIntArray;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-virtual/range {p4 .. p4}, Ljava/util/ArrayList;->size()I

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    invoke-virtual {v0}, Lbb/x;->p()Lbb/x;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    iget-object v4, v4, Lbb/x;->B:Lbb/u;

    .line 21
    .line 22
    if-eqz v4, :cond_0

    .line 23
    .line 24
    const/4 v4, 0x1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v4, 0x0

    .line 27
    :goto_0
    const/4 v6, 0x0

    .line 28
    :goto_1
    if-ge v6, v3, :cond_e

    .line 29
    .line 30
    move-object/from16 v7, p4

    .line 31
    .line 32
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    check-cast v8, Lbb/f0;

    .line 37
    .line 38
    move-object/from16 v9, p5

    .line 39
    .line 40
    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    check-cast v10, Lbb/f0;

    .line 45
    .line 46
    if-eqz v8, :cond_1

    .line 47
    .line 48
    iget-object v12, v8, Lbb/f0;->c:Ljava/util/ArrayList;

    .line 49
    .line 50
    invoke-virtual {v12, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v12

    .line 54
    if-nez v12, :cond_1

    .line 55
    .line 56
    const/4 v8, 0x0

    .line 57
    :cond_1
    if-eqz v10, :cond_2

    .line 58
    .line 59
    iget-object v12, v10, Lbb/f0;->c:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v12, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v12

    .line 65
    if-nez v12, :cond_2

    .line 66
    .line 67
    const/4 v10, 0x0

    .line 68
    :cond_2
    if-nez v8, :cond_5

    .line 69
    .line 70
    if-nez v10, :cond_5

    .line 71
    .line 72
    :cond_3
    move-object/from16 v12, p1

    .line 73
    .line 74
    :cond_4
    move/from16 v16, v3

    .line 75
    .line 76
    move/from16 v17, v4

    .line 77
    .line 78
    goto/16 :goto_6

    .line 79
    .line 80
    :cond_5
    if-eqz v8, :cond_6

    .line 81
    .line 82
    if-eqz v10, :cond_6

    .line 83
    .line 84
    invoke-virtual {v0, v8, v10}, Lbb/x;->v(Lbb/f0;Lbb/f0;)Z

    .line 85
    .line 86
    .line 87
    move-result v12

    .line 88
    if-eqz v12, :cond_3

    .line 89
    .line 90
    :cond_6
    move-object/from16 v12, p1

    .line 91
    .line 92
    invoke-virtual {v0, v12, v8, v10}, Lbb/x;->l(Landroid/view/ViewGroup;Lbb/f0;Lbb/f0;)Landroid/animation/Animator;

    .line 93
    .line 94
    .line 95
    move-result-object v13

    .line 96
    if-eqz v13, :cond_4

    .line 97
    .line 98
    iget-object v14, v0, Lbb/x;->d:Ljava/lang/String;

    .line 99
    .line 100
    if-eqz v10, :cond_b

    .line 101
    .line 102
    iget-object v8, v10, Lbb/f0;->b:Landroid/view/View;

    .line 103
    .line 104
    invoke-virtual {v0}, Lbb/x;->r()[Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v10

    .line 108
    if-eqz v10, :cond_a

    .line 109
    .line 110
    array-length v15, v10

    .line 111
    if-lez v15, :cond_a

    .line 112
    .line 113
    new-instance v15, Lbb/f0;

    .line 114
    .line 115
    invoke-direct {v15, v8}, Lbb/f0;-><init>(Landroid/view/View;)V

    .line 116
    .line 117
    .line 118
    move-object/from16 v5, p3

    .line 119
    .line 120
    iget-object v11, v5, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v11, Landroidx/collection/f;

    .line 123
    .line 124
    invoke-virtual {v11, v8}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v11

    .line 128
    check-cast v11, Lbb/f0;

    .line 129
    .line 130
    move/from16 v16, v3

    .line 131
    .line 132
    move/from16 v17, v4

    .line 133
    .line 134
    if-eqz v11, :cond_7

    .line 135
    .line 136
    const/4 v3, 0x0

    .line 137
    :goto_2
    array-length v4, v10

    .line 138
    if-ge v3, v4, :cond_7

    .line 139
    .line 140
    aget-object v4, v10, v3

    .line 141
    .line 142
    move/from16 v18, v3

    .line 143
    .line 144
    iget-object v3, v11, Lbb/f0;->a:Ljava/util/HashMap;

    .line 145
    .line 146
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    iget-object v5, v15, Lbb/f0;->a:Ljava/util/HashMap;

    .line 151
    .line 152
    invoke-virtual {v5, v4, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    add-int/lit8 v3, v18, 0x1

    .line 156
    .line 157
    move-object/from16 v5, p3

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_7
    invoke-virtual {v1}, Landroidx/collection/a1;->size()I

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    const/4 v4, 0x0

    .line 165
    :goto_3
    if-ge v4, v3, :cond_9

    .line 166
    .line 167
    invoke-virtual {v1, v4}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    check-cast v5, Landroid/animation/Animator;

    .line 172
    .line 173
    invoke-virtual {v1, v5}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v5

    .line 177
    check-cast v5, Lbb/r;

    .line 178
    .line 179
    iget-object v10, v5, Lbb/r;->c:Lbb/f0;

    .line 180
    .line 181
    if-eqz v10, :cond_8

    .line 182
    .line 183
    iget-object v10, v5, Lbb/r;->a:Landroid/view/View;

    .line 184
    .line 185
    if-ne v10, v8, :cond_8

    .line 186
    .line 187
    iget-object v10, v5, Lbb/r;->b:Ljava/lang/String;

    .line 188
    .line 189
    invoke-virtual {v10, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v10

    .line 193
    if-eqz v10, :cond_8

    .line 194
    .line 195
    iget-object v5, v5, Lbb/r;->c:Lbb/f0;

    .line 196
    .line 197
    invoke-virtual {v5, v15}, Lbb/f0;->equals(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-eqz v5, :cond_8

    .line 202
    .line 203
    const/4 v11, 0x0

    .line 204
    goto :goto_4

    .line 205
    :cond_8
    add-int/lit8 v4, v4, 0x1

    .line 206
    .line 207
    goto :goto_3

    .line 208
    :cond_9
    move-object v11, v13

    .line 209
    goto :goto_4

    .line 210
    :cond_a
    move/from16 v16, v3

    .line 211
    .line 212
    move/from16 v17, v4

    .line 213
    .line 214
    move-object v11, v13

    .line 215
    const/4 v15, 0x0

    .line 216
    :goto_4
    move-object v13, v11

    .line 217
    move-object v11, v15

    .line 218
    goto :goto_5

    .line 219
    :cond_b
    move/from16 v16, v3

    .line 220
    .line 221
    move/from16 v17, v4

    .line 222
    .line 223
    iget-object v8, v8, Lbb/f0;->b:Landroid/view/View;

    .line 224
    .line 225
    const/4 v11, 0x0

    .line 226
    :goto_5
    if-eqz v13, :cond_d

    .line 227
    .line 228
    new-instance v3, Lbb/r;

    .line 229
    .line 230
    invoke-virtual {v12}, Landroid/view/View;->getWindowId()Landroid/view/WindowId;

    .line 231
    .line 232
    .line 233
    move-result-object v4

    .line 234
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 235
    .line 236
    .line 237
    iput-object v8, v3, Lbb/r;->a:Landroid/view/View;

    .line 238
    .line 239
    iput-object v14, v3, Lbb/r;->b:Ljava/lang/String;

    .line 240
    .line 241
    iput-object v11, v3, Lbb/r;->c:Lbb/f0;

    .line 242
    .line 243
    iput-object v4, v3, Lbb/r;->d:Landroid/view/WindowId;

    .line 244
    .line 245
    iput-object v0, v3, Lbb/r;->e:Lbb/x;

    .line 246
    .line 247
    iput-object v13, v3, Lbb/r;->f:Landroid/animation/Animator;

    .line 248
    .line 249
    if-eqz v17, :cond_c

    .line 250
    .line 251
    new-instance v4, Landroid/animation/AnimatorSet;

    .line 252
    .line 253
    invoke-direct {v4}, Landroid/animation/AnimatorSet;-><init>()V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v4, v13}, Landroid/animation/AnimatorSet;->play(Landroid/animation/Animator;)Landroid/animation/AnimatorSet$Builder;

    .line 257
    .line 258
    .line 259
    move-object v13, v4

    .line 260
    :cond_c
    invoke-virtual {v1, v13, v3}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    iget-object v3, v0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 264
    .line 265
    invoke-virtual {v3, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    :cond_d
    :goto_6
    add-int/lit8 v6, v6, 0x1

    .line 269
    .line 270
    move/from16 v3, v16

    .line 271
    .line 272
    move/from16 v4, v17

    .line 273
    .line 274
    goto/16 :goto_1

    .line 275
    .line 276
    :cond_e
    invoke-virtual {v2}, Landroid/util/SparseIntArray;->size()I

    .line 277
    .line 278
    .line 279
    move-result v3

    .line 280
    if-eqz v3, :cond_f

    .line 281
    .line 282
    const/4 v5, 0x0

    .line 283
    :goto_7
    invoke-virtual {v2}, Landroid/util/SparseIntArray;->size()I

    .line 284
    .line 285
    .line 286
    move-result v3

    .line 287
    if-ge v5, v3, :cond_f

    .line 288
    .line 289
    invoke-virtual {v2, v5}, Landroid/util/SparseIntArray;->keyAt(I)I

    .line 290
    .line 291
    .line 292
    move-result v3

    .line 293
    iget-object v4, v0, Lbb/x;->x:Ljava/util/ArrayList;

    .line 294
    .line 295
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v3

    .line 299
    check-cast v3, Landroid/animation/Animator;

    .line 300
    .line 301
    invoke-virtual {v1, v3}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    check-cast v3, Lbb/r;

    .line 306
    .line 307
    invoke-virtual {v2, v5}, Landroid/util/SparseIntArray;->valueAt(I)I

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    int-to-long v6, v4

    .line 312
    const-wide v8, 0x7fffffffffffffffL

    .line 313
    .line 314
    .line 315
    .line 316
    .line 317
    sub-long/2addr v6, v8

    .line 318
    iget-object v4, v3, Lbb/r;->f:Landroid/animation/Animator;

    .line 319
    .line 320
    invoke-virtual {v4}, Landroid/animation/Animator;->getStartDelay()J

    .line 321
    .line 322
    .line 323
    move-result-wide v8

    .line 324
    add-long/2addr v8, v6

    .line 325
    iget-object v3, v3, Lbb/r;->f:Landroid/animation/Animator;

    .line 326
    .line 327
    invoke-virtual {v3, v8, v9}, Landroid/animation/Animator;->setStartDelay(J)V

    .line 328
    .line 329
    .line 330
    add-int/lit8 v5, v5, 0x1

    .line 331
    .line 332
    goto :goto_7

    .line 333
    :cond_f
    return-void
.end method

.method public final n()V
    .locals 4

    .line 1
    iget v0, p0, Lbb/x;->s:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    sub-int/2addr v0, v1

    .line 5
    iput v0, p0, Lbb/x;->s:I

    .line 6
    .line 7
    if-nez v0, :cond_4

    .line 8
    .line 9
    sget-object v0, Lbb/w;->i0:Lb8/b;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {p0, p0, v0, v2}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 13
    .line 14
    .line 15
    move v0, v2

    .line 16
    :goto_0
    iget-object v3, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 17
    .line 18
    iget-object v3, v3, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Landroidx/collection/u;

    .line 21
    .line 22
    invoke-virtual {v3}, Landroidx/collection/u;->h()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ge v0, v3, :cond_1

    .line 27
    .line 28
    iget-object v3, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 29
    .line 30
    iget-object v3, v3, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v3, Landroidx/collection/u;

    .line 33
    .line 34
    invoke-virtual {v3, v0}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    check-cast v3, Landroid/view/View;

    .line 39
    .line 40
    if-eqz v3, :cond_0

    .line 41
    .line 42
    invoke-virtual {v3, v2}, Landroid/view/View;->setHasTransientState(Z)V

    .line 43
    .line 44
    .line 45
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    move v0, v2

    .line 49
    :goto_1
    iget-object v3, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 50
    .line 51
    iget-object v3, v3, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v3, Landroidx/collection/u;

    .line 54
    .line 55
    invoke-virtual {v3}, Landroidx/collection/u;->h()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-ge v0, v3, :cond_3

    .line 60
    .line 61
    iget-object v3, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 62
    .line 63
    iget-object v3, v3, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v3, Landroidx/collection/u;

    .line 66
    .line 67
    invoke-virtual {v3, v0}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    check-cast v3, Landroid/view/View;

    .line 72
    .line 73
    if-eqz v3, :cond_2

    .line 74
    .line 75
    invoke-virtual {v3, v2}, Landroid/view/View;->setHasTransientState(Z)V

    .line 76
    .line 77
    .line 78
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    iput-boolean v1, p0, Lbb/x;->u:Z

    .line 82
    .line 83
    :cond_4
    return-void
.end method

.method public final o(Landroid/view/View;Z)Lbb/f0;
    .locals 4

    .line 1
    iget-object v0, p0, Lbb/x;->l:Lbb/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Lbb/x;->o(Landroid/view/View;Z)Lbb/f0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    if-eqz p2, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Lbb/x;->n:Ljava/util/ArrayList;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    iget-object v0, p0, Lbb/x;->o:Ljava/util/ArrayList;

    .line 16
    .line 17
    :goto_0
    if-nez v0, :cond_2

    .line 18
    .line 19
    goto :goto_4

    .line 20
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    const/4 v2, 0x0

    .line 25
    :goto_1
    if-ge v2, v1, :cond_5

    .line 26
    .line 27
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    check-cast v3, Lbb/f0;

    .line 32
    .line 33
    if-nez v3, :cond_3

    .line 34
    .line 35
    goto :goto_4

    .line 36
    :cond_3
    iget-object v3, v3, Lbb/f0;->b:Landroid/view/View;

    .line 37
    .line 38
    if-ne v3, p1, :cond_4

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_4
    add-int/lit8 v2, v2, 0x1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_5
    const/4 v2, -0x1

    .line 45
    :goto_2
    if-ltz v2, :cond_7

    .line 46
    .line 47
    if-eqz p2, :cond_6

    .line 48
    .line 49
    iget-object p0, p0, Lbb/x;->o:Ljava/util/ArrayList;

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_6
    iget-object p0, p0, Lbb/x;->n:Ljava/util/ArrayList;

    .line 53
    .line 54
    :goto_3
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p0, Lbb/f0;

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_7
    :goto_4
    const/4 p0, 0x0

    .line 62
    return-object p0
.end method

.method public final p()Lbb/x;
    .locals 1

    .line 1
    iget-object v0, p0, Lbb/x;->l:Lbb/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lbb/x;->p()Lbb/x;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public r()[Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final s(Landroid/view/View;Z)Lbb/f0;
    .locals 1

    .line 1
    iget-object v0, p0, Lbb/x;->l:Lbb/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Lbb/x;->s(Landroid/view/View;Z)Lbb/f0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    if-eqz p2, :cond_1

    .line 11
    .line 12
    iget-object p0, p0, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    iget-object p0, p0, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 16
    .line 17
    :goto_0
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Landroidx/collection/f;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lbb/f0;

    .line 26
    .line 27
    return-object p0
.end method

.method public t()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    xor-int/lit8 p0, p0, 0x1

    .line 8
    .line 9
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lbb/x;->N(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public abstract u()Z
.end method

.method public v(Lbb/f0;Lbb/f0;)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_3

    .line 3
    .line 4
    if-eqz p2, :cond_3

    .line 5
    .line 6
    invoke-virtual {p0}, Lbb/x;->r()[Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    array-length v1, p0

    .line 13
    move v2, v0

    .line 14
    :goto_0
    if-ge v2, v1, :cond_3

    .line 15
    .line 16
    aget-object v3, p0, v2

    .line 17
    .line 18
    invoke-static {p1, p2, v3}, Lbb/x;->x(Lbb/f0;Lbb/f0;Ljava/lang/String;)Z

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    iget-object p0, p1, Lbb/f0;->a:Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_3

    .line 43
    .line 44
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {p1, p2, v1}, Lbb/x;->x(Lbb/f0;Lbb/f0;Ljava/lang/String;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    :goto_1
    const/4 p0, 0x1

    .line 57
    return p0

    .line 58
    :cond_3
    return v0
.end method

.method public final w(Landroid/view/View;)Z
    .locals 4

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getId()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lbb/x;->h:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x1

    .line 12
    iget-object p0, p0, Lbb/x;->i:Ljava/util/ArrayList;

    .line 13
    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    return v3

    .line 23
    :cond_0
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/4 p0, 0x0

    .line 41
    return p0

    .line 42
    :cond_2
    :goto_0
    return v3
.end method

.method public final y(Lbb/x;Lbb/w;Z)V
    .locals 5

    .line 1
    iget-object v0, p0, Lbb/x;->v:Lbb/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2, p3}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 9
    .line 10
    if-eqz v0, :cond_3

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_3

    .line 17
    .line 18
    iget-object v0, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object v1, p0, Lbb/x;->p:[Lbb/v;

    .line 25
    .line 26
    if-nez v1, :cond_1

    .line 27
    .line 28
    new-array v1, v0, [Lbb/v;

    .line 29
    .line 30
    :cond_1
    const/4 v2, 0x0

    .line 31
    iput-object v2, p0, Lbb/x;->p:[Lbb/v;

    .line 32
    .line 33
    iget-object v3, p0, Lbb/x;->w:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, [Lbb/v;

    .line 40
    .line 41
    const/4 v3, 0x0

    .line 42
    :goto_0
    if-ge v3, v0, :cond_2

    .line 43
    .line 44
    aget-object v4, v1, v3

    .line 45
    .line 46
    invoke-interface {p2, v4, p1, p3}, Lbb/w;->a(Lbb/v;Lbb/x;Z)V

    .line 47
    .line 48
    .line 49
    aput-object v2, v1, v3

    .line 50
    .line 51
    add-int/lit8 v3, v3, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    iput-object v1, p0, Lbb/x;->p:[Lbb/v;

    .line 55
    .line 56
    :cond_3
    return-void
.end method

.method public z(Landroid/view/View;)V
    .locals 4

    .line 1
    iget-boolean p1, p0, Lbb/x;->u:Z

    .line 2
    .line 3
    if-nez p1, :cond_1

    .line 4
    .line 5
    iget-object p1, p0, Lbb/x;->q:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget-object v1, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 12
    .line 13
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, [Landroid/animation/Animator;

    .line 18
    .line 19
    sget-object v1, Lbb/x;->D:[Landroid/animation/Animator;

    .line 20
    .line 21
    iput-object v1, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 22
    .line 23
    const/4 v1, 0x1

    .line 24
    sub-int/2addr v0, v1

    .line 25
    :goto_0
    if-ltz v0, :cond_0

    .line 26
    .line 27
    aget-object v2, p1, v0

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    aput-object v3, p1, v0

    .line 31
    .line 32
    invoke-virtual {v2}, Landroid/animation/Animator;->pause()V

    .line 33
    .line 34
    .line 35
    add-int/lit8 v0, v0, -0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    iput-object p1, p0, Lbb/x;->r:[Landroid/animation/Animator;

    .line 39
    .line 40
    sget-object p1, Lbb/w;->k0:Lb8/b;

    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    invoke-virtual {p0, p0, p1, v0}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 44
    .line 45
    .line 46
    iput-boolean v1, p0, Lbb/x;->t:Z

    .line 47
    .line 48
    :cond_1
    return-void
.end method
