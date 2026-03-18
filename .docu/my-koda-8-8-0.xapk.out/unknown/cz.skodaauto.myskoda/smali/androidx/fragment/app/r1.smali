.class public final Landroidx/fragment/app/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroidx/fragment/app/p0;

.field public final b:Landroidx/fragment/app/s1;

.field public final c:Landroidx/fragment/app/j0;

.field public d:Z

.field public e:I


# direct methods
.method public constructor <init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Landroidx/fragment/app/j0;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Landroidx/fragment/app/r1;->d:Z

    const/4 v0, -0x1

    .line 3
    iput v0, p0, Landroidx/fragment/app/r1;->e:I

    .line 4
    iput-object p1, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 5
    iput-object p2, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 6
    iput-object p3, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    return-void
.end method

.method public constructor <init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Landroidx/fragment/app/j0;Landroid/os/Bundle;)V
    .locals 2

    .line 40
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 41
    iput-boolean v0, p0, Landroidx/fragment/app/r1;->d:Z

    const/4 v1, -0x1

    .line 42
    iput v1, p0, Landroidx/fragment/app/r1;->e:I

    .line 43
    iput-object p1, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 44
    iput-object p2, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 45
    iput-object p3, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    const/4 p0, 0x0

    .line 46
    iput-object p0, p3, Landroidx/fragment/app/j0;->mSavedViewState:Landroid/util/SparseArray;

    .line 47
    iput-object p0, p3, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 48
    iput v0, p3, Landroidx/fragment/app/j0;->mBackStackNesting:I

    .line 49
    iput-boolean v0, p3, Landroidx/fragment/app/j0;->mInLayout:Z

    .line 50
    iput-boolean v0, p3, Landroidx/fragment/app/j0;->mAdded:Z

    .line 51
    iget-object p1, p3, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    if-eqz p1, :cond_0

    iget-object p1, p1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object p1, p0

    :goto_0
    iput-object p1, p3, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 52
    iput-object p0, p3, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 53
    iput-object p4, p3, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 54
    const-string p0, "arguments"

    invoke-virtual {p4, p0}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    move-result-object p0

    iput-object p0, p3, Landroidx/fragment/app/j0;->mArguments:Landroid/os/Bundle;

    return-void
.end method

.method public constructor <init>(Landroidx/fragment/app/p0;Landroidx/fragment/app/s1;Ljava/lang/ClassLoader;Landroidx/fragment/app/b1;Landroid/os/Bundle;)V
    .locals 1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 8
    iput-boolean v0, p0, Landroidx/fragment/app/r1;->d:Z

    const/4 v0, -0x1

    .line 9
    iput v0, p0, Landroidx/fragment/app/r1;->e:I

    .line 10
    iput-object p1, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 11
    iput-object p2, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 12
    const-string p1, "state"

    invoke-virtual {p5, p1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object p1

    check-cast p1, Landroidx/fragment/app/p1;

    .line 13
    iget-object p2, p1, Landroidx/fragment/app/p1;->d:Ljava/lang/String;

    .line 14
    iget-object p4, p4, Landroidx/fragment/app/b1;->a:Landroidx/fragment/app/j1;

    .line 15
    iget-object p4, p4, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 16
    iget-object p4, p4, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    const/4 v0, 0x0

    .line 17
    invoke-static {p4, p2, v0}, Landroidx/fragment/app/j0;->instantiate(Landroid/content/Context;Ljava/lang/String;Landroid/os/Bundle;)Landroidx/fragment/app/j0;

    move-result-object p2

    .line 18
    iget-object p4, p1, Landroidx/fragment/app/p1;->e:Ljava/lang/String;

    iput-object p4, p2, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 19
    iget-boolean p4, p1, Landroidx/fragment/app/p1;->f:Z

    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mFromLayout:Z

    .line 20
    iget-boolean p4, p1, Landroidx/fragment/app/p1;->g:Z

    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mInDynamicContainer:Z

    const/4 p4, 0x1

    .line 21
    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mRestored:Z

    .line 22
    iget p4, p1, Landroidx/fragment/app/p1;->h:I

    iput p4, p2, Landroidx/fragment/app/j0;->mFragmentId:I

    .line 23
    iget p4, p1, Landroidx/fragment/app/p1;->i:I

    iput p4, p2, Landroidx/fragment/app/j0;->mContainerId:I

    .line 24
    iget-object p4, p1, Landroidx/fragment/app/p1;->j:Ljava/lang/String;

    iput-object p4, p2, Landroidx/fragment/app/j0;->mTag:Ljava/lang/String;

    .line 25
    iget-boolean p4, p1, Landroidx/fragment/app/p1;->k:Z

    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mRetainInstance:Z

    .line 26
    iget-boolean p4, p1, Landroidx/fragment/app/p1;->l:Z

    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 27
    iget-boolean p4, p1, Landroidx/fragment/app/p1;->m:Z

    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mDetached:Z

    .line 28
    iget-boolean p4, p1, Landroidx/fragment/app/p1;->n:Z

    iput-boolean p4, p2, Landroidx/fragment/app/j0;->mHidden:Z

    .line 29
    invoke-static {}, Landroidx/lifecycle/q;->values()[Landroidx/lifecycle/q;

    move-result-object p4

    iget v0, p1, Landroidx/fragment/app/p1;->o:I

    aget-object p4, p4, v0

    iput-object p4, p2, Landroidx/fragment/app/j0;->mMaxState:Landroidx/lifecycle/q;

    .line 30
    iget-object p4, p1, Landroidx/fragment/app/p1;->p:Ljava/lang/String;

    iput-object p4, p2, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 31
    iget p4, p1, Landroidx/fragment/app/p1;->q:I

    iput p4, p2, Landroidx/fragment/app/j0;->mTargetRequestCode:I

    .line 32
    iget-boolean p1, p1, Landroidx/fragment/app/p1;->r:Z

    iput-boolean p1, p2, Landroidx/fragment/app/j0;->mUserVisibleHint:Z

    .line 33
    iput-object p2, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 34
    iput-object p5, p2, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 35
    const-string p0, "arguments"

    invoke-virtual {p5, p0}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 36
    invoke-virtual {p0, p3}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 37
    :cond_0
    invoke-virtual {p2, p0}, Landroidx/fragment/app/j0;->setArguments(Landroid/os/Bundle;)V

    const/4 p0, 0x2

    .line 38
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    move-result p0

    if-eqz p0, :cond_1

    .line 39
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p1, "Instantiated fragment "

    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string p1, "FragmentManager"

    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    :cond_1
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    iget-object v1, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "moveto ACTIVITY_CREATED: "

    .line 13
    .line 14
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v2, "FragmentManager"

    .line 25
    .line 26
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v0, v1, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const-string v2, "savedInstanceState"

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/4 v0, 0x0

    .line 41
    :goto_0
    invoke-virtual {v1, v0}, Landroidx/fragment/app/j0;->performActivityCreated(Landroid/os/Bundle;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-virtual {p0, v1, v0}, Landroidx/fragment/app/p0;->a(Landroidx/fragment/app/j0;Z)V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public final b()V
    .locals 7

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 4
    .line 5
    invoke-static {v1}, Landroidx/fragment/app/j1;->E(Landroid/view/View;)Landroidx/fragment/app/j0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragment()Landroidx/fragment/app/j0;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Landroidx/fragment/app/j0;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    iget v2, v0, Landroidx/fragment/app/j0;->mContainerId:I

    .line 22
    .line 23
    sget-object v3, Lx6/c;->a:Lx6/b;

    .line 24
    .line 25
    new-instance v3, Lx6/a;

    .line 26
    .line 27
    new-instance v4, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v5, "Attempting to nest fragment "

    .line 30
    .line 31
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v5, " within the view of parent fragment "

    .line 38
    .line 39
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, " via container with ID "

    .line 46
    .line 47
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, " without using parent\'s childFragmentManager"

    .line 51
    .line 52
    invoke-static {v2, v1, v4}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-direct {v3, v0, v1}, Lx6/g;-><init>(Landroidx/fragment/app/j0;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-static {v3}, Lx6/c;->b(Lx6/g;)V

    .line 60
    .line 61
    .line 62
    invoke-static {v0}, Lx6/c;->a(Landroidx/fragment/app/j0;)Lx6/b;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    :cond_0
    iget-object p0, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 70
    .line 71
    iget-object p0, p0, Landroidx/fragment/app/s1;->a:Ljava/util/ArrayList;

    .line 72
    .line 73
    iget-object v1, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 74
    .line 75
    const/4 v2, -0x1

    .line 76
    if-nez v1, :cond_1

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_1
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    add-int/lit8 v4, v3, -0x1

    .line 84
    .line 85
    :goto_0
    if-ltz v4, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    check-cast v5, Landroidx/fragment/app/j0;

    .line 92
    .line 93
    iget-object v6, v5, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 94
    .line 95
    if-ne v6, v1, :cond_2

    .line 96
    .line 97
    iget-object v5, v5, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 98
    .line 99
    if-eqz v5, :cond_2

    .line 100
    .line 101
    invoke-virtual {v1, v5}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    add-int/lit8 v2, p0, 0x1

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_2
    add-int/lit8 v4, v4, -0x1

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_3
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-ge v3, v4, :cond_5

    .line 118
    .line 119
    invoke-virtual {p0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    check-cast v4, Landroidx/fragment/app/j0;

    .line 124
    .line 125
    iget-object v5, v4, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 126
    .line 127
    if-ne v5, v1, :cond_4

    .line 128
    .line 129
    iget-object v4, v4, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 130
    .line 131
    if-eqz v4, :cond_4

    .line 132
    .line 133
    invoke-virtual {v1, v4}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    goto :goto_2

    .line 138
    :cond_4
    goto :goto_1

    .line 139
    :cond_5
    :goto_2
    iget-object p0, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 140
    .line 141
    iget-object v0, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 142
    .line 143
    invoke-virtual {p0, v0, v2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;I)V

    .line 144
    .line 145
    .line 146
    return-void
.end method

.method public final c()V
    .locals 7

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    iget-object v1, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "moveto ATTACHED: "

    .line 13
    .line 14
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v2, "FragmentManager"

    .line 25
    .line 26
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v0, v1, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    const-string v3, " that does not belong to this FragmentManager!"

    .line 33
    .line 34
    const-string v4, " declared target fragment "

    .line 35
    .line 36
    const-string v5, "Fragment "

    .line 37
    .line 38
    iget-object v6, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    iget-object v0, v0, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v6, v6, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 45
    .line 46
    invoke-virtual {v6, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Landroidx/fragment/app/r1;

    .line 51
    .line 52
    if-eqz v0, :cond_1

    .line 53
    .line 54
    iget-object v3, v1, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 55
    .line 56
    iget-object v3, v3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 57
    .line 58
    iput-object v3, v1, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 59
    .line 60
    iput-object v2, v1, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 61
    .line 62
    move-object v2, v0

    .line 63
    goto :goto_0

    .line 64
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 65
    .line 66
    new-instance v0, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    iget-object v1, v1, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_2
    iget-object v0, v1, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 94
    .line 95
    if-eqz v0, :cond_4

    .line 96
    .line 97
    iget-object v2, v6, Landroidx/fragment/app/s1;->b:Ljava/util/HashMap;

    .line 98
    .line 99
    invoke-virtual {v2, v0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    move-object v2, v0

    .line 104
    check-cast v2, Landroidx/fragment/app/r1;

    .line 105
    .line 106
    if-eqz v2, :cond_3

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    new-instance v0, Ljava/lang/StringBuilder;

    .line 112
    .line 113
    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    iget-object v1, v1, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 123
    .line 124
    invoke-static {v0, v1, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    throw p0

    .line 132
    :cond_4
    :goto_0
    if-eqz v2, :cond_5

    .line 133
    .line 134
    invoke-virtual {v2}, Landroidx/fragment/app/r1;->k()V

    .line 135
    .line 136
    .line 137
    :cond_5
    iget-object v0, v1, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 138
    .line 139
    iget-object v2, v0, Landroidx/fragment/app/j1;->w:Landroidx/fragment/app/t0;

    .line 140
    .line 141
    iput-object v2, v1, Landroidx/fragment/app/j0;->mHost:Landroidx/fragment/app/t0;

    .line 142
    .line 143
    iget-object v0, v0, Landroidx/fragment/app/j1;->y:Landroidx/fragment/app/j0;

    .line 144
    .line 145
    iput-object v0, v1, Landroidx/fragment/app/j0;->mParentFragment:Landroidx/fragment/app/j0;

    .line 146
    .line 147
    iget-object p0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 148
    .line 149
    const/4 v0, 0x0

    .line 150
    invoke-virtual {p0, v1, v0}, Landroidx/fragment/app/p0;->g(Landroidx/fragment/app/j0;Z)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->performAttach()V

    .line 154
    .line 155
    .line 156
    invoke-virtual {p0, v1, v0}, Landroidx/fragment/app/p0;->b(Landroidx/fragment/app/j0;Z)V

    .line 157
    .line 158
    .line 159
    return-void
.end method

.method public final d()I
    .locals 11

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget p0, v0, Landroidx/fragment/app/j0;->mState:I

    .line 8
    .line 9
    return p0

    .line 10
    :cond_0
    iget v1, p0, Landroidx/fragment/app/r1;->e:I

    .line 11
    .line 12
    iget-object v2, v0, Landroidx/fragment/app/j0;->mMaxState:Landroidx/lifecycle/q;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    const/4 v3, 0x0

    .line 19
    const/4 v4, 0x5

    .line 20
    const/4 v5, -0x1

    .line 21
    const/4 v6, 0x3

    .line 22
    const/4 v7, 0x4

    .line 23
    const/4 v8, 0x2

    .line 24
    const/4 v9, 0x1

    .line 25
    if-eq v2, v9, :cond_3

    .line 26
    .line 27
    if-eq v2, v8, :cond_2

    .line 28
    .line 29
    if-eq v2, v6, :cond_1

    .line 30
    .line 31
    if-eq v2, v7, :cond_4

    .line 32
    .line 33
    invoke-static {v1, v5}, Ljava/lang/Math;->min(II)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    invoke-static {v1, v4}, Ljava/lang/Math;->min(II)I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    goto :goto_0

    .line 43
    :cond_2
    invoke-static {v1, v9}, Ljava/lang/Math;->min(II)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    goto :goto_0

    .line 48
    :cond_3
    invoke-static {v1, v3}, Ljava/lang/Math;->min(II)I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    :cond_4
    :goto_0
    iget-boolean v2, v0, Landroidx/fragment/app/j0;->mFromLayout:Z

    .line 53
    .line 54
    if-eqz v2, :cond_7

    .line 55
    .line 56
    iget-boolean v2, v0, Landroidx/fragment/app/j0;->mInLayout:Z

    .line 57
    .line 58
    if-eqz v2, :cond_5

    .line 59
    .line 60
    iget p0, p0, Landroidx/fragment/app/r1;->e:I

    .line 61
    .line 62
    invoke-static {p0, v8}, Ljava/lang/Math;->max(II)I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    iget-object p0, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 67
    .line 68
    if-eqz p0, :cond_7

    .line 69
    .line 70
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    if-nez p0, :cond_7

    .line 75
    .line 76
    invoke-static {v1, v8}, Ljava/lang/Math;->min(II)I

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    goto :goto_1

    .line 81
    :cond_5
    iget p0, p0, Landroidx/fragment/app/r1;->e:I

    .line 82
    .line 83
    if-ge p0, v7, :cond_6

    .line 84
    .line 85
    iget p0, v0, Landroidx/fragment/app/j0;->mState:I

    .line 86
    .line 87
    invoke-static {v1, p0}, Ljava/lang/Math;->min(II)I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    goto :goto_1

    .line 92
    :cond_6
    invoke-static {v1, v9}, Ljava/lang/Math;->min(II)I

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    :cond_7
    :goto_1
    iget-boolean p0, v0, Landroidx/fragment/app/j0;->mInDynamicContainer:Z

    .line 97
    .line 98
    if-eqz p0, :cond_8

    .line 99
    .line 100
    iget-object p0, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 101
    .line 102
    if-nez p0, :cond_8

    .line 103
    .line 104
    invoke-static {v1, v7}, Ljava/lang/Math;->min(II)I

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    :cond_8
    iget-boolean p0, v0, Landroidx/fragment/app/j0;->mAdded:Z

    .line 109
    .line 110
    if-nez p0, :cond_9

    .line 111
    .line 112
    invoke-static {v1, v9}, Ljava/lang/Math;->min(II)I

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    :cond_9
    iget-object p0, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 117
    .line 118
    if-eqz p0, :cond_d

    .line 119
    .line 120
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    invoke-static {p0, v2}, Landroidx/fragment/app/r;->j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-virtual {p0, v0}, Landroidx/fragment/app/r;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/g2;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    if-eqz v2, :cond_a

    .line 133
    .line 134
    iget v2, v2, Landroidx/fragment/app/g2;->b:I

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_a
    move v2, v3

    .line 138
    :goto_2
    invoke-virtual {p0, v0}, Landroidx/fragment/app/r;->h(Landroidx/fragment/app/j0;)Landroidx/fragment/app/g2;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    if-eqz p0, :cond_b

    .line 143
    .line 144
    iget v3, p0, Landroidx/fragment/app/g2;->b:I

    .line 145
    .line 146
    :cond_b
    if-nez v2, :cond_c

    .line 147
    .line 148
    move p0, v5

    .line 149
    goto :goto_3

    .line 150
    :cond_c
    sget-object p0, Landroidx/fragment/app/h2;->a:[I

    .line 151
    .line 152
    invoke-static {v2}, Lu/w;->o(I)I

    .line 153
    .line 154
    .line 155
    move-result v10

    .line 156
    aget p0, p0, v10

    .line 157
    .line 158
    :goto_3
    if-eq p0, v5, :cond_d

    .line 159
    .line 160
    if-eq p0, v9, :cond_d

    .line 161
    .line 162
    move v3, v2

    .line 163
    :cond_d
    if-ne v3, v8, :cond_e

    .line 164
    .line 165
    const/4 p0, 0x6

    .line 166
    invoke-static {v1, p0}, Ljava/lang/Math;->min(II)I

    .line 167
    .line 168
    .line 169
    move-result v1

    .line 170
    goto :goto_4

    .line 171
    :cond_e
    if-ne v3, v6, :cond_f

    .line 172
    .line 173
    invoke-static {v1, v6}, Ljava/lang/Math;->max(II)I

    .line 174
    .line 175
    .line 176
    move-result v1

    .line 177
    goto :goto_4

    .line 178
    :cond_f
    iget-boolean p0, v0, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 179
    .line 180
    if-eqz p0, :cond_11

    .line 181
    .line 182
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->isInBackStack()Z

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    if-eqz p0, :cond_10

    .line 187
    .line 188
    invoke-static {v1, v9}, Ljava/lang/Math;->min(II)I

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    goto :goto_4

    .line 193
    :cond_10
    invoke-static {v1, v5}, Ljava/lang/Math;->min(II)I

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    :cond_11
    :goto_4
    iget-boolean p0, v0, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 198
    .line 199
    if-eqz p0, :cond_12

    .line 200
    .line 201
    iget p0, v0, Landroidx/fragment/app/j0;->mState:I

    .line 202
    .line 203
    if-ge p0, v4, :cond_12

    .line 204
    .line 205
    invoke-static {v1, v7}, Ljava/lang/Math;->min(II)I

    .line 206
    .line 207
    .line 208
    move-result v1

    .line 209
    :cond_12
    iget-boolean p0, v0, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 210
    .line 211
    if-eqz p0, :cond_13

    .line 212
    .line 213
    invoke-static {v1, v6}, Ljava/lang/Math;->max(II)I

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    :cond_13
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 218
    .line 219
    .line 220
    move-result p0

    .line 221
    if-eqz p0, :cond_14

    .line 222
    .line 223
    new-instance p0, Ljava/lang/StringBuilder;

    .line 224
    .line 225
    const-string v2, "computeExpectedState() of "

    .line 226
    .line 227
    invoke-direct {p0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 231
    .line 232
    .line 233
    const-string v2, " for "

    .line 234
    .line 235
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    const-string v0, "FragmentManager"

    .line 246
    .line 247
    invoke-static {v0, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 248
    .line 249
    .line 250
    :cond_14
    return v1
.end method

.method public final e()V
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    iget-object v1, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "moveto CREATED: "

    .line 13
    .line 14
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v2, "FragmentManager"

    .line 25
    .line 26
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v0, v1, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const-string v2, "savedInstanceState"

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/4 v0, 0x0

    .line 41
    :goto_0
    iget-boolean v2, v1, Landroidx/fragment/app/j0;->mIsCreated:Z

    .line 42
    .line 43
    if-nez v2, :cond_2

    .line 44
    .line 45
    iget-object p0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    invoke-virtual {p0, v1, v2}, Landroidx/fragment/app/p0;->h(Landroidx/fragment/app/j0;Z)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1, v0}, Landroidx/fragment/app/j0;->performCreate(Landroid/os/Bundle;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0, v1, v2}, Landroidx/fragment/app/p0;->c(Landroidx/fragment/app/j0;Z)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_2
    const/4 p0, 0x1

    .line 59
    iput p0, v1, Landroidx/fragment/app/j0;->mState:I

    .line 60
    .line 61
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->restoreChildFragmentState()V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public final f()V
    .locals 9

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mFromLayout:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v1, 0x3

    .line 9
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const-string v3, "FragmentManager"

    .line 14
    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    new-instance v2, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v4, "moveto CREATE_VIEW: "

    .line 20
    .line 21
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-static {v3, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 32
    .line 33
    .line 34
    :cond_1
    iget-object v2, v0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 35
    .line 36
    const/4 v4, 0x0

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    const-string v5, "savedInstanceState"

    .line 40
    .line 41
    invoke-virtual {v2, v5}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    move-object v2, v4

    .line 47
    :goto_0
    invoke-virtual {v0, v2}, Landroidx/fragment/app/j0;->performGetLayoutInflater(Landroid/os/Bundle;)Landroid/view/LayoutInflater;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    iget-object v6, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 52
    .line 53
    if-eqz v6, :cond_3

    .line 54
    .line 55
    move-object v4, v6

    .line 56
    goto/16 :goto_2

    .line 57
    .line 58
    :cond_3
    iget v6, v0, Landroidx/fragment/app/j0;->mContainerId:I

    .line 59
    .line 60
    if-eqz v6, :cond_7

    .line 61
    .line 62
    const/4 v4, -0x1

    .line 63
    if-eq v6, v4, :cond_6

    .line 64
    .line 65
    iget-object v4, v0, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 66
    .line 67
    iget-object v4, v4, Landroidx/fragment/app/j1;->x:Landroidx/fragment/app/r0;

    .line 68
    .line 69
    invoke-virtual {v4, v6}, Landroidx/fragment/app/r0;->b(I)Landroid/view/View;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    check-cast v4, Landroid/view/ViewGroup;

    .line 74
    .line 75
    if-nez v4, :cond_5

    .line 76
    .line 77
    iget-boolean v6, v0, Landroidx/fragment/app/j0;->mRestored:Z

    .line 78
    .line 79
    if-nez v6, :cond_7

    .line 80
    .line 81
    iget-boolean v6, v0, Landroidx/fragment/app/j0;->mInDynamicContainer:Z

    .line 82
    .line 83
    if-eqz v6, :cond_4

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    :try_start_0
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->getResources()Landroid/content/res/Resources;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    iget v1, v0, Landroidx/fragment/app/j0;->mContainerId:I

    .line 91
    .line 92
    invoke-virtual {p0, v1}, Landroid/content/res/Resources;->getResourceName(I)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 96
    goto :goto_1

    .line 97
    :catch_0
    const-string p0, "unknown"

    .line 98
    .line 99
    :goto_1
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 100
    .line 101
    new-instance v2, Ljava/lang/StringBuilder;

    .line 102
    .line 103
    const-string v3, "No view found for id 0x"

    .line 104
    .line 105
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    iget v3, v0, Landroidx/fragment/app/j0;->mContainerId:I

    .line 109
    .line 110
    invoke-static {v3}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    const-string v3, " ("

    .line 118
    .line 119
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    const-string p0, ") for fragment "

    .line 126
    .line 127
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    throw v1

    .line 141
    :cond_5
    instance-of v6, v4, Landroidx/fragment/app/FragmentContainerView;

    .line 142
    .line 143
    if-nez v6, :cond_7

    .line 144
    .line 145
    sget-object v6, Lx6/c;->a:Lx6/b;

    .line 146
    .line 147
    new-instance v6, Lx6/a;

    .line 148
    .line 149
    new-instance v7, Ljava/lang/StringBuilder;

    .line 150
    .line 151
    const-string v8, "Attempting to add fragment "

    .line 152
    .line 153
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    const-string v8, " to container "

    .line 160
    .line 161
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    const-string v8, " which is not a FragmentContainerView"

    .line 168
    .line 169
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 170
    .line 171
    .line 172
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v7

    .line 176
    invoke-direct {v6, v0, v7}, Lx6/g;-><init>(Landroidx/fragment/app/j0;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    invoke-static {v6}, Lx6/c;->b(Lx6/g;)V

    .line 180
    .line 181
    .line 182
    invoke-static {v0}, Lx6/c;->a(Landroidx/fragment/app/j0;)Lx6/b;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 187
    .line 188
    .line 189
    goto :goto_2

    .line 190
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 191
    .line 192
    const-string v1, "Cannot create fragment "

    .line 193
    .line 194
    const-string v2, " for a container view with no id"

    .line 195
    .line 196
    invoke-static {v1, v0, v2}, La7/g0;->g(Ljava/lang/String;Landroidx/fragment/app/j0;Ljava/lang/String;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0

    .line 204
    :cond_7
    :goto_2
    iput-object v4, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 205
    .line 206
    invoke-virtual {v0, v5, v4, v2}, Landroidx/fragment/app/j0;->performCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)V

    .line 207
    .line 208
    .line 209
    iget-object v2, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 210
    .line 211
    const/4 v5, 0x2

    .line 212
    if-eqz v2, :cond_d

    .line 213
    .line 214
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 215
    .line 216
    .line 217
    move-result v1

    .line 218
    if-eqz v1, :cond_8

    .line 219
    .line 220
    new-instance v1, Ljava/lang/StringBuilder;

    .line 221
    .line 222
    const-string v2, "moveto VIEW_CREATED: "

    .line 223
    .line 224
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    invoke-static {v3, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 235
    .line 236
    .line 237
    :cond_8
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 238
    .line 239
    const/4 v2, 0x0

    .line 240
    invoke-virtual {v1, v2}, Landroid/view/View;->setSaveFromParentEnabled(Z)V

    .line 241
    .line 242
    .line 243
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 244
    .line 245
    const v6, 0x7f0a017a

    .line 246
    .line 247
    .line 248
    invoke-virtual {v1, v6, v0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    if-eqz v4, :cond_9

    .line 252
    .line 253
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->b()V

    .line 254
    .line 255
    .line 256
    :cond_9
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mHidden:Z

    .line 257
    .line 258
    if-eqz v1, :cond_a

    .line 259
    .line 260
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 261
    .line 262
    const/16 v4, 0x8

    .line 263
    .line 264
    invoke-virtual {v1, v4}, Landroid/view/View;->setVisibility(I)V

    .line 265
    .line 266
    .line 267
    :cond_a
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 268
    .line 269
    invoke-virtual {v1}, Landroid/view/View;->isAttachedToWindow()Z

    .line 270
    .line 271
    .line 272
    move-result v1

    .line 273
    if-eqz v1, :cond_b

    .line 274
    .line 275
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 276
    .line 277
    sget-object v4, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 278
    .line 279
    invoke-static {v1}, Ld6/i0;->c(Landroid/view/View;)V

    .line 280
    .line 281
    .line 282
    goto :goto_3

    .line 283
    :cond_b
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 284
    .line 285
    new-instance v4, Landroidx/fragment/app/q1;

    .line 286
    .line 287
    invoke-direct {v4, v1}, Landroidx/fragment/app/q1;-><init>(Landroid/view/View;)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v1, v4}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 291
    .line 292
    .line 293
    :goto_3
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->performViewCreated()V

    .line 294
    .line 295
    .line 296
    iget-object p0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 297
    .line 298
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 299
    .line 300
    invoke-virtual {p0, v0, v1, v2}, Landroidx/fragment/app/p0;->m(Landroidx/fragment/app/j0;Landroid/view/View;Z)V

    .line 301
    .line 302
    .line 303
    iget-object p0, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 304
    .line 305
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 306
    .line 307
    .line 308
    move-result p0

    .line 309
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 310
    .line 311
    invoke-virtual {v1}, Landroid/view/View;->getAlpha()F

    .line 312
    .line 313
    .line 314
    move-result v1

    .line 315
    invoke-virtual {v0, v1}, Landroidx/fragment/app/j0;->setPostOnViewCreatedAlpha(F)V

    .line 316
    .line 317
    .line 318
    iget-object v1, v0, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 319
    .line 320
    if-eqz v1, :cond_d

    .line 321
    .line 322
    if-nez p0, :cond_d

    .line 323
    .line 324
    iget-object p0, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 325
    .line 326
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 327
    .line 328
    .line 329
    move-result-object p0

    .line 330
    if-eqz p0, :cond_c

    .line 331
    .line 332
    invoke-virtual {v0, p0}, Landroidx/fragment/app/j0;->setFocusedView(Landroid/view/View;)V

    .line 333
    .line 334
    .line 335
    invoke-static {v5}, Landroidx/fragment/app/j1;->L(I)Z

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    if-eqz v1, :cond_c

    .line 340
    .line 341
    new-instance v1, Ljava/lang/StringBuilder;

    .line 342
    .line 343
    const-string v2, "requestFocus: Saved focused view "

    .line 344
    .line 345
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 349
    .line 350
    .line 351
    const-string p0, " for Fragment "

    .line 352
    .line 353
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 354
    .line 355
    .line 356
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    invoke-static {v3, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 364
    .line 365
    .line 366
    :cond_c
    iget-object p0, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 367
    .line 368
    const/4 v1, 0x0

    .line 369
    invoke-virtual {p0, v1}, Landroid/view/View;->setAlpha(F)V

    .line 370
    .line 371
    .line 372
    :cond_d
    iput v5, v0, Landroidx/fragment/app/j0;->mState:I

    .line 373
    .line 374
    return-void
.end method

.method public final g()V
    .locals 9

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    iget-object v1, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "movefrom CREATED: "

    .line 13
    .line 14
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v2, "FragmentManager"

    .line 25
    .line 26
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-boolean v0, v1, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    const/4 v3, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->isInBackStack()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_1

    .line 40
    .line 41
    move v0, v2

    .line 42
    goto :goto_0

    .line 43
    :cond_1
    move v0, v3

    .line 44
    :goto_0
    const/4 v4, 0x0

    .line 45
    iget-object v5, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 46
    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    iget-boolean v6, v1, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 50
    .line 51
    if-nez v6, :cond_2

    .line 52
    .line 53
    iget-object v6, v1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 54
    .line 55
    invoke-virtual {v5, v6, v4}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 56
    .line 57
    .line 58
    :cond_2
    if-nez v0, :cond_7

    .line 59
    .line 60
    iget-object v6, v5, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 61
    .line 62
    iget-object v7, v6, Landroidx/fragment/app/n1;->d:Ljava/util/HashMap;

    .line 63
    .line 64
    iget-object v8, v1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {v7, v8}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v7

    .line 70
    if-nez v7, :cond_3

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_3
    iget-boolean v7, v6, Landroidx/fragment/app/n1;->g:Z

    .line 74
    .line 75
    if-eqz v7, :cond_4

    .line 76
    .line 77
    iget-boolean v6, v6, Landroidx/fragment/app/n1;->h:Z

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_4
    :goto_1
    move v6, v2

    .line 81
    :goto_2
    if-eqz v6, :cond_5

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_5
    iget-object p0, v1, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 85
    .line 86
    if-eqz p0, :cond_6

    .line 87
    .line 88
    invoke-virtual {v5, p0}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    if-eqz p0, :cond_6

    .line 93
    .line 94
    iget-boolean v0, p0, Landroidx/fragment/app/j0;->mRetainInstance:Z

    .line 95
    .line 96
    if-eqz v0, :cond_6

    .line 97
    .line 98
    iput-object p0, v1, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 99
    .line 100
    :cond_6
    iput v3, v1, Landroidx/fragment/app/j0;->mState:I

    .line 101
    .line 102
    return-void

    .line 103
    :cond_7
    :goto_3
    iget-object v6, v1, Landroidx/fragment/app/j0;->mHost:Landroidx/fragment/app/t0;

    .line 104
    .line 105
    instance-of v7, v6, Landroidx/lifecycle/i1;

    .line 106
    .line 107
    if-eqz v7, :cond_8

    .line 108
    .line 109
    iget-object v2, v5, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 110
    .line 111
    iget-boolean v2, v2, Landroidx/fragment/app/n1;->h:Z

    .line 112
    .line 113
    goto :goto_4

    .line 114
    :cond_8
    iget-object v6, v6, Landroidx/fragment/app/t0;->e:Landroidx/fragment/app/o0;

    .line 115
    .line 116
    if-eqz v6, :cond_9

    .line 117
    .line 118
    invoke-virtual {v6}, Landroid/app/Activity;->isChangingConfigurations()Z

    .line 119
    .line 120
    .line 121
    move-result v6

    .line 122
    xor-int/2addr v2, v6

    .line 123
    :cond_9
    :goto_4
    if-eqz v0, :cond_a

    .line 124
    .line 125
    iget-boolean v0, v1, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 126
    .line 127
    if-eqz v0, :cond_b

    .line 128
    .line 129
    :cond_a
    if-eqz v2, :cond_c

    .line 130
    .line 131
    :cond_b
    iget-object v0, v5, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 132
    .line 133
    invoke-virtual {v0, v1, v3}, Landroidx/fragment/app/n1;->b(Landroidx/fragment/app/j0;Z)V

    .line 134
    .line 135
    .line 136
    :cond_c
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->performDestroy()V

    .line 137
    .line 138
    .line 139
    iget-object v0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 140
    .line 141
    invoke-virtual {v0, v1, v3}, Landroidx/fragment/app/p0;->d(Landroidx/fragment/app/j0;Z)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v5}, Landroidx/fragment/app/s1;->d()Ljava/util/ArrayList;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    :cond_d
    :goto_5
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 153
    .line 154
    .line 155
    move-result v2

    .line 156
    if-eqz v2, :cond_e

    .line 157
    .line 158
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    check-cast v2, Landroidx/fragment/app/r1;

    .line 163
    .line 164
    if-eqz v2, :cond_d

    .line 165
    .line 166
    iget-object v2, v2, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 167
    .line 168
    iget-object v3, v1, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 169
    .line 170
    iget-object v6, v2, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 171
    .line 172
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    if-eqz v3, :cond_d

    .line 177
    .line 178
    iput-object v1, v2, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 179
    .line 180
    iput-object v4, v2, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 181
    .line 182
    goto :goto_5

    .line 183
    :cond_e
    iget-object v0, v1, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 184
    .line 185
    if-eqz v0, :cond_f

    .line 186
    .line 187
    invoke-virtual {v5, v0}, Landroidx/fragment/app/s1;->b(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    iput-object v0, v1, Landroidx/fragment/app/j0;->mTarget:Landroidx/fragment/app/j0;

    .line 192
    .line 193
    :cond_f
    invoke-virtual {v5, p0}, Landroidx/fragment/app/s1;->h(Landroidx/fragment/app/r1;)V

    .line 194
    .line 195
    .line 196
    return-void
.end method

.method public final h()V
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    iget-object v1, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "movefrom CREATE_VIEW: "

    .line 13
    .line 14
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v2, "FragmentManager"

    .line 25
    .line 26
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v0, v1, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    iget-object v2, v1, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 34
    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    invoke-virtual {v1}, Landroidx/fragment/app/j0;->performDestroyView()V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 44
    .line 45
    const/4 v0, 0x0

    .line 46
    invoke-virtual {p0, v1, v0}, Landroidx/fragment/app/p0;->n(Landroidx/fragment/app/j0;Z)V

    .line 47
    .line 48
    .line 49
    const/4 p0, 0x0

    .line 50
    iput-object p0, v1, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 51
    .line 52
    iput-object p0, v1, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 53
    .line 54
    iput-object p0, v1, Landroidx/fragment/app/j0;->mViewLifecycleOwner:Landroidx/fragment/app/c2;

    .line 55
    .line 56
    iget-object v2, v1, Landroidx/fragment/app/j0;->mViewLifecycleOwnerLiveData:Landroidx/lifecycle/i0;

    .line 57
    .line 58
    invoke-virtual {v2, p0}, Landroidx/lifecycle/i0;->j(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-boolean v0, v1, Landroidx/fragment/app/j0;->mInLayout:Z

    .line 62
    .line 63
    return-void
.end method

.method public final i()V
    .locals 5

    .line 1
    const/4 v0, 0x3

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
    iget-object v3, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v4, "movefrom ATTACHED: "

    .line 15
    .line 16
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->performDetach()V

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    invoke-virtual {v1, v3, v4}, Landroidx/fragment/app/p0;->e(Landroidx/fragment/app/j0;Z)V

    .line 36
    .line 37
    .line 38
    const/4 v1, -0x1

    .line 39
    iput v1, v3, Landroidx/fragment/app/j0;->mState:I

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    iput-object v1, v3, Landroidx/fragment/app/j0;->mHost:Landroidx/fragment/app/t0;

    .line 43
    .line 44
    iput-object v1, v3, Landroidx/fragment/app/j0;->mParentFragment:Landroidx/fragment/app/j0;

    .line 45
    .line 46
    iput-object v1, v3, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 47
    .line 48
    iget-boolean v1, v3, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 49
    .line 50
    if-eqz v1, :cond_1

    .line 51
    .line 52
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->isInBackStack()Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-nez v1, :cond_1

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_1
    iget-object p0, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 60
    .line 61
    iget-object p0, p0, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 62
    .line 63
    iget-object v1, p0, Landroidx/fragment/app/n1;->d:Ljava/util/HashMap;

    .line 64
    .line 65
    iget-object v4, v3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {v1, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_2

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    iget-boolean v1, p0, Landroidx/fragment/app/n1;->g:Z

    .line 75
    .line 76
    if-eqz v1, :cond_3

    .line 77
    .line 78
    iget-boolean p0, p0, Landroidx/fragment/app/n1;->h:Z

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 82
    :goto_1
    if-eqz p0, :cond_5

    .line 83
    .line 84
    :goto_2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-eqz p0, :cond_4

    .line 89
    .line 90
    new-instance p0, Ljava/lang/StringBuilder;

    .line 91
    .line 92
    const-string v0, "initState called for fragment: "

    .line 93
    .line 94
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-static {v2, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 105
    .line 106
    .line 107
    :cond_4
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->initState()V

    .line 108
    .line 109
    .line 110
    :cond_5
    return-void
.end method

.method public final j()V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mFromLayout:Z

    .line 4
    .line 5
    if-eqz v1, :cond_3

    .line 6
    .line 7
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mInLayout:Z

    .line 8
    .line 9
    if-eqz v1, :cond_3

    .line 10
    .line 11
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mPerformedCreateView:Z

    .line 12
    .line 13
    if-nez v1, :cond_3

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    new-instance v1, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v2, "moveto CREATE_VIEW: "

    .line 25
    .line 26
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    const-string v2, "FragmentManager"

    .line 37
    .line 38
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    :cond_0
    iget-object v1, v0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    const-string v3, "savedInstanceState"

    .line 47
    .line 48
    invoke-virtual {v1, v3}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move-object v1, v2

    .line 54
    :goto_0
    invoke-virtual {v0, v1}, Landroidx/fragment/app/j0;->performGetLayoutInflater(Landroid/os/Bundle;)Landroid/view/LayoutInflater;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    invoke-virtual {v0, v3, v2, v1}, Landroidx/fragment/app/j0;->performCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)V

    .line 59
    .line 60
    .line 61
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 62
    .line 63
    if-eqz v1, :cond_3

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    invoke-virtual {v1, v2}, Landroid/view/View;->setSaveFromParentEnabled(Z)V

    .line 67
    .line 68
    .line 69
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 70
    .line 71
    const v3, 0x7f0a017a

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1, v3, v0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-boolean v1, v0, Landroidx/fragment/app/j0;->mHidden:Z

    .line 78
    .line 79
    if-eqz v1, :cond_2

    .line 80
    .line 81
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 82
    .line 83
    const/16 v3, 0x8

    .line 84
    .line 85
    invoke-virtual {v1, v3}, Landroid/view/View;->setVisibility(I)V

    .line 86
    .line 87
    .line 88
    :cond_2
    invoke-virtual {v0}, Landroidx/fragment/app/j0;->performViewCreated()V

    .line 89
    .line 90
    .line 91
    iget-object p0, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 92
    .line 93
    iget-object v1, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 94
    .line 95
    invoke-virtual {p0, v0, v1, v2}, Landroidx/fragment/app/p0;->m(Landroidx/fragment/app/j0;Landroid/view/View;Z)V

    .line 96
    .line 97
    .line 98
    const/4 p0, 0x2

    .line 99
    iput p0, v0, Landroidx/fragment/app/j0;->mState:I

    .line 100
    .line 101
    :cond_3
    return-void
.end method

.method public final k()V
    .locals 10

    .line 1
    iget-boolean v0, p0, Landroidx/fragment/app/r1;->d:Z

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const-string v2, "FragmentManager"

    .line 5
    .line 6
    iget-object v3, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    new-instance p0, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v0, "Ignoring re-entrant call to moveToExpectedState() for "

    .line 19
    .line 20
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-static {v2, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void

    .line 34
    :cond_1
    const/4 v0, 0x1

    .line 35
    const/4 v4, 0x0

    .line 36
    :try_start_0
    iput-boolean v0, p0, Landroidx/fragment/app/r1;->d:Z

    .line 37
    .line 38
    move v5, v4

    .line 39
    :goto_0
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->d()I

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    iget v7, v3, Landroidx/fragment/app/j0;->mState:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    const/4 v8, 0x3

    .line 46
    iget-object v9, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 47
    .line 48
    if-eq v6, v7, :cond_11

    .line 49
    .line 50
    iget-object v5, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 51
    .line 52
    if-le v6, v7, :cond_8

    .line 53
    .line 54
    add-int/lit8 v7, v7, 0x1

    .line 55
    .line 56
    packed-switch v7, :pswitch_data_0

    .line 57
    .line 58
    .line 59
    goto/16 :goto_3

    .line 60
    .line 61
    :pswitch_0
    :try_start_1
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->m()V

    .line 62
    .line 63
    .line 64
    goto/16 :goto_3

    .line 65
    .line 66
    :catchall_0
    move-exception v0

    .line 67
    goto/16 :goto_5

    .line 68
    .line 69
    :pswitch_1
    const/4 v5, 0x6

    .line 70
    iput v5, v3, Landroidx/fragment/app/j0;->mState:I

    .line 71
    .line 72
    goto/16 :goto_3

    .line 73
    .line 74
    :pswitch_2
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    if-eqz v6, :cond_2

    .line 79
    .line 80
    new-instance v6, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    const-string v7, "moveto STARTED: "

    .line 83
    .line 84
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    invoke-static {v2, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 95
    .line 96
    .line 97
    :cond_2
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->performStart()V

    .line 98
    .line 99
    .line 100
    invoke-virtual {v5, v3, v4}, Landroidx/fragment/app/p0;->k(Landroidx/fragment/app/j0;Z)V

    .line 101
    .line 102
    .line 103
    goto/16 :goto_3

    .line 104
    .line 105
    :pswitch_3
    iget-object v5, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 106
    .line 107
    const/4 v6, 0x4

    .line 108
    if-eqz v5, :cond_7

    .line 109
    .line 110
    iget-object v5, v3, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 111
    .line 112
    if-eqz v5, :cond_7

    .line 113
    .line 114
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    invoke-static {v5, v7}, Landroidx/fragment/app/r;->j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    iget-object v7, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 123
    .line 124
    invoke-virtual {v7}, Landroid/view/View;->getVisibility()I

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    if-eqz v7, :cond_5

    .line 129
    .line 130
    if-eq v7, v6, :cond_4

    .line 131
    .line 132
    const/16 v9, 0x8

    .line 133
    .line 134
    if-ne v7, v9, :cond_3

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 138
    .line 139
    new-instance v1, Ljava/lang/StringBuilder;

    .line 140
    .line 141
    const-string v2, "Unknown visibility "

    .line 142
    .line 143
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw v0

    .line 157
    :cond_4
    move v8, v6

    .line 158
    goto :goto_1

    .line 159
    :cond_5
    move v8, v1

    .line 160
    :goto_1
    const-string v7, "finalState"

    .line 161
    .line 162
    invoke-static {v8, v7}, Lia/b;->q(ILjava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 166
    .line 167
    .line 168
    move-result v7

    .line 169
    if-eqz v7, :cond_6

    .line 170
    .line 171
    new-instance v7, Ljava/lang/StringBuilder;

    .line 172
    .line 173
    const-string v9, "SpecialEffectsController: Enqueuing add operation for fragment "

    .line 174
    .line 175
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v7

    .line 185
    invoke-static {v2, v7}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 186
    .line 187
    .line 188
    :cond_6
    invoke-virtual {v5, v8, v1, p0}, Landroidx/fragment/app/r;->d(IILandroidx/fragment/app/r1;)V

    .line 189
    .line 190
    .line 191
    :cond_7
    iput v6, v3, Landroidx/fragment/app/j0;->mState:I

    .line 192
    .line 193
    goto/16 :goto_3

    .line 194
    .line 195
    :pswitch_4
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->a()V

    .line 196
    .line 197
    .line 198
    goto/16 :goto_3

    .line 199
    .line 200
    :pswitch_5
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->j()V

    .line 201
    .line 202
    .line 203
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->f()V

    .line 204
    .line 205
    .line 206
    goto/16 :goto_3

    .line 207
    .line 208
    :pswitch_6
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->e()V

    .line 209
    .line 210
    .line 211
    goto/16 :goto_3

    .line 212
    .line 213
    :pswitch_7
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->c()V

    .line 214
    .line 215
    .line 216
    goto/16 :goto_3

    .line 217
    .line 218
    :cond_8
    add-int/lit8 v7, v7, -0x1

    .line 219
    .line 220
    packed-switch v7, :pswitch_data_1

    .line 221
    .line 222
    .line 223
    goto/16 :goto_3

    .line 224
    .line 225
    :pswitch_8
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 226
    .line 227
    .line 228
    move-result v6

    .line 229
    if-eqz v6, :cond_9

    .line 230
    .line 231
    new-instance v6, Ljava/lang/StringBuilder;

    .line 232
    .line 233
    const-string v7, "movefrom RESUMED: "

    .line 234
    .line 235
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 239
    .line 240
    .line 241
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v6

    .line 245
    invoke-static {v2, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 246
    .line 247
    .line 248
    :cond_9
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->performPause()V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v5, v3, v4}, Landroidx/fragment/app/p0;->f(Landroidx/fragment/app/j0;Z)V

    .line 252
    .line 253
    .line 254
    goto/16 :goto_3

    .line 255
    .line 256
    :pswitch_9
    const/4 v5, 0x5

    .line 257
    iput v5, v3, Landroidx/fragment/app/j0;->mState:I

    .line 258
    .line 259
    goto/16 :goto_3

    .line 260
    .line 261
    :pswitch_a
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 262
    .line 263
    .line 264
    move-result v6

    .line 265
    if-eqz v6, :cond_a

    .line 266
    .line 267
    new-instance v6, Ljava/lang/StringBuilder;

    .line 268
    .line 269
    const-string v7, "movefrom STARTED: "

    .line 270
    .line 271
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 275
    .line 276
    .line 277
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v6

    .line 281
    invoke-static {v2, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 282
    .line 283
    .line 284
    :cond_a
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->performStop()V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v5, v3, v4}, Landroidx/fragment/app/p0;->l(Landroidx/fragment/app/j0;Z)V

    .line 288
    .line 289
    .line 290
    goto/16 :goto_3

    .line 291
    .line 292
    :pswitch_b
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 293
    .line 294
    .line 295
    move-result v5

    .line 296
    if-eqz v5, :cond_b

    .line 297
    .line 298
    new-instance v5, Ljava/lang/StringBuilder;

    .line 299
    .line 300
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 301
    .line 302
    .line 303
    const-string v6, "movefrom ACTIVITY_CREATED: "

    .line 304
    .line 305
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 306
    .line 307
    .line 308
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 309
    .line 310
    .line 311
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v5

    .line 315
    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 316
    .line 317
    .line 318
    :cond_b
    iget-boolean v5, v3, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 319
    .line 320
    if-eqz v5, :cond_c

    .line 321
    .line 322
    iget-object v5, v3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 323
    .line 324
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->n()Landroid/os/Bundle;

    .line 325
    .line 326
    .line 327
    move-result-object v6

    .line 328
    invoke-virtual {v9, v5, v6}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 329
    .line 330
    .line 331
    goto :goto_2

    .line 332
    :cond_c
    iget-object v5, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 333
    .line 334
    if-eqz v5, :cond_d

    .line 335
    .line 336
    iget-object v5, v3, Landroidx/fragment/app/j0;->mSavedViewState:Landroid/util/SparseArray;

    .line 337
    .line 338
    if-nez v5, :cond_d

    .line 339
    .line 340
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->o()V

    .line 341
    .line 342
    .line 343
    :cond_d
    :goto_2
    iget-object v5, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 344
    .line 345
    if-eqz v5, :cond_f

    .line 346
    .line 347
    iget-object v5, v3, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 348
    .line 349
    if-eqz v5, :cond_f

    .line 350
    .line 351
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 352
    .line 353
    .line 354
    move-result-object v6

    .line 355
    invoke-static {v5, v6}, Landroidx/fragment/app/r;->j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;

    .line 356
    .line 357
    .line 358
    move-result-object v5

    .line 359
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 360
    .line 361
    .line 362
    move-result v6

    .line 363
    if-eqz v6, :cond_e

    .line 364
    .line 365
    new-instance v6, Ljava/lang/StringBuilder;

    .line 366
    .line 367
    const-string v7, "SpecialEffectsController: Enqueuing remove operation for fragment "

    .line 368
    .line 369
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 370
    .line 371
    .line 372
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 373
    .line 374
    .line 375
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object v6

    .line 379
    invoke-static {v2, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 380
    .line 381
    .line 382
    :cond_e
    invoke-virtual {v5, v0, v8, p0}, Landroidx/fragment/app/r;->d(IILandroidx/fragment/app/r1;)V

    .line 383
    .line 384
    .line 385
    :cond_f
    iput v8, v3, Landroidx/fragment/app/j0;->mState:I

    .line 386
    .line 387
    goto :goto_3

    .line 388
    :pswitch_c
    iput-boolean v4, v3, Landroidx/fragment/app/j0;->mInLayout:Z

    .line 389
    .line 390
    iput v1, v3, Landroidx/fragment/app/j0;->mState:I

    .line 391
    .line 392
    goto :goto_3

    .line 393
    :pswitch_d
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->h()V

    .line 394
    .line 395
    .line 396
    iput v0, v3, Landroidx/fragment/app/j0;->mState:I

    .line 397
    .line 398
    goto :goto_3

    .line 399
    :pswitch_e
    iget-boolean v5, v3, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 400
    .line 401
    if-eqz v5, :cond_10

    .line 402
    .line 403
    iget-object v5, v3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 404
    .line 405
    iget-object v6, v9, Landroidx/fragment/app/s1;->c:Ljava/util/HashMap;

    .line 406
    .line 407
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v5

    .line 411
    check-cast v5, Landroid/os/Bundle;

    .line 412
    .line 413
    if-nez v5, :cond_10

    .line 414
    .line 415
    iget-object v5, v3, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 416
    .line 417
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->n()Landroid/os/Bundle;

    .line 418
    .line 419
    .line 420
    move-result-object v6

    .line 421
    invoke-virtual {v9, v5, v6}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 422
    .line 423
    .line 424
    :cond_10
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->g()V

    .line 425
    .line 426
    .line 427
    goto :goto_3

    .line 428
    :pswitch_f
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->i()V

    .line 429
    .line 430
    .line 431
    :goto_3
    move v5, v0

    .line 432
    goto/16 :goto_0

    .line 433
    .line 434
    :cond_11
    if-nez v5, :cond_14

    .line 435
    .line 436
    const/4 v5, -0x1

    .line 437
    if-ne v7, v5, :cond_14

    .line 438
    .line 439
    iget-boolean v5, v3, Landroidx/fragment/app/j0;->mRemoving:Z

    .line 440
    .line 441
    if-eqz v5, :cond_14

    .line 442
    .line 443
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->isInBackStack()Z

    .line 444
    .line 445
    .line 446
    move-result v5

    .line 447
    if-nez v5, :cond_14

    .line 448
    .line 449
    iget-boolean v5, v3, Landroidx/fragment/app/j0;->mBeingSaved:Z

    .line 450
    .line 451
    if-nez v5, :cond_14

    .line 452
    .line 453
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 454
    .line 455
    .line 456
    move-result v5

    .line 457
    if-eqz v5, :cond_12

    .line 458
    .line 459
    new-instance v5, Ljava/lang/StringBuilder;

    .line 460
    .line 461
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 462
    .line 463
    .line 464
    const-string v6, "Cleaning up state of never attached fragment: "

    .line 465
    .line 466
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 467
    .line 468
    .line 469
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 470
    .line 471
    .line 472
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 473
    .line 474
    .line 475
    move-result-object v5

    .line 476
    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 477
    .line 478
    .line 479
    :cond_12
    iget-object v5, v9, Landroidx/fragment/app/s1;->d:Landroidx/fragment/app/n1;

    .line 480
    .line 481
    invoke-virtual {v5, v3, v0}, Landroidx/fragment/app/n1;->b(Landroidx/fragment/app/j0;Z)V

    .line 482
    .line 483
    .line 484
    invoke-virtual {v9, p0}, Landroidx/fragment/app/s1;->h(Landroidx/fragment/app/r1;)V

    .line 485
    .line 486
    .line 487
    invoke-static {v8}, Landroidx/fragment/app/j1;->L(I)Z

    .line 488
    .line 489
    .line 490
    move-result v5

    .line 491
    if-eqz v5, :cond_13

    .line 492
    .line 493
    new-instance v5, Ljava/lang/StringBuilder;

    .line 494
    .line 495
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 496
    .line 497
    .line 498
    const-string v6, "initState called for fragment: "

    .line 499
    .line 500
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 501
    .line 502
    .line 503
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 504
    .line 505
    .line 506
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object v5

    .line 510
    invoke-static {v2, v5}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 511
    .line 512
    .line 513
    :cond_13
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->initState()V

    .line 514
    .line 515
    .line 516
    :cond_14
    iget-boolean v5, v3, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 517
    .line 518
    if-eqz v5, :cond_1a

    .line 519
    .line 520
    iget-object v5, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 521
    .line 522
    if-eqz v5, :cond_18

    .line 523
    .line 524
    iget-object v5, v3, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 525
    .line 526
    if-eqz v5, :cond_18

    .line 527
    .line 528
    invoke-virtual {v3}, Landroidx/fragment/app/j0;->getParentFragmentManager()Landroidx/fragment/app/j1;

    .line 529
    .line 530
    .line 531
    move-result-object v6

    .line 532
    invoke-static {v5, v6}, Landroidx/fragment/app/r;->j(Landroid/view/ViewGroup;Landroidx/fragment/app/j1;)Landroidx/fragment/app/r;

    .line 533
    .line 534
    .line 535
    move-result-object v5

    .line 536
    iget-boolean v6, v3, Landroidx/fragment/app/j0;->mHidden:Z

    .line 537
    .line 538
    if-eqz v6, :cond_16

    .line 539
    .line 540
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 541
    .line 542
    .line 543
    move-result v1

    .line 544
    if-eqz v1, :cond_15

    .line 545
    .line 546
    new-instance v1, Ljava/lang/StringBuilder;

    .line 547
    .line 548
    const-string v6, "SpecialEffectsController: Enqueuing hide operation for fragment "

    .line 549
    .line 550
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 554
    .line 555
    .line 556
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 557
    .line 558
    .line 559
    move-result-object v1

    .line 560
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 561
    .line 562
    .line 563
    :cond_15
    invoke-virtual {v5, v8, v0, p0}, Landroidx/fragment/app/r;->d(IILandroidx/fragment/app/r1;)V

    .line 564
    .line 565
    .line 566
    goto :goto_4

    .line 567
    :cond_16
    invoke-static {v1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 568
    .line 569
    .line 570
    move-result v6

    .line 571
    if-eqz v6, :cond_17

    .line 572
    .line 573
    new-instance v6, Ljava/lang/StringBuilder;

    .line 574
    .line 575
    const-string v7, "SpecialEffectsController: Enqueuing show operation for fragment "

    .line 576
    .line 577
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 581
    .line 582
    .line 583
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 584
    .line 585
    .line 586
    move-result-object v6

    .line 587
    invoke-static {v2, v6}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 588
    .line 589
    .line 590
    :cond_17
    invoke-virtual {v5, v1, v0, p0}, Landroidx/fragment/app/r;->d(IILandroidx/fragment/app/r1;)V

    .line 591
    .line 592
    .line 593
    :cond_18
    :goto_4
    iget-object v1, v3, Landroidx/fragment/app/j0;->mFragmentManager:Landroidx/fragment/app/j1;

    .line 594
    .line 595
    if-eqz v1, :cond_19

    .line 596
    .line 597
    iget-boolean v2, v3, Landroidx/fragment/app/j0;->mAdded:Z

    .line 598
    .line 599
    if-eqz v2, :cond_19

    .line 600
    .line 601
    invoke-static {v3}, Landroidx/fragment/app/j1;->M(Landroidx/fragment/app/j0;)Z

    .line 602
    .line 603
    .line 604
    move-result v2

    .line 605
    if-eqz v2, :cond_19

    .line 606
    .line 607
    iput-boolean v0, v1, Landroidx/fragment/app/j1;->G:Z

    .line 608
    .line 609
    :cond_19
    iput-boolean v4, v3, Landroidx/fragment/app/j0;->mHiddenChanged:Z

    .line 610
    .line 611
    iget-boolean v0, v3, Landroidx/fragment/app/j0;->mHidden:Z

    .line 612
    .line 613
    invoke-virtual {v3, v0}, Landroidx/fragment/app/j0;->onHiddenChanged(Z)V

    .line 614
    .line 615
    .line 616
    iget-object v0, v3, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 617
    .line 618
    invoke-virtual {v0}, Landroidx/fragment/app/j1;->o()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 619
    .line 620
    .line 621
    :cond_1a
    iput-boolean v4, p0, Landroidx/fragment/app/r1;->d:Z

    .line 622
    .line 623
    return-void

    .line 624
    :goto_5
    iput-boolean v4, p0, Landroidx/fragment/app/r1;->d:Z

    .line 625
    .line 626
    throw v0

    .line 627
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 628
    .line 629
    .line 630
    .line 631
    .line 632
    .line 633
    .line 634
    .line 635
    .line 636
    .line 637
    .line 638
    .line 639
    .line 640
    .line 641
    .line 642
    .line 643
    .line 644
    .line 645
    .line 646
    .line 647
    :pswitch_data_1
    .packed-switch -0x1
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
    .end packed-switch
.end method

.method public final l(Ljava/lang/ClassLoader;)V
    .locals 3

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    invoke-virtual {v0, p1}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 12
    .line 13
    const-string v0, "savedInstanceState"

    .line 14
    .line 15
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    iget-object p1, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 22
    .line 23
    new-instance v1, Landroid/os/Bundle;

    .line 24
    .line 25
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    :try_start_0
    iget-object p1, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 32
    .line 33
    const-string v0, "viewState"

    .line 34
    .line 35
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getSparseParcelableArray(Ljava/lang/String;)Landroid/util/SparseArray;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object p1, p0, Landroidx/fragment/app/j0;->mSavedViewState:Landroid/util/SparseArray;
    :try_end_0
    .catch Landroid/os/BadParcelableException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    iget-object p1, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 42
    .line 43
    const-string v0, "viewRegistryState"

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iput-object p1, p0, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 50
    .line 51
    iget-object p1, p0, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 52
    .line 53
    const-string v0, "state"

    .line 54
    .line 55
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, Landroidx/fragment/app/p1;

    .line 60
    .line 61
    if-eqz p1, :cond_3

    .line 62
    .line 63
    iget-object v0, p1, Landroidx/fragment/app/p1;->p:Ljava/lang/String;

    .line 64
    .line 65
    iput-object v0, p0, Landroidx/fragment/app/j0;->mTargetWho:Ljava/lang/String;

    .line 66
    .line 67
    iget v0, p1, Landroidx/fragment/app/p1;->q:I

    .line 68
    .line 69
    iput v0, p0, Landroidx/fragment/app/j0;->mTargetRequestCode:I

    .line 70
    .line 71
    iget-object v0, p0, Landroidx/fragment/app/j0;->mSavedUserVisibleHint:Ljava/lang/Boolean;

    .line 72
    .line 73
    if-eqz v0, :cond_2

    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    iput-boolean p1, p0, Landroidx/fragment/app/j0;->mUserVisibleHint:Z

    .line 80
    .line 81
    const/4 p1, 0x0

    .line 82
    iput-object p1, p0, Landroidx/fragment/app/j0;->mSavedUserVisibleHint:Ljava/lang/Boolean;

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_2
    iget-boolean p1, p1, Landroidx/fragment/app/p1;->r:Z

    .line 86
    .line 87
    iput-boolean p1, p0, Landroidx/fragment/app/j0;->mUserVisibleHint:Z

    .line 88
    .line 89
    :cond_3
    :goto_0
    iget-boolean p1, p0, Landroidx/fragment/app/j0;->mUserVisibleHint:Z

    .line 90
    .line 91
    if-nez p1, :cond_4

    .line 92
    .line 93
    const/4 p1, 0x1

    .line 94
    iput-boolean p1, p0, Landroidx/fragment/app/j0;->mDeferStart:Z

    .line 95
    .line 96
    :cond_4
    :goto_1
    return-void

    .line 97
    :catch_0
    move-exception p1

    .line 98
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 99
    .line 100
    new-instance v1, Ljava/lang/StringBuilder;

    .line 101
    .line 102
    const-string v2, "Failed to restore view hierarchy state for fragment "

    .line 103
    .line 104
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    invoke-direct {v0, p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 115
    .line 116
    .line 117
    throw v0
.end method

.method public final m()V
    .locals 6

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v0

    .line 6
    const-string v1, "FragmentManager"

    .line 7
    .line 8
    iget-object v2, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v3, "moveto RESUMED: "

    .line 15
    .line 16
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    invoke-virtual {v2}, Landroidx/fragment/app/j0;->getFocusedView()Landroid/view/View;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    if-eqz v0, :cond_4

    .line 34
    .line 35
    iget-object v3, v2, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 36
    .line 37
    if-ne v0, v3, :cond_1

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    :goto_0
    if-eqz v3, :cond_4

    .line 45
    .line 46
    iget-object v4, v2, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 47
    .line 48
    if-ne v3, v4, :cond_3

    .line 49
    .line 50
    :goto_1
    invoke-virtual {v0}, Landroid/view/View;->requestFocus()Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    const/4 v4, 0x2

    .line 55
    invoke-static {v4}, Landroidx/fragment/app/j1;->L(I)Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_4

    .line 60
    .line 61
    new-instance v4, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    const-string v5, "requestFocus: Restoring focused view "

    .line 64
    .line 65
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v0, " "

    .line 72
    .line 73
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    if-eqz v3, :cond_2

    .line 77
    .line 78
    const-string v0, "succeeded"

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_2
    const-string v0, "failed"

    .line 82
    .line 83
    :goto_2
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v0, " on Fragment "

    .line 87
    .line 88
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v0, " resulting in focused view "

    .line 95
    .line 96
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    iget-object v0, v2, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 100
    .line 101
    invoke-virtual {v0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    invoke-static {v1, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 113
    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_3
    invoke-interface {v3}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    goto :goto_0

    .line 121
    :cond_4
    :goto_3
    const/4 v0, 0x0

    .line 122
    invoke-virtual {v2, v0}, Landroidx/fragment/app/j0;->setFocusedView(Landroid/view/View;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v2}, Landroidx/fragment/app/j0;->performResume()V

    .line 126
    .line 127
    .line 128
    iget-object v1, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 129
    .line 130
    const/4 v3, 0x0

    .line 131
    invoke-virtual {v1, v2, v3}, Landroidx/fragment/app/p0;->i(Landroidx/fragment/app/j0;Z)V

    .line 132
    .line 133
    .line 134
    iget-object p0, p0, Landroidx/fragment/app/r1;->b:Landroidx/fragment/app/s1;

    .line 135
    .line 136
    iget-object v1, v2, Landroidx/fragment/app/j0;->mWho:Ljava/lang/String;

    .line 137
    .line 138
    invoke-virtual {p0, v1, v0}, Landroidx/fragment/app/s1;->i(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 139
    .line 140
    .line 141
    iput-object v0, v2, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 142
    .line 143
    iput-object v0, v2, Landroidx/fragment/app/j0;->mSavedViewState:Landroid/util/SparseArray;

    .line 144
    .line 145
    iput-object v0, v2, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 146
    .line 147
    return-void
.end method

.method public final n()Landroid/os/Bundle;
    .locals 5

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    iget v2, v1, Landroidx/fragment/app/j0;->mState:I

    .line 9
    .line 10
    const/4 v3, -0x1

    .line 11
    if-ne v2, v3, :cond_0

    .line 12
    .line 13
    iget-object v2, v1, Landroidx/fragment/app/j0;->mSavedFragmentState:Landroid/os/Bundle;

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0, v2}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    new-instance v2, Landroidx/fragment/app/p1;

    .line 21
    .line 22
    invoke-direct {v2, v1}, Landroidx/fragment/app/p1;-><init>(Landroidx/fragment/app/j0;)V

    .line 23
    .line 24
    .line 25
    const-string v3, "state"

    .line 26
    .line 27
    invoke-virtual {v0, v3, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 28
    .line 29
    .line 30
    iget v2, v1, Landroidx/fragment/app/j0;->mState:I

    .line 31
    .line 32
    if-lez v2, :cond_6

    .line 33
    .line 34
    new-instance v2, Landroid/os/Bundle;

    .line 35
    .line 36
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, v2}, Landroidx/fragment/app/j0;->performSaveInstanceState(Landroid/os/Bundle;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-nez v3, :cond_1

    .line 47
    .line 48
    const-string v3, "savedInstanceState"

    .line 49
    .line 50
    invoke-virtual {v0, v3, v2}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    iget-object v3, p0, Landroidx/fragment/app/r1;->a:Landroidx/fragment/app/p0;

    .line 54
    .line 55
    const/4 v4, 0x0

    .line 56
    invoke-virtual {v3, v1, v2, v4}, Landroidx/fragment/app/p0;->j(Landroidx/fragment/app/j0;Landroid/os/Bundle;Z)V

    .line 57
    .line 58
    .line 59
    new-instance v2, Landroid/os/Bundle;

    .line 60
    .line 61
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 62
    .line 63
    .line 64
    iget-object v3, v1, Landroidx/fragment/app/j0;->mSavedStateRegistryController:Lra/e;

    .line 65
    .line 66
    invoke-virtual {v3, v2}, Lra/e;->c(Landroid/os/Bundle;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    if-nez v3, :cond_2

    .line 74
    .line 75
    const-string v3, "registryState"

    .line 76
    .line 77
    invoke-virtual {v0, v3, v2}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 78
    .line 79
    .line 80
    :cond_2
    iget-object v2, v1, Landroidx/fragment/app/j0;->mChildFragmentManager:Landroidx/fragment/app/j1;

    .line 81
    .line 82
    invoke-virtual {v2}, Landroidx/fragment/app/j1;->Y()Landroid/os/Bundle;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v2}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-nez v3, :cond_3

    .line 91
    .line 92
    const-string v3, "childFragmentManager"

    .line 93
    .line 94
    invoke-virtual {v0, v3, v2}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 95
    .line 96
    .line 97
    :cond_3
    iget-object v2, v1, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 98
    .line 99
    if-eqz v2, :cond_4

    .line 100
    .line 101
    invoke-virtual {p0}, Landroidx/fragment/app/r1;->o()V

    .line 102
    .line 103
    .line 104
    :cond_4
    iget-object p0, v1, Landroidx/fragment/app/j0;->mSavedViewState:Landroid/util/SparseArray;

    .line 105
    .line 106
    if-eqz p0, :cond_5

    .line 107
    .line 108
    const-string v2, "viewState"

    .line 109
    .line 110
    invoke-virtual {v0, v2, p0}, Landroid/os/Bundle;->putSparseParcelableArray(Ljava/lang/String;Landroid/util/SparseArray;)V

    .line 111
    .line 112
    .line 113
    :cond_5
    iget-object p0, v1, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 114
    .line 115
    if-eqz p0, :cond_6

    .line 116
    .line 117
    const-string v2, "viewRegistryState"

    .line 118
    .line 119
    invoke-virtual {v0, v2, p0}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 120
    .line 121
    .line 122
    :cond_6
    iget-object p0, v1, Landroidx/fragment/app/j0;->mArguments:Landroid/os/Bundle;

    .line 123
    .line 124
    if-eqz p0, :cond_7

    .line 125
    .line 126
    const-string v1, "arguments"

    .line 127
    .line 128
    invoke-virtual {v0, v1, p0}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 129
    .line 130
    .line 131
    :cond_7
    return-object v0
.end method

.method public final o()V
    .locals 2

    .line 1
    iget-object p0, p0, Landroidx/fragment/app/r1;->c:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

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
    const-string v1, "Saving view state for fragment "

    .line 18
    .line 19
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, " with view "

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const-string v1, "FragmentManager"

    .line 40
    .line 41
    invoke-static {v1, v0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    :cond_1
    new-instance v0, Landroid/util/SparseArray;

    .line 45
    .line 46
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 50
    .line 51
    invoke-virtual {v1, v0}, Landroid/view/View;->saveHierarchyState(Landroid/util/SparseArray;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-lez v1, :cond_2

    .line 59
    .line 60
    iput-object v0, p0, Landroidx/fragment/app/j0;->mSavedViewState:Landroid/util/SparseArray;

    .line 61
    .line 62
    :cond_2
    new-instance v0, Landroid/os/Bundle;

    .line 63
    .line 64
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 65
    .line 66
    .line 67
    iget-object v1, p0, Landroidx/fragment/app/j0;->mViewLifecycleOwner:Landroidx/fragment/app/c2;

    .line 68
    .line 69
    iget-object v1, v1, Landroidx/fragment/app/c2;->i:Lra/e;

    .line 70
    .line 71
    invoke-virtual {v1, v0}, Lra/e;->c(Landroid/os/Bundle;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-nez v1, :cond_3

    .line 79
    .line 80
    iput-object v0, p0, Landroidx/fragment/app/j0;->mSavedViewRegistryState:Landroid/os/Bundle;

    .line 81
    .line 82
    :cond_3
    :goto_0
    return-void
.end method
