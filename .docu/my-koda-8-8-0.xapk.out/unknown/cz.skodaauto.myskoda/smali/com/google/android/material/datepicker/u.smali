.class public final Lcom/google/android/material/datepicker/u;
.super Lcom/google/android/material/datepicker/g0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<S:",
        "Ljava/lang/Object;",
        ">",
        "Lcom/google/android/material/datepicker/g0;"
    }
.end annotation


# instance fields
.field public e:I

.field public f:Lcom/google/android/material/datepicker/i;

.field public g:Lcom/google/android/material/datepicker/c;

.field public h:Lcom/google/android/material/datepicker/b0;

.field public i:I

.field public j:Lcom/google/android/material/datepicker/d;

.field public k:Landroidx/recyclerview/widget/RecyclerView;

.field public l:Landroidx/recyclerview/widget/RecyclerView;

.field public m:Landroid/view/View;

.field public n:Landroid/view/View;

.field public o:Landroid/view/View;

.field public p:Landroid/view/View;

.field public q:Lcom/google/android/material/button/MaterialButton;

.field public r:Landroid/view/accessibility/AccessibilityManager;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/material/datepicker/g0;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final i(Lcom/google/android/material/datepicker/x;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/g0;->d:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final j(Lcom/google/android/material/datepicker/b0;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->getAdapter()Lka/y;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcom/google/android/material/datepicker/f0;

    .line 8
    .line 9
    iget-object v1, v0, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 10
    .line 11
    iget-object v1, v1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 12
    .line 13
    invoke-virtual {v1, p1}, Lcom/google/android/material/datepicker/b0;->i(Lcom/google/android/material/datepicker/b0;)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    iget-object v2, p0, Lcom/google/android/material/datepicker/u;->r:Landroid/view/accessibility/AccessibilityManager;

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    invoke-virtual {v2}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    iput-object p1, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 28
    .line 29
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 30
    .line 31
    invoke-virtual {p1, v1}, Landroidx/recyclerview/widget/RecyclerView;->c0(I)V

    .line 32
    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_0
    iget-object v2, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 36
    .line 37
    iget-object v0, v0, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 38
    .line 39
    iget-object v0, v0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 40
    .line 41
    invoke-virtual {v0, v2}, Lcom/google/android/material/datepicker/b0;->i(Lcom/google/android/material/datepicker/b0;)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    sub-int v0, v1, v0

    .line 46
    .line 47
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    const/4 v3, 0x0

    .line 52
    const/4 v4, 0x1

    .line 53
    const/4 v5, 0x3

    .line 54
    if-le v2, v5, :cond_1

    .line 55
    .line 56
    move v2, v4

    .line 57
    goto :goto_0

    .line 58
    :cond_1
    move v2, v3

    .line 59
    :goto_0
    if-lez v0, :cond_2

    .line 60
    .line 61
    move v3, v4

    .line 62
    :cond_2
    iput-object p1, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 63
    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    if-eqz v3, :cond_3

    .line 67
    .line 68
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 69
    .line 70
    add-int/lit8 v0, v1, -0x3

    .line 71
    .line 72
    invoke-virtual {p1, v0}, Landroidx/recyclerview/widget/RecyclerView;->c0(I)V

    .line 73
    .line 74
    .line 75
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 76
    .line 77
    new-instance v0, Lcom/google/android/material/datepicker/n;

    .line 78
    .line 79
    const/4 v2, 0x0

    .line 80
    invoke-direct {v0, p0, v1, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_3
    if-eqz v2, :cond_4

    .line 88
    .line 89
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 90
    .line 91
    add-int/lit8 v0, v1, 0x3

    .line 92
    .line 93
    invoke-virtual {p1, v0}, Landroidx/recyclerview/widget/RecyclerView;->c0(I)V

    .line 94
    .line 95
    .line 96
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 97
    .line 98
    new-instance v0, Lcom/google/android/material/datepicker/n;

    .line 99
    .line 100
    const/4 v2, 0x0

    .line 101
    invoke-direct {v0, p0, v1, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_4
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 109
    .line 110
    new-instance v0, Lcom/google/android/material/datepicker/n;

    .line 111
    .line 112
    const/4 v2, 0x0

    .line 113
    invoke-direct {v0, p0, v1, v2}, Lcom/google/android/material/datepicker/n;-><init>(Ljava/lang/Object;II)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 117
    .line 118
    .line 119
    :goto_1
    invoke-virtual {p0, v1}, Lcom/google/android/material/datepicker/u;->l(I)V

    .line 120
    .line 121
    .line 122
    return-void
.end method

.method public final k(I)V
    .locals 4

    .line 1
    iput p1, p0, Lcom/google/android/material/datepicker/u;->i:I

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    const/16 v1, 0x8

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 10
    .line 11
    invoke-virtual {p1}, Landroidx/recyclerview/widget/RecyclerView;->getLayoutManager()Lka/f0;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 16
    .line 17
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->getAdapter()Lka/y;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lcom/google/android/material/datepicker/q0;

    .line 22
    .line 23
    iget-object v3, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 24
    .line 25
    iget v3, v3, Lcom/google/android/material/datepicker/b0;->f:I

    .line 26
    .line 27
    iget-object v0, v0, Lcom/google/android/material/datepicker/q0;->d:Lcom/google/android/material/datepicker/u;

    .line 28
    .line 29
    iget-object v0, v0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 30
    .line 31
    iget-object v0, v0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 32
    .line 33
    iget v0, v0, Lcom/google/android/material/datepicker/b0;->f:I

    .line 34
    .line 35
    sub-int/2addr v3, v0

    .line 36
    invoke-virtual {p1, v3}, Lka/f0;->p0(I)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->o:Landroid/view/View;

    .line 40
    .line 41
    invoke-virtual {p1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->p:Landroid/view/View;

    .line 45
    .line 46
    invoke-virtual {p1, v1}, Landroid/view/View;->setVisibility(I)V

    .line 47
    .line 48
    .line 49
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->m:Landroid/view/View;

    .line 50
    .line 51
    invoke-virtual {p1, v1}, Landroid/view/View;->setVisibility(I)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Lcom/google/android/material/datepicker/u;->n:Landroid/view/View;

    .line 55
    .line 56
    invoke-virtual {p0, v1}, Landroid/view/View;->setVisibility(I)V

    .line 57
    .line 58
    .line 59
    return-void

    .line 60
    :cond_0
    const/4 v0, 0x1

    .line 61
    if-ne p1, v0, :cond_1

    .line 62
    .line 63
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->o:Landroid/view/View;

    .line 64
    .line 65
    invoke-virtual {p1, v1}, Landroid/view/View;->setVisibility(I)V

    .line 66
    .line 67
    .line 68
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->p:Landroid/view/View;

    .line 69
    .line 70
    invoke-virtual {p1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 71
    .line 72
    .line 73
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->m:Landroid/view/View;

    .line 74
    .line 75
    invoke-virtual {p1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 76
    .line 77
    .line 78
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->n:Landroid/view/View;

    .line 79
    .line 80
    invoke-virtual {p1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 81
    .line 82
    .line 83
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 84
    .line 85
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/u;->j(Lcom/google/android/material/datepicker/b0;)V

    .line 86
    .line 87
    .line 88
    :cond_1
    return-void
.end method

.method public final l(I)V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->n:Landroid/view/View;

    .line 2
    .line 3
    add-int/lit8 v1, p1, 0x1

    .line 4
    .line 5
    iget-object v2, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 6
    .line 7
    invoke-virtual {v2}, Landroidx/recyclerview/widget/RecyclerView;->getAdapter()Lka/y;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {v2}, Lka/y;->a()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/4 v3, 0x0

    .line 16
    const/4 v4, 0x1

    .line 17
    if-ge v1, v2, :cond_0

    .line 18
    .line 19
    move v1, v4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v1, v3

    .line 22
    :goto_0
    invoke-virtual {v0, v1}, Landroid/view/View;->setEnabled(Z)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lcom/google/android/material/datepicker/u;->m:Landroid/view/View;

    .line 26
    .line 27
    sub-int/2addr p1, v4

    .line 28
    if-ltz p1, :cond_1

    .line 29
    .line 30
    move v3, v4

    .line 31
    :cond_1
    invoke-virtual {p0, v3}, Landroid/view/View;->setEnabled(Z)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/j0;->onCreate(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getArguments()Landroid/os/Bundle;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    :cond_0
    const-string v0, "THEME_RES_ID_KEY"

    .line 11
    .line 12
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iput v0, p0, Lcom/google/android/material/datepicker/u;->e:I

    .line 17
    .line 18
    const-string v0, "GRID_SELECTOR_KEY"

    .line 19
    .line 20
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lcom/google/android/material/datepicker/i;

    .line 25
    .line 26
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->f:Lcom/google/android/material/datepicker/i;

    .line 27
    .line 28
    const-string v0, "CALENDAR_CONSTRAINTS_KEY"

    .line 29
    .line 30
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Lcom/google/android/material/datepicker/c;

    .line 35
    .line 36
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 37
    .line 38
    const-string v0, "DAY_VIEW_DECORATOR_KEY"

    .line 39
    .line 40
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-nez v0, :cond_1

    .line 45
    .line 46
    const-string v0, "CURRENT_MONTH_KEY"

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, Lcom/google/android/material/datepicker/b0;

    .line 53
    .line 54
    iput-object p1, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 58
    .line 59
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public final onCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;
    .locals 10

    .line 1
    new-instance p3, Landroid/view/ContextThemeWrapper;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lcom/google/android/material/datepicker/u;->e:I

    .line 8
    .line 9
    invoke-direct {p3, v0, v1}, Landroid/view/ContextThemeWrapper;-><init>(Landroid/content/Context;I)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lcom/google/android/material/datepicker/d;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-direct {v0, p3, v1}, Lcom/google/android/material/datepicker/d;-><init>(Landroid/content/Context;I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->j:Lcom/google/android/material/datepicker/d;

    .line 19
    .line 20
    invoke-virtual {p1, p3}, Landroid/view/LayoutInflater;->cloneInContext(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    const-string v1, "accessibility"

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Landroid/view/accessibility/AccessibilityManager;

    .line 35
    .line 36
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->r:Landroid/view/accessibility/AccessibilityManager;

    .line 37
    .line 38
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 39
    .line 40
    iget-object v0, v0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 41
    .line 42
    const v1, 0x101020d

    .line 43
    .line 44
    .line 45
    invoke-static {p3, v1}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    const/4 v3, 0x0

    .line 50
    const/4 v4, 0x1

    .line 51
    if-eqz v2, :cond_0

    .line 52
    .line 53
    const v2, 0x7f0d02cc

    .line 54
    .line 55
    .line 56
    move v5, v4

    .line 57
    goto :goto_0

    .line 58
    :cond_0
    const v2, 0x7f0d02c7

    .line 59
    .line 60
    .line 61
    move v5, v3

    .line 62
    :goto_0
    invoke-virtual {p1, v2, p2, v3}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    invoke-virtual {p2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    const v2, 0x7f070401

    .line 75
    .line 76
    .line 77
    invoke-virtual {p2, v2}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    const v6, 0x7f070402

    .line 82
    .line 83
    .line 84
    invoke-virtual {p2, v6}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    add-int/2addr v6, v2

    .line 89
    const v2, 0x7f070400

    .line 90
    .line 91
    .line 92
    invoke-virtual {p2, v2}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    add-int/2addr v2, v6

    .line 97
    const v6, 0x7f0703f1

    .line 98
    .line 99
    .line 100
    invoke-virtual {p2, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    sget v7, Lcom/google/android/material/datepicker/c0;->f:I

    .line 105
    .line 106
    const v8, 0x7f0703ec

    .line 107
    .line 108
    .line 109
    invoke-virtual {p2, v8}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    mul-int/2addr v8, v7

    .line 114
    sub-int/2addr v7, v4

    .line 115
    const v9, 0x7f0703ff

    .line 116
    .line 117
    .line 118
    invoke-virtual {p2, v9}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 119
    .line 120
    .line 121
    move-result v9

    .line 122
    mul-int/2addr v9, v7

    .line 123
    add-int/2addr v9, v8

    .line 124
    const v7, 0x7f0703e9

    .line 125
    .line 126
    .line 127
    invoke-virtual {p2, v7}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    add-int/2addr v2, v6

    .line 132
    add-int/2addr v2, v9

    .line 133
    add-int/2addr v2, p2

    .line 134
    invoke-virtual {p1, v2}, Landroid/view/View;->setMinimumHeight(I)V

    .line 135
    .line 136
    .line 137
    const p2, 0x7f0a0205

    .line 138
    .line 139
    .line 140
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 141
    .line 142
    .line 143
    move-result-object p2

    .line 144
    check-cast p2, Landroid/widget/GridView;

    .line 145
    .line 146
    new-instance v2, Lcom/google/android/material/datepicker/o;

    .line 147
    .line 148
    const/4 v6, 0x0

    .line 149
    invoke-direct {v2, v6}, Lcom/google/android/material/datepicker/o;-><init>(I)V

    .line 150
    .line 151
    .line 152
    invoke-static {p2, v2}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 153
    .line 154
    .line 155
    iget-object v2, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 156
    .line 157
    iget v2, v2, Lcom/google/android/material/datepicker/c;->h:I

    .line 158
    .line 159
    new-instance v6, Lcom/google/android/material/datepicker/l;

    .line 160
    .line 161
    if-lez v2, :cond_1

    .line 162
    .line 163
    invoke-direct {v6, v2}, Lcom/google/android/material/datepicker/l;-><init>(I)V

    .line 164
    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_1
    invoke-direct {v6}, Lcom/google/android/material/datepicker/l;-><init>()V

    .line 168
    .line 169
    .line 170
    :goto_1
    invoke-virtual {p2, v6}, Landroid/widget/GridView;->setAdapter(Landroid/widget/ListAdapter;)V

    .line 171
    .line 172
    .line 173
    iget v0, v0, Lcom/google/android/material/datepicker/b0;->g:I

    .line 174
    .line 175
    invoke-virtual {p2, v0}, Landroid/widget/GridView;->setNumColumns(I)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p2, v3}, Landroid/view/View;->setEnabled(Z)V

    .line 179
    .line 180
    .line 181
    const p2, 0x7f0a0208

    .line 182
    .line 183
    .line 184
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 185
    .line 186
    .line 187
    move-result-object p2

    .line 188
    check-cast p2, Landroidx/recyclerview/widget/RecyclerView;

    .line 189
    .line 190
    iput-object p2, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 191
    .line 192
    new-instance p2, Lcom/google/android/material/datepicker/p;

    .line 193
    .line 194
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 195
    .line 196
    .line 197
    invoke-direct {p2, p0, v5, v5}, Lcom/google/android/material/datepicker/p;-><init>(Lcom/google/android/material/datepicker/u;II)V

    .line 198
    .line 199
    .line 200
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 201
    .line 202
    invoke-virtual {v0, p2}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Lka/f0;)V

    .line 203
    .line 204
    .line 205
    iget-object p2, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 206
    .line 207
    const-string v0, "MONTHS_VIEW_GROUP_TAG"

    .line 208
    .line 209
    invoke-virtual {p2, v0}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    new-instance p2, Lcom/google/android/material/datepicker/f0;

    .line 213
    .line 214
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->f:Lcom/google/android/material/datepicker/i;

    .line 215
    .line 216
    iget-object v2, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 217
    .line 218
    new-instance v3, La0/j;

    .line 219
    .line 220
    const/16 v5, 0x9

    .line 221
    .line 222
    invoke-direct {v3, p0, v5}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    invoke-direct {p2, p3, v0, v2, v3}, Lcom/google/android/material/datepicker/f0;-><init>(Landroid/view/ContextThemeWrapper;Lcom/google/android/material/datepicker/i;Lcom/google/android/material/datepicker/c;La0/j;)V

    .line 226
    .line 227
    .line 228
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 229
    .line 230
    invoke-virtual {v0, p2}, Landroidx/recyclerview/widget/RecyclerView;->setAdapter(Lka/y;)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p3}, Landroid/view/ContextThemeWrapper;->getResources()Landroid/content/res/Resources;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    const v2, 0x7f0b003b

    .line 238
    .line 239
    .line 240
    invoke-virtual {v0, v2}, Landroid/content/res/Resources;->getInteger(I)I

    .line 241
    .line 242
    .line 243
    move-result v0

    .line 244
    const v2, 0x7f0a020b

    .line 245
    .line 246
    .line 247
    invoke-virtual {p1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 248
    .line 249
    .line 250
    move-result-object v3

    .line 251
    check-cast v3, Landroidx/recyclerview/widget/RecyclerView;

    .line 252
    .line 253
    iput-object v3, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 254
    .line 255
    if-eqz v3, :cond_2

    .line 256
    .line 257
    invoke-virtual {v3, v4}, Landroidx/recyclerview/widget/RecyclerView;->setHasFixedSize(Z)V

    .line 258
    .line 259
    .line 260
    iget-object v3, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 261
    .line 262
    new-instance v5, Landroidx/recyclerview/widget/GridLayoutManager;

    .line 263
    .line 264
    invoke-direct {v5, v0}, Landroidx/recyclerview/widget/GridLayoutManager;-><init>(I)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v3, v5}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Lka/f0;)V

    .line 268
    .line 269
    .line 270
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 271
    .line 272
    new-instance v3, Lcom/google/android/material/datepicker/q0;

    .line 273
    .line 274
    invoke-direct {v3, p0}, Lcom/google/android/material/datepicker/q0;-><init>(Lcom/google/android/material/datepicker/u;)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v0, v3}, Landroidx/recyclerview/widget/RecyclerView;->setAdapter(Lka/y;)V

    .line 278
    .line 279
    .line 280
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 281
    .line 282
    new-instance v3, Lcom/google/android/material/datepicker/q;

    .line 283
    .line 284
    invoke-direct {v3, p0}, Lcom/google/android/material/datepicker/q;-><init>(Lcom/google/android/material/datepicker/u;)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {v0, v3}, Landroidx/recyclerview/widget/RecyclerView;->g(Lka/d0;)V

    .line 288
    .line 289
    .line 290
    :cond_2
    const v0, 0x7f0a01ff

    .line 291
    .line 292
    .line 293
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    iget-object v5, p2, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 298
    .line 299
    if-eqz v3, :cond_3

    .line 300
    .line 301
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    check-cast v0, Lcom/google/android/material/button/MaterialButton;

    .line 306
    .line 307
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->q:Lcom/google/android/material/button/MaterialButton;

    .line 308
    .line 309
    const-string v3, "SELECTOR_TOGGLE_TAG"

    .line 310
    .line 311
    invoke-virtual {v0, v3}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->q:Lcom/google/android/material/button/MaterialButton;

    .line 315
    .line 316
    new-instance v3, Lcom/google/android/material/datepicker/r;

    .line 317
    .line 318
    const/4 v6, 0x0

    .line 319
    invoke-direct {v3, p0, v6}, Lcom/google/android/material/datepicker/r;-><init>(Ljava/lang/Object;I)V

    .line 320
    .line 321
    .line 322
    invoke-static {v0, v3}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 323
    .line 324
    .line 325
    const v0, 0x7f0a0201

    .line 326
    .line 327
    .line 328
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->m:Landroid/view/View;

    .line 333
    .line 334
    const-string v3, "NAVIGATION_PREV_TAG"

    .line 335
    .line 336
    invoke-virtual {v0, v3}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 337
    .line 338
    .line 339
    const v0, 0x7f0a0200

    .line 340
    .line 341
    .line 342
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->n:Landroid/view/View;

    .line 347
    .line 348
    const-string v3, "NAVIGATION_NEXT_TAG"

    .line 349
    .line 350
    invoke-virtual {v0, v3}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {p1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->o:Landroid/view/View;

    .line 358
    .line 359
    const v0, 0x7f0a0204

    .line 360
    .line 361
    .line 362
    invoke-virtual {p1, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 363
    .line 364
    .line 365
    move-result-object v0

    .line 366
    iput-object v0, p0, Lcom/google/android/material/datepicker/u;->p:Landroid/view/View;

    .line 367
    .line 368
    invoke-virtual {p0, v4}, Lcom/google/android/material/datepicker/u;->k(I)V

    .line 369
    .line 370
    .line 371
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->q:Lcom/google/android/material/button/MaterialButton;

    .line 372
    .line 373
    iget-object v2, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 374
    .line 375
    invoke-virtual {v2}, Lcom/google/android/material/datepicker/b0;->h()Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object v2

    .line 379
    invoke-virtual {v0, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 380
    .line 381
    .line 382
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 383
    .line 384
    new-instance v2, Lcom/google/android/material/datepicker/s;

    .line 385
    .line 386
    invoke-direct {v2, p0, p2}, Lcom/google/android/material/datepicker/s;-><init>(Lcom/google/android/material/datepicker/u;Lcom/google/android/material/datepicker/f0;)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {v0, v2}, Landroidx/recyclerview/widget/RecyclerView;->h(Lka/i0;)V

    .line 390
    .line 391
    .line 392
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->q:Lcom/google/android/material/button/MaterialButton;

    .line 393
    .line 394
    new-instance v2, Lcom/google/android/material/datepicker/t;

    .line 395
    .line 396
    const/4 v3, 0x0

    .line 397
    invoke-direct {v2, p0, v3}, Lcom/google/android/material/datepicker/t;-><init>(Ljava/lang/Object;I)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v0, v2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 401
    .line 402
    .line 403
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->n:Landroid/view/View;

    .line 404
    .line 405
    new-instance v2, Lcom/google/android/material/datepicker/m;

    .line 406
    .line 407
    const/4 v3, 0x1

    .line 408
    invoke-direct {v2, p0, p2, v3}, Lcom/google/android/material/datepicker/m;-><init>(Lcom/google/android/material/datepicker/u;Lcom/google/android/material/datepicker/f0;I)V

    .line 409
    .line 410
    .line 411
    invoke-virtual {v0, v2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 412
    .line 413
    .line 414
    iget-object v0, p0, Lcom/google/android/material/datepicker/u;->m:Landroid/view/View;

    .line 415
    .line 416
    new-instance v2, Lcom/google/android/material/datepicker/m;

    .line 417
    .line 418
    const/4 v3, 0x0

    .line 419
    invoke-direct {v2, p0, p2, v3}, Lcom/google/android/material/datepicker/m;-><init>(Lcom/google/android/material/datepicker/u;Lcom/google/android/material/datepicker/f0;I)V

    .line 420
    .line 421
    .line 422
    invoke-virtual {v0, v2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 423
    .line 424
    .line 425
    iget-object p2, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 426
    .line 427
    iget-object v0, v5, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 428
    .line 429
    invoke-virtual {v0, p2}, Lcom/google/android/material/datepicker/b0;->i(Lcom/google/android/material/datepicker/b0;)I

    .line 430
    .line 431
    .line 432
    move-result p2

    .line 433
    invoke-virtual {p0, p2}, Lcom/google/android/material/datepicker/u;->l(I)V

    .line 434
    .line 435
    .line 436
    :cond_3
    invoke-static {p3, v1}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 437
    .line 438
    .line 439
    move-result p2

    .line 440
    if-nez p2, :cond_8

    .line 441
    .line 442
    new-instance p2, Lka/w;

    .line 443
    .line 444
    invoke-direct {p2}, Lka/w;-><init>()V

    .line 445
    .line 446
    .line 447
    iget-object p3, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 448
    .line 449
    iget-object v0, p2, Lka/w;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 450
    .line 451
    if-ne v0, p3, :cond_4

    .line 452
    .line 453
    goto :goto_2

    .line 454
    :cond_4
    iget-object v1, p2, Lka/w;->b:Lka/y0;

    .line 455
    .line 456
    if-eqz v0, :cond_6

    .line 457
    .line 458
    iget-object v0, v0, Landroidx/recyclerview/widget/RecyclerView;->s1:Ljava/util/ArrayList;

    .line 459
    .line 460
    if-eqz v0, :cond_5

    .line 461
    .line 462
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 463
    .line 464
    .line 465
    :cond_5
    iget-object v0, p2, Lka/w;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 466
    .line 467
    const/4 v2, 0x0

    .line 468
    invoke-virtual {v0, v2}, Landroidx/recyclerview/widget/RecyclerView;->setOnFlingListener(Lka/h0;)V

    .line 469
    .line 470
    .line 471
    :cond_6
    iput-object p3, p2, Lka/w;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 472
    .line 473
    if-eqz p3, :cond_8

    .line 474
    .line 475
    invoke-virtual {p3}, Landroidx/recyclerview/widget/RecyclerView;->getOnFlingListener()Lka/h0;

    .line 476
    .line 477
    .line 478
    move-result-object p3

    .line 479
    if-nez p3, :cond_7

    .line 480
    .line 481
    iget-object p3, p2, Lka/w;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 482
    .line 483
    invoke-virtual {p3, v1}, Landroidx/recyclerview/widget/RecyclerView;->h(Lka/i0;)V

    .line 484
    .line 485
    .line 486
    iget-object p3, p2, Lka/w;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 487
    .line 488
    invoke-virtual {p3, p2}, Landroidx/recyclerview/widget/RecyclerView;->setOnFlingListener(Lka/h0;)V

    .line 489
    .line 490
    .line 491
    new-instance p3, Landroid/widget/Scroller;

    .line 492
    .line 493
    iget-object v0, p2, Lka/w;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 494
    .line 495
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 496
    .line 497
    .line 498
    move-result-object v0

    .line 499
    new-instance v1, Landroid/view/animation/DecelerateInterpolator;

    .line 500
    .line 501
    invoke-direct {v1}, Landroid/view/animation/DecelerateInterpolator;-><init>()V

    .line 502
    .line 503
    .line 504
    invoke-direct {p3, v0, v1}, Landroid/widget/Scroller;-><init>(Landroid/content/Context;Landroid/view/animation/Interpolator;)V

    .line 505
    .line 506
    .line 507
    invoke-virtual {p2}, Lka/w;->f()V

    .line 508
    .line 509
    .line 510
    goto :goto_2

    .line 511
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 512
    .line 513
    const-string p1, "An instance of OnFlingListener already set."

    .line 514
    .line 515
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 516
    .line 517
    .line 518
    throw p0

    .line 519
    :cond_8
    :goto_2
    iget-object p2, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 520
    .line 521
    iget-object p3, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 522
    .line 523
    iget-object v0, v5, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 524
    .line 525
    invoke-virtual {v0, p3}, Lcom/google/android/material/datepicker/b0;->i(Lcom/google/android/material/datepicker/b0;)I

    .line 526
    .line 527
    .line 528
    move-result p3

    .line 529
    invoke-virtual {p2, p3}, Landroidx/recyclerview/widget/RecyclerView;->c0(I)V

    .line 530
    .line 531
    .line 532
    iget-object p0, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 533
    .line 534
    new-instance p2, Lcom/google/android/material/datepicker/o;

    .line 535
    .line 536
    const/4 p3, 0x1

    .line 537
    invoke-direct {p2, p3}, Lcom/google/android/material/datepicker/o;-><init>(I)V

    .line 538
    .line 539
    .line 540
    invoke-static {p0, p2}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 541
    .line 542
    .line 543
    return-object p1
.end method

.method public final onSaveInstanceState(Landroid/os/Bundle;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/j0;->onSaveInstanceState(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    const-string v0, "THEME_RES_ID_KEY"

    .line 5
    .line 6
    iget v1, p0, Lcom/google/android/material/datepicker/u;->e:I

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 9
    .line 10
    .line 11
    const-string v0, "GRID_SELECTOR_KEY"

    .line 12
    .line 13
    iget-object v1, p0, Lcom/google/android/material/datepicker/u;->f:Lcom/google/android/material/datepicker/i;

    .line 14
    .line 15
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 16
    .line 17
    .line 18
    const-string v0, "CALENDAR_CONSTRAINTS_KEY"

    .line 19
    .line 20
    iget-object v1, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 21
    .line 22
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 23
    .line 24
    .line 25
    const-string v0, "DAY_VIEW_DECORATOR_KEY"

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 29
    .line 30
    .line 31
    const-string v0, "CURRENT_MONTH_KEY"

    .line 32
    .line 33
    iget-object p0, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 34
    .line 35
    invoke-virtual {p1, v0, p0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
