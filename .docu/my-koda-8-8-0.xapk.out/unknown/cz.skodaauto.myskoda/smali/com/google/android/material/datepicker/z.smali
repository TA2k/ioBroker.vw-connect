.class public Lcom/google/android/material/datepicker/z;
.super Landroidx/fragment/app/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<S:",
        "Ljava/lang/Object;",
        ">",
        "Landroidx/fragment/app/x;"
    }
.end annotation


# instance fields
.field public A:Lcom/google/android/material/datepicker/c;

.field public B:Lcom/google/android/material/datepicker/u;

.field public C:I

.field public D:Ljava/lang/CharSequence;

.field public E:Z

.field public F:I

.field public G:I

.field public H:Ljava/lang/CharSequence;

.field public I:I

.field public J:Ljava/lang/CharSequence;

.field public K:I

.field public L:Ljava/lang/CharSequence;

.field public M:I

.field public N:Ljava/lang/CharSequence;

.field public O:Landroid/widget/TextView;

.field public P:Landroid/widget/TextView;

.field public Q:Lcom/google/android/material/internal/CheckableImageButton;

.field public R:Lwq/i;

.field public S:Landroid/widget/Button;

.field public T:Z

.field public U:Ljava/lang/CharSequence;

.field public V:Ljava/lang/CharSequence;

.field public final t:Ljava/util/LinkedHashSet;

.field public final u:Ljava/util/LinkedHashSet;

.field public final v:Ljava/util/LinkedHashSet;

.field public final w:Ljava/util/LinkedHashSet;

.field public x:I

.field public y:Lcom/google/android/material/datepicker/i;

.field public z:Lcom/google/android/material/datepicker/g0;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/fragment/app/x;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->t:Ljava/util/LinkedHashSet;

    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->u:Ljava/util/LinkedHashSet;

    .line 17
    .line 18
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->v:Ljava/util/LinkedHashSet;

    .line 24
    .line 25
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->w:Ljava/util/LinkedHashSet;

    .line 31
    .line 32
    return-void
.end method

.method public static m(Landroid/content/Context;)I
    .locals 6

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const v0, 0x7f0703ea

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/4 v2, 0x5

    .line 17
    const/4 v3, 0x1

    .line 18
    invoke-virtual {v1, v2, v3}, Ljava/util/Calendar;->set(II)V

    .line 19
    .line 20
    .line 21
    invoke-static {v1}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-virtual {v1, v4}, Ljava/util/Calendar;->get(I)I

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, v3}, Ljava/util/Calendar;->get(I)I

    .line 30
    .line 31
    .line 32
    const/4 v5, 0x7

    .line 33
    invoke-virtual {v1, v5}, Ljava/util/Calendar;->getMaximum(I)I

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    invoke-virtual {v1, v2}, Ljava/util/Calendar;->getActualMaximum(I)I

    .line 38
    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 41
    .line 42
    .line 43
    const v1, 0x7f0703f0

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0, v1}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    const v2, 0x7f0703fe

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v2}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    mul-int/2addr v0, v4

    .line 58
    mul-int/2addr v1, v5

    .line 59
    add-int/2addr v1, v0

    .line 60
    sub-int/2addr v5, v3

    .line 61
    mul-int/2addr v5, p0

    .line 62
    add-int/2addr v5, v1

    .line 63
    return v5
.end method

.method public static n(Landroid/content/Context;I)Z
    .locals 2

    .line 1
    const-class v0, Lcom/google/android/material/datepicker/u;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const v1, 0x7f040383

    .line 8
    .line 9
    .line 10
    invoke-static {p0, v0, v1}, Llp/w9;->e(Landroid/content/Context;Ljava/lang/String;I)Landroid/util/TypedValue;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget v0, v0, Landroid/util/TypedValue;->data:I

    .line 15
    .line 16
    filled-new-array {p1}, [I

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, v0, p1}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const/4 p1, 0x0

    .line 25
    invoke-virtual {p0, p1, p1}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    .line 30
    .line 31
    .line 32
    return p1
.end method


# virtual methods
.method public final j()Landroid/app/Dialog;
    .locals 6

    .line 1
    new-instance v0, Landroid/app/Dialog;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    iget v3, p0, Lcom/google/android/material/datepicker/z;->x:I

    .line 12
    .line 13
    if-eqz v3, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    invoke-interface {v3, v2}, Lcom/google/android/material/datepicker/i;->H(Landroid/content/Context;)I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    :goto_0
    invoke-direct {v0, v1, v3}, Landroid/app/Dialog;-><init>(Landroid/content/Context;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    const v2, 0x101020d

    .line 32
    .line 33
    .line 34
    invoke-static {v1, v2}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    iput-boolean v2, p0, Lcom/google/android/material/datepicker/z;->E:Z

    .line 39
    .line 40
    new-instance v2, Lwq/i;

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    const v4, 0x7f040383

    .line 44
    .line 45
    .line 46
    const v5, 0x7f130528

    .line 47
    .line 48
    .line 49
    invoke-direct {v2, v1, v3, v4, v5}, Lwq/i;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 50
    .line 51
    .line 52
    iput-object v2, p0, Lcom/google/android/material/datepicker/z;->R:Lwq/i;

    .line 53
    .line 54
    sget-object v2, Ldq/a;->m:[I

    .line 55
    .line 56
    invoke-virtual {v1, v3, v2, v4, v5}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    const/4 v3, 0x1

    .line 61
    const/4 v4, 0x0

    .line 62
    invoke-virtual {v2, v3, v4}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 67
    .line 68
    .line 69
    iget-object v2, p0, Lcom/google/android/material/datepicker/z;->R:Lwq/i;

    .line 70
    .line 71
    invoke-virtual {v2, v1}, Lwq/i;->j(Landroid/content/Context;)V

    .line 72
    .line 73
    .line 74
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->R:Lwq/i;

    .line 75
    .line 76
    invoke-static {v3}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-virtual {v1, v2}, Lwq/i;->m(Landroid/content/res/ColorStateList;)V

    .line 81
    .line 82
    .line 83
    iget-object p0, p0, Lcom/google/android/material/datepicker/z;->R:Lwq/i;

    .line 84
    .line 85
    invoke-virtual {v0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    invoke-virtual {v1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {v1}, Landroid/view/View;->getElevation()F

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    invoke-virtual {p0, v1}, Lwq/i;->l(F)V

    .line 98
    .line 99
    .line 100
    return-object v0
.end method

.method public final l()Lcom/google/android/material/datepicker/i;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/z;->y:Lcom/google/android/material/datepicker/i;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getArguments()Landroid/os/Bundle;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "DATE_SELECTOR_KEY"

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lcom/google/android/material/datepicker/i;

    .line 16
    .line 17
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->y:Lcom/google/android/material/datepicker/i;

    .line 18
    .line 19
    :cond_0
    iget-object p0, p0, Lcom/google/android/material/datepicker/z;->y:Lcom/google/android/material/datepicker/i;

    .line 20
    .line 21
    return-object p0
.end method

.method public final o()V
    .locals 9

    .line 1
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget v1, p0, Lcom/google/android/material/datepicker/z;->x:I

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-interface {v1, v0}, Lcom/google/android/material/datepicker/i;->H(Landroid/content/Context;)I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iget-object v2, p0, Lcom/google/android/material/datepicker/z;->A:Lcom/google/android/material/datepicker/c;

    .line 23
    .line 24
    new-instance v3, Lcom/google/android/material/datepicker/u;

    .line 25
    .line 26
    invoke-direct {v3}, Lcom/google/android/material/datepicker/u;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v4, Landroid/os/Bundle;

    .line 30
    .line 31
    invoke-direct {v4}, Landroid/os/Bundle;-><init>()V

    .line 32
    .line 33
    .line 34
    const-string v5, "THEME_RES_ID_KEY"

    .line 35
    .line 36
    invoke-virtual {v4, v5, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    const-string v6, "GRID_SELECTOR_KEY"

    .line 40
    .line 41
    invoke-virtual {v4, v6, v0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 42
    .line 43
    .line 44
    const-string v0, "CALENDAR_CONSTRAINTS_KEY"

    .line 45
    .line 46
    invoke-virtual {v4, v0, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 47
    .line 48
    .line 49
    const-string v6, "DAY_VIEW_DECORATOR_KEY"

    .line 50
    .line 51
    const/4 v7, 0x0

    .line 52
    invoke-virtual {v4, v6, v7}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 53
    .line 54
    .line 55
    const-string v6, "CURRENT_MONTH_KEY"

    .line 56
    .line 57
    iget-object v2, v2, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 58
    .line 59
    invoke-virtual {v4, v6, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v3, v4}, Landroidx/fragment/app/j0;->setArguments(Landroid/os/Bundle;)V

    .line 63
    .line 64
    .line 65
    iput-object v3, p0, Lcom/google/android/material/datepicker/z;->B:Lcom/google/android/material/datepicker/u;

    .line 66
    .line 67
    iget v2, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    if-ne v2, v4, :cond_1

    .line 71
    .line 72
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    iget-object v3, p0, Lcom/google/android/material/datepicker/z;->A:Lcom/google/android/material/datepicker/c;

    .line 77
    .line 78
    new-instance v6, Lcom/google/android/material/datepicker/a0;

    .line 79
    .line 80
    invoke-direct {v6}, Lcom/google/android/material/datepicker/a0;-><init>()V

    .line 81
    .line 82
    .line 83
    new-instance v8, Landroid/os/Bundle;

    .line 84
    .line 85
    invoke-direct {v8}, Landroid/os/Bundle;-><init>()V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v8, v5, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 89
    .line 90
    .line 91
    const-string v1, "DATE_SELECTOR_KEY"

    .line 92
    .line 93
    invoke-virtual {v8, v1, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v8, v0, v3}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v6, v8}, Landroidx/fragment/app/j0;->setArguments(Landroid/os/Bundle;)V

    .line 100
    .line 101
    .line 102
    move-object v3, v6

    .line 103
    :cond_1
    iput-object v3, p0, Lcom/google/android/material/datepicker/z;->z:Lcom/google/android/material/datepicker/g0;

    .line 104
    .line 105
    iget-object v0, p0, Lcom/google/android/material/datepicker/z;->O:Landroid/widget/TextView;

    .line 106
    .line 107
    iget v1, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 108
    .line 109
    const/4 v2, 0x2

    .line 110
    if-ne v1, v4, :cond_2

    .line 111
    .line 112
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getResources()Landroid/content/res/Resources;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    iget v1, v1, Landroid/content/res/Configuration;->orientation:I

    .line 121
    .line 122
    if-ne v1, v2, :cond_2

    .line 123
    .line 124
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->V:Ljava/lang/CharSequence;

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_2
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->U:Ljava/lang/CharSequence;

    .line 128
    .line 129
    :goto_1
    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    invoke-interface {v0, v1}, Lcom/google/android/material/datepicker/i;->T(Landroid/content/Context;)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->P:Landroid/widget/TextView;

    .line 145
    .line 146
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 151
    .line 152
    .line 153
    move-result-object v4

    .line 154
    invoke-interface {v3, v4}, Lcom/google/android/material/datepicker/i;->E(Landroid/content/Context;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    invoke-virtual {v1, v3}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 159
    .line 160
    .line 161
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->P:Landroid/widget/TextView;

    .line 162
    .line 163
    invoke-virtual {v1, v0}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getChildFragmentManager()Landroidx/fragment/app/j1;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 171
    .line 172
    .line 173
    new-instance v1, Landroidx/fragment/app/a;

    .line 174
    .line 175
    invoke-direct {v1, v0}, Landroidx/fragment/app/a;-><init>(Landroidx/fragment/app/j1;)V

    .line 176
    .line 177
    .line 178
    const v0, 0x7f0a0206

    .line 179
    .line 180
    .line 181
    iget-object v3, p0, Lcom/google/android/material/datepicker/z;->z:Lcom/google/android/material/datepicker/g0;

    .line 182
    .line 183
    invoke-virtual {v1, v0, v3, v7, v2}, Landroidx/fragment/app/a;->f(ILandroidx/fragment/app/j0;Ljava/lang/String;I)V

    .line 184
    .line 185
    .line 186
    iget-boolean v0, v1, Landroidx/fragment/app/a;->g:Z

    .line 187
    .line 188
    if-nez v0, :cond_3

    .line 189
    .line 190
    iget-object v0, v1, Landroidx/fragment/app/a;->q:Landroidx/fragment/app/j1;

    .line 191
    .line 192
    const/4 v2, 0x0

    .line 193
    invoke-virtual {v0, v1, v2}, Landroidx/fragment/app/j1;->A(Landroidx/fragment/app/a;Z)V

    .line 194
    .line 195
    .line 196
    iget-object v0, p0, Lcom/google/android/material/datepicker/z;->z:Lcom/google/android/material/datepicker/g0;

    .line 197
    .line 198
    new-instance v1, Lcom/google/android/material/datepicker/x;

    .line 199
    .line 200
    invoke-direct {v1, p0, v2}, Lcom/google/android/material/datepicker/x;-><init>(Landroidx/fragment/app/j0;I)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0, v1}, Lcom/google/android/material/datepicker/g0;->i(Lcom/google/android/material/datepicker/x;)V

    .line 204
    .line 205
    .line 206
    return-void

    .line 207
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 208
    .line 209
    const-string v0, "This transaction is already being added to the back stack"

    .line 210
    .line 211
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0
.end method

.method public final onCancel(Landroid/content/DialogInterface;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/z;->v:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Landroid/content/DialogInterface$OnCancelListener;

    .line 18
    .line 19
    invoke-interface {v0, p1}, Landroid/content/DialogInterface$OnCancelListener;->onCancel(Landroid/content/DialogInterface;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/x;->onCreate(Landroid/os/Bundle;)V

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
    const-string v0, "OVERRIDE_THEME_RES_ID"

    .line 11
    .line 12
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iput v0, p0, Lcom/google/android/material/datepicker/z;->x:I

    .line 17
    .line 18
    const-string v0, "DATE_SELECTOR_KEY"

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
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->y:Lcom/google/android/material/datepicker/i;

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
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->A:Lcom/google/android/material/datepicker/c;

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
    if-nez v0, :cond_4

    .line 45
    .line 46
    const-string v0, "TITLE_TEXT_RES_ID_KEY"

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iput v0, p0, Lcom/google/android/material/datepicker/z;->C:I

    .line 53
    .line 54
    const-string v0, "TITLE_TEXT_KEY"

    .line 55
    .line 56
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->D:Ljava/lang/CharSequence;

    .line 61
    .line 62
    const-string v0, "INPUT_MODE_KEY"

    .line 63
    .line 64
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iput v0, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 69
    .line 70
    const-string v0, "POSITIVE_BUTTON_TEXT_RES_ID_KEY"

    .line 71
    .line 72
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    iput v0, p0, Lcom/google/android/material/datepicker/z;->G:I

    .line 77
    .line 78
    const-string v0, "POSITIVE_BUTTON_TEXT_KEY"

    .line 79
    .line 80
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->H:Ljava/lang/CharSequence;

    .line 85
    .line 86
    const-string v0, "POSITIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY"

    .line 87
    .line 88
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    iput v0, p0, Lcom/google/android/material/datepicker/z;->I:I

    .line 93
    .line 94
    const-string v0, "POSITIVE_BUTTON_CONTENT_DESCRIPTION_KEY"

    .line 95
    .line 96
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->J:Ljava/lang/CharSequence;

    .line 101
    .line 102
    const-string v0, "NEGATIVE_BUTTON_TEXT_RES_ID_KEY"

    .line 103
    .line 104
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    iput v0, p0, Lcom/google/android/material/datepicker/z;->K:I

    .line 109
    .line 110
    const-string v0, "NEGATIVE_BUTTON_TEXT_KEY"

    .line 111
    .line 112
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    iput-object v0, p0, Lcom/google/android/material/datepicker/z;->L:Ljava/lang/CharSequence;

    .line 117
    .line 118
    const-string v0, "NEGATIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY"

    .line 119
    .line 120
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    iput v0, p0, Lcom/google/android/material/datepicker/z;->M:I

    .line 125
    .line 126
    const-string v0, "NEGATIVE_BUTTON_CONTENT_DESCRIPTION_KEY"

    .line 127
    .line 128
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    iput-object p1, p0, Lcom/google/android/material/datepicker/z;->N:Ljava/lang/CharSequence;

    .line 133
    .line 134
    iget-object p1, p0, Lcom/google/android/material/datepicker/z;->D:Ljava/lang/CharSequence;

    .line 135
    .line 136
    if-eqz p1, :cond_1

    .line 137
    .line 138
    goto :goto_0

    .line 139
    :cond_1
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    iget v0, p0, Lcom/google/android/material/datepicker/z;->C:I

    .line 148
    .line 149
    invoke-virtual {p1, v0}, Landroid/content/res/Resources;->getText(I)Ljava/lang/CharSequence;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    :goto_0
    iput-object p1, p0, Lcom/google/android/material/datepicker/z;->U:Ljava/lang/CharSequence;

    .line 154
    .line 155
    if-eqz p1, :cond_2

    .line 156
    .line 157
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    const-string v1, "\n"

    .line 162
    .line 163
    invoke-static {v0, v1}, Landroid/text/TextUtils;->split(Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    array-length v1, v0

    .line 168
    const/4 v2, 0x1

    .line 169
    if-le v1, v2, :cond_3

    .line 170
    .line 171
    const/4 p1, 0x0

    .line 172
    aget-object p1, v0, p1

    .line 173
    .line 174
    goto :goto_1

    .line 175
    :cond_2
    const/4 p1, 0x0

    .line 176
    :cond_3
    :goto_1
    iput-object p1, p0, Lcom/google/android/material/datepicker/z;->V:Ljava/lang/CharSequence;

    .line 177
    .line 178
    return-void

    .line 179
    :cond_4
    new-instance p0, Ljava/lang/ClassCastException;

    .line 180
    .line 181
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 182
    .line 183
    .line 184
    throw p0
.end method

.method public final onCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;
    .locals 5

    .line 1
    iget-boolean p3, p0, Lcom/google/android/material/datepicker/z;->E:Z

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const p3, 0x7f0d02d3

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const p3, 0x7f0d02d2

    .line 10
    .line 11
    .line 12
    :goto_0
    invoke-virtual {p1, p3, p2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    iget-boolean p3, p0, Lcom/google/android/material/datepicker/z;->E:Z

    .line 21
    .line 22
    if-eqz p3, :cond_1

    .line 23
    .line 24
    const p3, 0x7f0a0206

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, p3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 28
    .line 29
    .line 30
    move-result-object p3

    .line 31
    new-instance v0, Landroid/widget/LinearLayout$LayoutParams;

    .line 32
    .line 33
    invoke-static {p2}, Lcom/google/android/material/datepicker/z;->m(Landroid/content/Context;)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const/4 v2, -0x2

    .line 38
    invoke-direct {v0, v1, v2}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p3, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    const p3, 0x7f0a0207

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 49
    .line 50
    .line 51
    move-result-object p3

    .line 52
    new-instance v0, Landroid/widget/LinearLayout$LayoutParams;

    .line 53
    .line 54
    invoke-static {p2}, Lcom/google/android/material/datepicker/z;->m(Landroid/content/Context;)I

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    const/4 v2, -0x1

    .line 59
    invoke-direct {v0, v1, v2}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p3, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 63
    .line 64
    .line 65
    :goto_1
    const p3, 0x7f0a0212

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, p3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 69
    .line 70
    .line 71
    move-result-object p3

    .line 72
    check-cast p3, Landroid/widget/TextView;

    .line 73
    .line 74
    iput-object p3, p0, Lcom/google/android/material/datepicker/z;->P:Landroid/widget/TextView;

    .line 75
    .line 76
    const/4 v0, 0x1

    .line 77
    invoke-virtual {p3, v0}, Landroid/view/View;->setAccessibilityLiveRegion(I)V

    .line 78
    .line 79
    .line 80
    const p3, 0x7f0a0214

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, p3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 84
    .line 85
    .line 86
    move-result-object p3

    .line 87
    check-cast p3, Lcom/google/android/material/internal/CheckableImageButton;

    .line 88
    .line 89
    iput-object p3, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 90
    .line 91
    const p3, 0x7f0a0218

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1, p3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 95
    .line 96
    .line 97
    move-result-object p3

    .line 98
    check-cast p3, Landroid/widget/TextView;

    .line 99
    .line 100
    iput-object p3, p0, Lcom/google/android/material/datepicker/z;->O:Landroid/widget/TextView;

    .line 101
    .line 102
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 103
    .line 104
    const-string v1, "TOGGLE_BUTTON_TAG"

    .line 105
    .line 106
    invoke-virtual {p3, v1}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 110
    .line 111
    new-instance v1, Landroid/graphics/drawable/StateListDrawable;

    .line 112
    .line 113
    invoke-direct {v1}, Landroid/graphics/drawable/StateListDrawable;-><init>()V

    .line 114
    .line 115
    .line 116
    const v2, 0x10100a0

    .line 117
    .line 118
    .line 119
    filled-new-array {v2}, [I

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    const v3, 0x7f080258

    .line 124
    .line 125
    .line 126
    invoke-static {p2, v3}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-virtual {v1, v2, v3}, Landroid/graphics/drawable/StateListDrawable;->addState([ILandroid/graphics/drawable/Drawable;)V

    .line 131
    .line 132
    .line 133
    const/4 v2, 0x0

    .line 134
    new-array v3, v2, [I

    .line 135
    .line 136
    const v4, 0x7f08025a

    .line 137
    .line 138
    .line 139
    invoke-static {p2, v4}, Llp/g1;->b(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    invoke-virtual {v1, v3, p2}, Landroid/graphics/drawable/StateListDrawable;->addState([ILandroid/graphics/drawable/Drawable;)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p3, v1}, Lm/w;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 147
    .line 148
    .line 149
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 150
    .line 151
    iget p3, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 152
    .line 153
    if-eqz p3, :cond_2

    .line 154
    .line 155
    move p3, v0

    .line 156
    goto :goto_2

    .line 157
    :cond_2
    move p3, v2

    .line 158
    :goto_2
    invoke-virtual {p2, p3}, Lcom/google/android/material/internal/CheckableImageButton;->setChecked(Z)V

    .line 159
    .line 160
    .line 161
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 162
    .line 163
    const/4 p3, 0x0

    .line 164
    invoke-static {p2, p3}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 165
    .line 166
    .line 167
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 168
    .line 169
    invoke-virtual {p0, p2}, Lcom/google/android/material/datepicker/z;->p(Lcom/google/android/material/internal/CheckableImageButton;)V

    .line 170
    .line 171
    .line 172
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 173
    .line 174
    new-instance p3, Lcom/google/android/material/datepicker/v;

    .line 175
    .line 176
    const/4 v1, 0x2

    .line 177
    invoke-direct {p3, p0, v1}, Lcom/google/android/material/datepicker/v;-><init>(Lcom/google/android/material/datepicker/z;I)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {p2, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 181
    .line 182
    .line 183
    const p2, 0x7f0a00eb

    .line 184
    .line 185
    .line 186
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 187
    .line 188
    .line 189
    move-result-object p2

    .line 190
    check-cast p2, Landroid/widget/Button;

    .line 191
    .line 192
    iput-object p2, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 193
    .line 194
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->l()Lcom/google/android/material/datepicker/i;

    .line 195
    .line 196
    .line 197
    move-result-object p2

    .line 198
    invoke-interface {p2}, Lcom/google/android/material/datepicker/i;->k0()Z

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    if-eqz p2, :cond_3

    .line 203
    .line 204
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 205
    .line 206
    invoke-virtual {p2, v0}, Landroid/view/View;->setEnabled(Z)V

    .line 207
    .line 208
    .line 209
    goto :goto_3

    .line 210
    :cond_3
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 211
    .line 212
    invoke-virtual {p2, v2}, Landroid/view/View;->setEnabled(Z)V

    .line 213
    .line 214
    .line 215
    :goto_3
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 216
    .line 217
    const-string p3, "CONFIRM_BUTTON_TAG"

    .line 218
    .line 219
    invoke-virtual {p2, p3}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->H:Ljava/lang/CharSequence;

    .line 223
    .line 224
    if-eqz p2, :cond_4

    .line 225
    .line 226
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 227
    .line 228
    invoke-virtual {p3, p2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 229
    .line 230
    .line 231
    goto :goto_4

    .line 232
    :cond_4
    iget p2, p0, Lcom/google/android/material/datepicker/z;->G:I

    .line 233
    .line 234
    if-eqz p2, :cond_5

    .line 235
    .line 236
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 237
    .line 238
    invoke-virtual {p3, p2}, Landroid/widget/TextView;->setText(I)V

    .line 239
    .line 240
    .line 241
    :cond_5
    :goto_4
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->J:Ljava/lang/CharSequence;

    .line 242
    .line 243
    if-eqz p2, :cond_6

    .line 244
    .line 245
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 246
    .line 247
    invoke-virtual {p3, p2}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 248
    .line 249
    .line 250
    goto :goto_5

    .line 251
    :cond_6
    iget p2, p0, Lcom/google/android/material/datepicker/z;->I:I

    .line 252
    .line 253
    if-eqz p2, :cond_7

    .line 254
    .line 255
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 256
    .line 257
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 258
    .line 259
    .line 260
    move-result-object p3

    .line 261
    invoke-virtual {p3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 262
    .line 263
    .line 264
    move-result-object p3

    .line 265
    iget v0, p0, Lcom/google/android/material/datepicker/z;->I:I

    .line 266
    .line 267
    invoke-virtual {p3, v0}, Landroid/content/res/Resources;->getText(I)Ljava/lang/CharSequence;

    .line 268
    .line 269
    .line 270
    move-result-object p3

    .line 271
    invoke-virtual {p2, p3}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 272
    .line 273
    .line 274
    :cond_7
    :goto_5
    iget-object p2, p0, Lcom/google/android/material/datepicker/z;->S:Landroid/widget/Button;

    .line 275
    .line 276
    new-instance p3, Lcom/google/android/material/datepicker/v;

    .line 277
    .line 278
    const/4 v0, 0x0

    .line 279
    invoke-direct {p3, p0, v0}, Lcom/google/android/material/datepicker/v;-><init>(Lcom/google/android/material/datepicker/z;I)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {p2, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 283
    .line 284
    .line 285
    const p2, 0x7f0a0073

    .line 286
    .line 287
    .line 288
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 289
    .line 290
    .line 291
    move-result-object p2

    .line 292
    check-cast p2, Landroid/widget/Button;

    .line 293
    .line 294
    const-string p3, "CANCEL_BUTTON_TAG"

    .line 295
    .line 296
    invoke-virtual {p2, p3}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->L:Ljava/lang/CharSequence;

    .line 300
    .line 301
    if-eqz p3, :cond_8

    .line 302
    .line 303
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 304
    .line 305
    .line 306
    goto :goto_6

    .line 307
    :cond_8
    iget p3, p0, Lcom/google/android/material/datepicker/z;->K:I

    .line 308
    .line 309
    if-eqz p3, :cond_9

    .line 310
    .line 311
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(I)V

    .line 312
    .line 313
    .line 314
    :cond_9
    :goto_6
    iget-object p3, p0, Lcom/google/android/material/datepicker/z;->N:Ljava/lang/CharSequence;

    .line 315
    .line 316
    if-eqz p3, :cond_a

    .line 317
    .line 318
    invoke-virtual {p2, p3}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 319
    .line 320
    .line 321
    goto :goto_7

    .line 322
    :cond_a
    iget p3, p0, Lcom/google/android/material/datepicker/z;->M:I

    .line 323
    .line 324
    if-eqz p3, :cond_b

    .line 325
    .line 326
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getContext()Landroid/content/Context;

    .line 327
    .line 328
    .line 329
    move-result-object p3

    .line 330
    invoke-virtual {p3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 331
    .line 332
    .line 333
    move-result-object p3

    .line 334
    iget v0, p0, Lcom/google/android/material/datepicker/z;->M:I

    .line 335
    .line 336
    invoke-virtual {p3, v0}, Landroid/content/res/Resources;->getText(I)Ljava/lang/CharSequence;

    .line 337
    .line 338
    .line 339
    move-result-object p3

    .line 340
    invoke-virtual {p2, p3}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 341
    .line 342
    .line 343
    :cond_b
    :goto_7
    new-instance p3, Lcom/google/android/material/datepicker/v;

    .line 344
    .line 345
    const/4 v0, 0x1

    .line 346
    invoke-direct {p3, p0, v0}, Lcom/google/android/material/datepicker/v;-><init>(Lcom/google/android/material/datepicker/z;I)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {p2, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 350
    .line 351
    .line 352
    return-object p1
.end method

.method public final onDismiss(Landroid/content/DialogInterface;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/z;->w:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Landroid/content/DialogInterface$OnDismissListener;

    .line 18
    .line 19
    invoke-interface {v1, p1}, Landroid/content/DialogInterface$OnDismissListener;->onDismiss(Landroid/content/DialogInterface;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getView()Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Landroid/view/ViewGroup;

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 32
    .line 33
    .line 34
    :cond_1
    invoke-super {p0, p1}, Landroidx/fragment/app/x;->onDismiss(Landroid/content/DialogInterface;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final onSaveInstanceState(Landroid/os/Bundle;)V
    .locals 5

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/x;->onSaveInstanceState(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    const-string v0, "OVERRIDE_THEME_RES_ID"

    .line 5
    .line 6
    iget v1, p0, Lcom/google/android/material/datepicker/z;->x:I

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 9
    .line 10
    .line 11
    const-string v0, "DATE_SELECTOR_KEY"

    .line 12
    .line 13
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->y:Lcom/google/android/material/datepicker/i;

    .line 14
    .line 15
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Lcom/google/android/material/datepicker/a;

    .line 19
    .line 20
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->A:Lcom/google/android/material/datepicker/c;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    sget-wide v2, Lcom/google/android/material/datepicker/a;->f:J

    .line 26
    .line 27
    iput-wide v2, v0, Lcom/google/android/material/datepicker/a;->a:J

    .line 28
    .line 29
    sget-wide v2, Lcom/google/android/material/datepicker/a;->g:J

    .line 30
    .line 31
    iput-wide v2, v0, Lcom/google/android/material/datepicker/a;->b:J

    .line 32
    .line 33
    new-instance v2, Lcom/google/android/material/datepicker/k;

    .line 34
    .line 35
    const-wide/high16 v3, -0x8000000000000000L

    .line 36
    .line 37
    invoke-direct {v2, v3, v4}, Lcom/google/android/material/datepicker/k;-><init>(J)V

    .line 38
    .line 39
    .line 40
    iput-object v2, v0, Lcom/google/android/material/datepicker/a;->e:Lcom/google/android/material/datepicker/b;

    .line 41
    .line 42
    iget-object v2, v1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 43
    .line 44
    iget-wide v2, v2, Lcom/google/android/material/datepicker/b0;->i:J

    .line 45
    .line 46
    iput-wide v2, v0, Lcom/google/android/material/datepicker/a;->a:J

    .line 47
    .line 48
    iget-object v2, v1, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 49
    .line 50
    iget-wide v2, v2, Lcom/google/android/material/datepicker/b0;->i:J

    .line 51
    .line 52
    iput-wide v2, v0, Lcom/google/android/material/datepicker/a;->b:J

    .line 53
    .line 54
    iget-object v2, v1, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 55
    .line 56
    iget-wide v2, v2, Lcom/google/android/material/datepicker/b0;->i:J

    .line 57
    .line 58
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    iput-object v2, v0, Lcom/google/android/material/datepicker/a;->c:Ljava/lang/Long;

    .line 63
    .line 64
    iget v2, v1, Lcom/google/android/material/datepicker/c;->h:I

    .line 65
    .line 66
    iput v2, v0, Lcom/google/android/material/datepicker/a;->d:I

    .line 67
    .line 68
    iget-object v1, v1, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 69
    .line 70
    iput-object v1, v0, Lcom/google/android/material/datepicker/a;->e:Lcom/google/android/material/datepicker/b;

    .line 71
    .line 72
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->B:Lcom/google/android/material/datepicker/u;

    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    if-nez v1, :cond_0

    .line 76
    .line 77
    move-object v1, v2

    .line 78
    goto :goto_0

    .line 79
    :cond_0
    iget-object v1, v1, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 80
    .line 81
    :goto_0
    if-eqz v1, :cond_1

    .line 82
    .line 83
    iget-wide v3, v1, Lcom/google/android/material/datepicker/b0;->i:J

    .line 84
    .line 85
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    iput-object v1, v0, Lcom/google/android/material/datepicker/a;->c:Ljava/lang/Long;

    .line 90
    .line 91
    :cond_1
    const-string v1, "CALENDAR_CONSTRAINTS_KEY"

    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/google/android/material/datepicker/a;->a()Lcom/google/android/material/datepicker/c;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    invoke-virtual {p1, v1, v0}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 98
    .line 99
    .line 100
    const-string v0, "DAY_VIEW_DECORATOR_KEY"

    .line 101
    .line 102
    invoke-virtual {p1, v0, v2}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 103
    .line 104
    .line 105
    const-string v0, "TITLE_TEXT_RES_ID_KEY"

    .line 106
    .line 107
    iget v1, p0, Lcom/google/android/material/datepicker/z;->C:I

    .line 108
    .line 109
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 110
    .line 111
    .line 112
    const-string v0, "TITLE_TEXT_KEY"

    .line 113
    .line 114
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->D:Ljava/lang/CharSequence;

    .line 115
    .line 116
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 117
    .line 118
    .line 119
    const-string v0, "INPUT_MODE_KEY"

    .line 120
    .line 121
    iget v1, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 122
    .line 123
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 124
    .line 125
    .line 126
    const-string v0, "POSITIVE_BUTTON_TEXT_RES_ID_KEY"

    .line 127
    .line 128
    iget v1, p0, Lcom/google/android/material/datepicker/z;->G:I

    .line 129
    .line 130
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 131
    .line 132
    .line 133
    const-string v0, "POSITIVE_BUTTON_TEXT_KEY"

    .line 134
    .line 135
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->H:Ljava/lang/CharSequence;

    .line 136
    .line 137
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 138
    .line 139
    .line 140
    const-string v0, "POSITIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY"

    .line 141
    .line 142
    iget v1, p0, Lcom/google/android/material/datepicker/z;->I:I

    .line 143
    .line 144
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 145
    .line 146
    .line 147
    const-string v0, "POSITIVE_BUTTON_CONTENT_DESCRIPTION_KEY"

    .line 148
    .line 149
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->J:Ljava/lang/CharSequence;

    .line 150
    .line 151
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 152
    .line 153
    .line 154
    const-string v0, "NEGATIVE_BUTTON_TEXT_RES_ID_KEY"

    .line 155
    .line 156
    iget v1, p0, Lcom/google/android/material/datepicker/z;->K:I

    .line 157
    .line 158
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 159
    .line 160
    .line 161
    const-string v0, "NEGATIVE_BUTTON_TEXT_KEY"

    .line 162
    .line 163
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->L:Ljava/lang/CharSequence;

    .line 164
    .line 165
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 166
    .line 167
    .line 168
    const-string v0, "NEGATIVE_BUTTON_CONTENT_DESCRIPTION_RES_ID_KEY"

    .line 169
    .line 170
    iget v1, p0, Lcom/google/android/material/datepicker/z;->M:I

    .line 171
    .line 172
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 173
    .line 174
    .line 175
    const-string v0, "NEGATIVE_BUTTON_CONTENT_DESCRIPTION_KEY"

    .line 176
    .line 177
    iget-object p0, p0, Lcom/google/android/material/datepicker/z;->N:Ljava/lang/CharSequence;

    .line 178
    .line 179
    invoke-virtual {p1, v0, p0}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 180
    .line 181
    .line 182
    return-void
.end method

.method public final onStart()V
    .locals 12

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/x;->onStart()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Landroidx/fragment/app/x;->o:Landroid/app/Dialog;

    .line 5
    .line 6
    const-string v1, " does not have a Dialog."

    .line 7
    .line 8
    const-string v2, "DialogFragment "

    .line 9
    .line 10
    if-eqz v0, :cond_12

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget-boolean v3, p0, Lcom/google/android/material/datepicker/z;->E:Z

    .line 17
    .line 18
    if-eqz v3, :cond_10

    .line 19
    .line 20
    const/4 v1, -0x1

    .line 21
    invoke-virtual {v0, v1, v1}, Landroid/view/Window;->setLayout(II)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lcom/google/android/material/datepicker/z;->R:Lwq/i;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Landroid/view/Window;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 27
    .line 28
    .line 29
    iget-boolean v1, p0, Lcom/google/android/material/datepicker/z;->T:Z

    .line 30
    .line 31
    if-eqz v1, :cond_0

    .line 32
    .line 33
    goto/16 :goto_9

    .line 34
    .line 35
    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireView()Landroid/view/View;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    const v2, 0x7f0a017c

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    invoke-virtual {v4}, Landroid/view/View;->getBackground()Landroid/graphics/drawable/Drawable;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    instance-of v2, v1, Landroid/graphics/drawable/ColorDrawable;

    .line 51
    .line 52
    const/4 v3, 0x0

    .line 53
    if-eqz v2, :cond_1

    .line 54
    .line 55
    check-cast v1, Landroid/graphics/drawable/ColorDrawable;

    .line 56
    .line 57
    invoke-virtual {v1}, Landroid/graphics/drawable/ColorDrawable;->getColor()I

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    invoke-static {v1}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    goto :goto_0

    .line 66
    :cond_1
    instance-of v2, v1, Landroid/graphics/drawable/ColorStateListDrawable;

    .line 67
    .line 68
    if-eqz v2, :cond_2

    .line 69
    .line 70
    check-cast v1, Landroid/graphics/drawable/ColorStateListDrawable;

    .line 71
    .line 72
    invoke-virtual {v1}, Landroid/graphics/drawable/ColorStateListDrawable;->getColorStateList()Landroid/content/res/ColorStateList;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    goto :goto_0

    .line 77
    :cond_2
    move-object v1, v3

    .line 78
    :goto_0
    if-eqz v1, :cond_3

    .line 79
    .line 80
    invoke-virtual {v1}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    goto :goto_1

    .line 89
    :cond_3
    move-object v1, v3

    .line 90
    :goto_1
    const/4 v2, 0x0

    .line 91
    const/4 v9, 0x1

    .line 92
    if-eqz v1, :cond_5

    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    if-nez v5, :cond_4

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_4
    move v5, v2

    .line 102
    goto :goto_3

    .line 103
    :cond_5
    :goto_2
    move v5, v9

    .line 104
    :goto_3
    invoke-virtual {v0}, Landroid/view/Window;->getContext()Landroid/content/Context;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    const v7, 0x1010031

    .line 109
    .line 110
    .line 111
    invoke-static {v6, v7}, Llp/w9;->c(Landroid/content/Context;I)Landroid/util/TypedValue;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    if-eqz v7, :cond_7

    .line 116
    .line 117
    iget v3, v7, Landroid/util/TypedValue;->resourceId:I

    .line 118
    .line 119
    if-eqz v3, :cond_6

    .line 120
    .line 121
    invoke-virtual {v6, v3}, Landroid/content/Context;->getColor(I)I

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    goto :goto_4

    .line 126
    :cond_6
    iget v3, v7, Landroid/util/TypedValue;->data:I

    .line 127
    .line 128
    :goto_4
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    :cond_7
    if-eqz v3, :cond_8

    .line 133
    .line 134
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    goto :goto_5

    .line 139
    :cond_8
    const/high16 v3, -0x1000000

    .line 140
    .line 141
    :goto_5
    if-eqz v5, :cond_9

    .line 142
    .line 143
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    :cond_9
    invoke-static {v0, v2}, Ljp/pf;->b(Landroid/view/Window;Z)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v0}, Landroid/view/Window;->getContext()Landroid/content/Context;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0}, Landroid/view/Window;->getContext()Landroid/content/Context;

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, v2}, Landroid/view/Window;->setStatusBarColor(I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v0, v2}, Landroid/view/Window;->setNavigationBarColor(I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 163
    .line 164
    .line 165
    move-result v1

    .line 166
    const-wide/high16 v5, 0x3fe0000000000000L    # 0.5

    .line 167
    .line 168
    if-eqz v1, :cond_a

    .line 169
    .line 170
    invoke-static {v1}, Ls5/a;->b(I)D

    .line 171
    .line 172
    .line 173
    move-result-wide v7

    .line 174
    cmpl-double v1, v7, v5

    .line 175
    .line 176
    if-lez v1, :cond_a

    .line 177
    .line 178
    move v1, v9

    .line 179
    goto :goto_6

    .line 180
    :cond_a
    move v1, v2

    .line 181
    :goto_6
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 182
    .line 183
    .line 184
    move-result-object v7

    .line 185
    new-instance v8, Laq/a;

    .line 186
    .line 187
    invoke-direct {v8, v7}, Laq/a;-><init>(Landroid/view/View;)V

    .line 188
    .line 189
    .line 190
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 191
    .line 192
    const/16 v10, 0x1e

    .line 193
    .line 194
    const/16 v11, 0x23

    .line 195
    .line 196
    if-lt v7, v11, :cond_b

    .line 197
    .line 198
    new-instance v7, Ld6/z1;

    .line 199
    .line 200
    invoke-direct {v7, v0, v8}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 201
    .line 202
    .line 203
    goto :goto_7

    .line 204
    :cond_b
    if-lt v7, v10, :cond_c

    .line 205
    .line 206
    new-instance v7, Ld6/y1;

    .line 207
    .line 208
    invoke-direct {v7, v0, v8}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 209
    .line 210
    .line 211
    goto :goto_7

    .line 212
    :cond_c
    new-instance v7, Ld6/x1;

    .line 213
    .line 214
    invoke-direct {v7, v0, v8}, Ld6/x1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 215
    .line 216
    .line 217
    :goto_7
    invoke-virtual {v7, v1}, Ljp/rf;->c(Z)V

    .line 218
    .line 219
    .line 220
    if-eqz v3, :cond_d

    .line 221
    .line 222
    invoke-static {v3}, Ls5/a;->b(I)D

    .line 223
    .line 224
    .line 225
    move-result-wide v7

    .line 226
    cmpl-double v1, v7, v5

    .line 227
    .line 228
    if-lez v1, :cond_d

    .line 229
    .line 230
    move v2, v9

    .line 231
    :cond_d
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    new-instance v3, Laq/a;

    .line 236
    .line 237
    invoke-direct {v3, v1}, Laq/a;-><init>(Landroid/view/View;)V

    .line 238
    .line 239
    .line 240
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 241
    .line 242
    if-lt v1, v11, :cond_e

    .line 243
    .line 244
    new-instance v1, Ld6/z1;

    .line 245
    .line 246
    invoke-direct {v1, v0, v3}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 247
    .line 248
    .line 249
    goto :goto_8

    .line 250
    :cond_e
    if-lt v1, v10, :cond_f

    .line 251
    .line 252
    new-instance v1, Ld6/y1;

    .line 253
    .line 254
    invoke-direct {v1, v0, v3}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 255
    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_f
    new-instance v1, Ld6/x1;

    .line 259
    .line 260
    invoke-direct {v1, v0, v3}, Ld6/x1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 261
    .line 262
    .line 263
    :goto_8
    invoke-virtual {v1, v2}, Ljp/rf;->b(Z)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v4}, Landroid/view/View;->getPaddingTop()I

    .line 267
    .line 268
    .line 269
    move-result v7

    .line 270
    invoke-virtual {v4}, Landroid/view/View;->getPaddingLeft()I

    .line 271
    .line 272
    .line 273
    move-result v6

    .line 274
    invoke-virtual {v4}, Landroid/view/View;->getPaddingRight()I

    .line 275
    .line 276
    .line 277
    move-result v8

    .line 278
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    iget v5, v0, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 283
    .line 284
    new-instance v3, Lcom/google/android/material/datepicker/w;

    .line 285
    .line 286
    invoke-direct/range {v3 .. v8}, Lcom/google/android/material/datepicker/w;-><init>(Landroid/view/View;IIII)V

    .line 287
    .line 288
    .line 289
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 290
    .line 291
    invoke-static {v4, v3}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 292
    .line 293
    .line 294
    iput-boolean v9, p0, Lcom/google/android/material/datepicker/z;->T:Z

    .line 295
    .line 296
    goto :goto_9

    .line 297
    :cond_10
    const/4 v3, -0x2

    .line 298
    invoke-virtual {v0, v3, v3}, Landroid/view/Window;->setLayout(II)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getResources()Landroid/content/res/Resources;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    const v4, 0x7f0703f2

    .line 306
    .line 307
    .line 308
    invoke-virtual {v3, v4}, Landroid/content/res/Resources;->getDimensionPixelOffset(I)I

    .line 309
    .line 310
    .line 311
    move-result v7

    .line 312
    new-instance v3, Landroid/graphics/Rect;

    .line 313
    .line 314
    invoke-direct {v3, v7, v7, v7, v7}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 315
    .line 316
    .line 317
    new-instance v5, Landroid/graphics/drawable/InsetDrawable;

    .line 318
    .line 319
    iget-object v6, p0, Lcom/google/android/material/datepicker/z;->R:Lwq/i;

    .line 320
    .line 321
    move v8, v7

    .line 322
    move v9, v7

    .line 323
    move v10, v7

    .line 324
    invoke-direct/range {v5 .. v10}, Landroid/graphics/drawable/InsetDrawable;-><init>(Landroid/graphics/drawable/Drawable;IIII)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v0, v5}, Landroid/view/Window;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    new-instance v4, Loq/a;

    .line 335
    .line 336
    iget-object v5, p0, Landroidx/fragment/app/x;->o:Landroid/app/Dialog;

    .line 337
    .line 338
    if-eqz v5, :cond_11

    .line 339
    .line 340
    invoke-direct {v4, v5, v3}, Loq/a;-><init>(Landroid/app/Dialog;Landroid/graphics/Rect;)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {v0, v4}, Landroid/view/View;->setOnTouchListener(Landroid/view/View$OnTouchListener;)V

    .line 344
    .line 345
    .line 346
    :goto_9
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/z;->o()V

    .line 347
    .line 348
    .line 349
    return-void

    .line 350
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 351
    .line 352
    new-instance v3, Ljava/lang/StringBuilder;

    .line 353
    .line 354
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 358
    .line 359
    .line 360
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 361
    .line 362
    .line 363
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object p0

    .line 367
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    throw v0

    .line 371
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 372
    .line 373
    new-instance v3, Ljava/lang/StringBuilder;

    .line 374
    .line 375
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 379
    .line 380
    .line 381
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 382
    .line 383
    .line 384
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 385
    .line 386
    .line 387
    move-result-object p0

    .line 388
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    throw v0
.end method

.method public final onStop()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/z;->z:Lcom/google/android/material/datepicker/g0;

    .line 2
    .line 3
    iget-object v0, v0, Lcom/google/android/material/datepicker/g0;->d:Ljava/util/LinkedHashSet;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->clear()V

    .line 6
    .line 7
    .line 8
    invoke-super {p0}, Landroidx/fragment/app/x;->onStop()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final p(Lcom/google/android/material/internal/CheckableImageButton;)V
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/z;->F:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    const v0, 0x7f1207ee

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const v0, 0x7f1207f0

    .line 23
    .line 24
    .line 25
    invoke-virtual {p1, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    :goto_0
    iget-object p0, p0, Lcom/google/android/material/datepicker/z;->Q:Lcom/google/android/material/internal/CheckableImageButton;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method
