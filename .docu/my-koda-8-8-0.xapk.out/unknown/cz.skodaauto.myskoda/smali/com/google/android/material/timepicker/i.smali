.class public final Lcom/google/android/material/timepicker/i;
.super Landroidx/fragment/app/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Lcom/google/android/material/timepicker/t;

.field public B:Ljava/lang/Object;

.field public C:I

.field public D:I

.field public E:I

.field public F:Ljava/lang/CharSequence;

.field public G:I

.field public H:Ljava/lang/CharSequence;

.field public I:I

.field public J:Ljava/lang/CharSequence;

.field public K:Lcom/google/android/material/button/MaterialButton;

.field public L:Landroid/widget/Button;

.field public M:I

.field public N:Lcom/google/android/material/timepicker/l;

.field public O:I

.field public final t:Ljava/util/LinkedHashSet;

.field public final u:Ljava/util/LinkedHashSet;

.field public final v:Ljava/util/LinkedHashSet;

.field public final w:Ljava/util/LinkedHashSet;

.field public x:Lcom/google/android/material/timepicker/TimePickerView;

.field public y:Landroid/view/ViewStub;

.field public z:Lcom/google/android/material/timepicker/n;


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
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->t:Ljava/util/LinkedHashSet;

    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->u:Ljava/util/LinkedHashSet;

    .line 17
    .line 18
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->v:Ljava/util/LinkedHashSet;

    .line 24
    .line 25
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->w:Ljava/util/LinkedHashSet;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    iput v0, p0, Lcom/google/android/material/timepicker/i;->E:I

    .line 34
    .line 35
    iput v0, p0, Lcom/google/android/material/timepicker/i;->G:I

    .line 36
    .line 37
    iput v0, p0, Lcom/google/android/material/timepicker/i;->I:I

    .line 38
    .line 39
    iput v0, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 40
    .line 41
    iput v0, p0, Lcom/google/android/material/timepicker/i;->O:I

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final j()Landroid/app/Dialog;
    .locals 8

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
    iget v2, p0, Lcom/google/android/material/timepicker/i;->O:I

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->requireContext()Landroid/content/Context;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const v4, 0x7f0403a1

    .line 18
    .line 19
    .line 20
    invoke-static {v2, v4}, Llp/w9;->c(Landroid/content/Context;I)Landroid/util/TypedValue;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    move v2, v3

    .line 27
    goto :goto_0

    .line 28
    :cond_1
    iget v2, v2, Landroid/util/TypedValue;->data:I

    .line 29
    .line 30
    :goto_0
    invoke-direct {v0, v1, v2}, Landroid/app/Dialog;-><init>(Landroid/content/Context;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v2, Lwq/i;

    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    const v5, 0x7f0403a0

    .line 41
    .line 42
    .line 43
    const v6, 0x7f130561

    .line 44
    .line 45
    .line 46
    invoke-direct {v2, v1, v4, v5, v6}, Lwq/i;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    .line 47
    .line 48
    .line 49
    sget-object v7, Ldq/a;->v:[I

    .line 50
    .line 51
    invoke-virtual {v1, v4, v7, v5, v6}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    const/4 v5, 0x1

    .line 56
    invoke-virtual {v4, v5, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 57
    .line 58
    .line 59
    move-result v6

    .line 60
    iput v6, p0, Lcom/google/android/material/timepicker/i;->D:I

    .line 61
    .line 62
    const/4 v6, 0x2

    .line 63
    invoke-virtual {v4, v6, v3}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 64
    .line 65
    .line 66
    move-result v6

    .line 67
    iput v6, p0, Lcom/google/android/material/timepicker/i;->C:I

    .line 68
    .line 69
    invoke-virtual {v4, v3, v3}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2, v1}, Lwq/i;->j(Landroid/content/Context;)V

    .line 77
    .line 78
    .line 79
    invoke-static {p0}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {v2, p0}, Lwq/i;->m(Landroid/content/res/ColorStateList;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-virtual {p0, v2}, Landroid/view/Window;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0, v5}, Landroid/view/Window;->requestFeature(I)Z

    .line 94
    .line 95
    .line 96
    const/4 v1, -0x2

    .line 97
    invoke-virtual {p0, v1, v1}, Landroid/view/Window;->setLayout(II)V

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-virtual {p0}, Landroid/view/View;->getElevation()F

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    invoke-virtual {v2, p0}, Lwq/i;->l(F)V

    .line 109
    .line 110
    .line 111
    return-object v0
.end method

.method public final l(Lcom/google/android/material/button/MaterialButton;)V
    .locals 3

    .line 1
    if-eqz p1, :cond_7

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->x:Lcom/google/android/material/timepicker/TimePickerView;

    .line 4
    .line 5
    if-eqz v0, :cond_7

    .line 6
    .line 7
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->y:Landroid/view/ViewStub;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto/16 :goto_2

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->B:Ljava/lang/Object;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Lcom/google/android/material/timepicker/o;->c()V

    .line 18
    .line 19
    .line 20
    :cond_1
    iget v0, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 21
    .line 22
    iget-object v1, p0, Lcom/google/android/material/timepicker/i;->x:Lcom/google/android/material/timepicker/TimePickerView;

    .line 23
    .line 24
    iget-object v2, p0, Lcom/google/android/material/timepicker/i;->y:Landroid/view/ViewStub;

    .line 25
    .line 26
    if-nez v0, :cond_3

    .line 27
    .line 28
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->z:Lcom/google/android/material/timepicker/n;

    .line 29
    .line 30
    if-nez v0, :cond_2

    .line 31
    .line 32
    new-instance v0, Lcom/google/android/material/timepicker/n;

    .line 33
    .line 34
    iget-object v2, p0, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 35
    .line 36
    invoke-direct {v0, v1, v2}, Lcom/google/android/material/timepicker/n;-><init>(Lcom/google/android/material/timepicker/TimePickerView;Lcom/google/android/material/timepicker/l;)V

    .line 37
    .line 38
    .line 39
    :cond_2
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->z:Lcom/google/android/material/timepicker/n;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_3
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->A:Lcom/google/android/material/timepicker/t;

    .line 43
    .line 44
    if-nez v0, :cond_4

    .line 45
    .line 46
    invoke-virtual {v2}, Landroid/view/ViewStub;->inflate()Landroid/view/View;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Landroid/widget/LinearLayout;

    .line 51
    .line 52
    new-instance v1, Lcom/google/android/material/timepicker/t;

    .line 53
    .line 54
    iget-object v2, p0, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 55
    .line 56
    invoke-direct {v1, v0, v2}, Lcom/google/android/material/timepicker/t;-><init>(Landroid/widget/LinearLayout;Lcom/google/android/material/timepicker/l;)V

    .line 57
    .line 58
    .line 59
    iput-object v1, p0, Lcom/google/android/material/timepicker/i;->A:Lcom/google/android/material/timepicker/t;

    .line 60
    .line 61
    :cond_4
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->A:Lcom/google/android/material/timepicker/t;

    .line 62
    .line 63
    iget-object v1, v0, Lcom/google/android/material/timepicker/t;->h:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    invoke-virtual {v1, v2}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 67
    .line 68
    .line 69
    iget-object v0, v0, Lcom/google/android/material/timepicker/t;->i:Lcom/google/android/material/timepicker/ChipTextInputComboView;

    .line 70
    .line 71
    invoke-virtual {v0, v2}, Lcom/google/android/material/timepicker/ChipTextInputComboView;->setChecked(Z)V

    .line 72
    .line 73
    .line 74
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->A:Lcom/google/android/material/timepicker/t;

    .line 75
    .line 76
    :goto_0
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->B:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-interface {v0}, Lcom/google/android/material/timepicker/o;->b()V

    .line 79
    .line 80
    .line 81
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->B:Ljava/lang/Object;

    .line 82
    .line 83
    invoke-interface {v0}, Lcom/google/android/material/timepicker/o;->invalidate()V

    .line 84
    .line 85
    .line 86
    iget v0, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 87
    .line 88
    if-eqz v0, :cond_6

    .line 89
    .line 90
    const/4 v1, 0x1

    .line 91
    if-ne v0, v1, :cond_5

    .line 92
    .line 93
    new-instance v0, Landroid/util/Pair;

    .line 94
    .line 95
    iget v1, p0, Lcom/google/android/material/timepicker/i;->D:I

    .line 96
    .line 97
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    const v2, 0x7f120724

    .line 102
    .line 103
    .line 104
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    invoke-direct {v0, v1, v2}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 113
    .line 114
    const-string p1, "no icon for mode: "

    .line 115
    .line 116
    invoke-static {v0, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_6
    new-instance v0, Landroid/util/Pair;

    .line 125
    .line 126
    iget v1, p0, Lcom/google/android/material/timepicker/i;->C:I

    .line 127
    .line 128
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    const v2, 0x7f120729

    .line 133
    .line 134
    .line 135
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    invoke-direct {v0, v1, v2}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    :goto_1
    iget-object v1, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v1, Ljava/lang/Integer;

    .line 145
    .line 146
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    invoke-virtual {p1, v1}, Lcom/google/android/material/button/MaterialButton;->setIconResource(I)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0}, Landroidx/fragment/app/j0;->getResources()Landroid/content/res/Resources;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v0, Ljava/lang/Integer;

    .line 160
    .line 161
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    invoke-virtual {p0, v0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    invoke-virtual {p1, p0}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 170
    .line 171
    .line 172
    const/4 p0, 0x4

    .line 173
    invoke-virtual {p1, p0}, Landroid/view/View;->sendAccessibilityEvent(I)V

    .line 174
    .line 175
    .line 176
    :cond_7
    :goto_2
    return-void
.end method

.method public final onCancel(Landroid/content/DialogInterface;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/material/timepicker/i;->v:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

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
    if-nez p1, :cond_1

    .line 11
    .line 12
    return-void

    .line 13
    :cond_1
    const-string v0, "TIME_PICKER_TIME_MODEL"

    .line 14
    .line 15
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lcom/google/android/material/timepicker/l;

    .line 20
    .line 21
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    if-nez v0, :cond_2

    .line 25
    .line 26
    new-instance v0, Lcom/google/android/material/timepicker/l;

    .line 27
    .line 28
    invoke-direct {v0, v1}, Lcom/google/android/material/timepicker/l;-><init>(I)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 32
    .line 33
    :cond_2
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 34
    .line 35
    iget v0, v0, Lcom/google/android/material/timepicker/l;->f:I

    .line 36
    .line 37
    const/4 v2, 0x1

    .line 38
    if-ne v0, v2, :cond_3

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_3
    move v2, v1

    .line 42
    :goto_0
    const-string v0, "TIME_PICKER_INPUT_MODE"

    .line 43
    .line 44
    invoke-virtual {p1, v0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iput v0, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 49
    .line 50
    const-string v0, "TIME_PICKER_TITLE_RES"

    .line 51
    .line 52
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iput v0, p0, Lcom/google/android/material/timepicker/i;->E:I

    .line 57
    .line 58
    const-string v0, "TIME_PICKER_TITLE_TEXT"

    .line 59
    .line 60
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->F:Ljava/lang/CharSequence;

    .line 65
    .line 66
    const-string v0, "TIME_PICKER_POSITIVE_BUTTON_TEXT_RES"

    .line 67
    .line 68
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iput v0, p0, Lcom/google/android/material/timepicker/i;->G:I

    .line 73
    .line 74
    const-string v0, "TIME_PICKER_POSITIVE_BUTTON_TEXT"

    .line 75
    .line 76
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->H:Ljava/lang/CharSequence;

    .line 81
    .line 82
    const-string v0, "TIME_PICKER_NEGATIVE_BUTTON_TEXT_RES"

    .line 83
    .line 84
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    iput v0, p0, Lcom/google/android/material/timepicker/i;->I:I

    .line 89
    .line 90
    const-string v0, "TIME_PICKER_NEGATIVE_BUTTON_TEXT"

    .line 91
    .line 92
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->J:Ljava/lang/CharSequence;

    .line 97
    .line 98
    const-string v0, "TIME_PICKER_OVERRIDE_THEME_RES_ID"

    .line 99
    .line 100
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    iput p1, p0, Lcom/google/android/material/timepicker/i;->O:I

    .line 105
    .line 106
    return-void
.end method

.method public final onCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;
    .locals 1

    .line 1
    const p3, 0x7f0d02a2

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1, p3, p2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    check-cast p1, Landroid/view/ViewGroup;

    .line 9
    .line 10
    const p2, 0x7f0a01cb

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    check-cast p2, Lcom/google/android/material/timepicker/TimePickerView;

    .line 18
    .line 19
    iput-object p2, p0, Lcom/google/android/material/timepicker/i;->x:Lcom/google/android/material/timepicker/TimePickerView;

    .line 20
    .line 21
    iput-object p0, p2, Lcom/google/android/material/timepicker/TimePickerView;->k:Lcom/google/android/material/timepicker/i;

    .line 22
    .line 23
    const p2, 0x7f0a01c6

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 27
    .line 28
    .line 29
    move-result-object p2

    .line 30
    check-cast p2, Landroid/view/ViewStub;

    .line 31
    .line 32
    iput-object p2, p0, Lcom/google/android/material/timepicker/i;->y:Landroid/view/ViewStub;

    .line 33
    .line 34
    const p2, 0x7f0a01c9

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Lcom/google/android/material/button/MaterialButton;

    .line 42
    .line 43
    iput-object p2, p0, Lcom/google/android/material/timepicker/i;->K:Lcom/google/android/material/button/MaterialButton;

    .line 44
    .line 45
    const p2, 0x7f0a0188

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    check-cast p2, Landroid/widget/TextView;

    .line 53
    .line 54
    iget p3, p0, Lcom/google/android/material/timepicker/i;->E:I

    .line 55
    .line 56
    if-eqz p3, :cond_0

    .line 57
    .line 58
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(I)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    iget-object p3, p0, Lcom/google/android/material/timepicker/i;->F:Ljava/lang/CharSequence;

    .line 63
    .line 64
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 65
    .line 66
    .line 67
    move-result p3

    .line 68
    if-nez p3, :cond_1

    .line 69
    .line 70
    iget-object p3, p0, Lcom/google/android/material/timepicker/i;->F:Ljava/lang/CharSequence;

    .line 71
    .line 72
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 73
    .line 74
    .line 75
    :cond_1
    :goto_0
    iget-object p2, p0, Lcom/google/android/material/timepicker/i;->K:Lcom/google/android/material/button/MaterialButton;

    .line 76
    .line 77
    invoke-virtual {p0, p2}, Lcom/google/android/material/timepicker/i;->l(Lcom/google/android/material/button/MaterialButton;)V

    .line 78
    .line 79
    .line 80
    const p2, 0x7f0a01ca

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    check-cast p2, Landroid/widget/Button;

    .line 88
    .line 89
    new-instance p3, Lcom/google/android/material/timepicker/h;

    .line 90
    .line 91
    const/4 v0, 0x0

    .line 92
    invoke-direct {p3, p0, v0}, Lcom/google/android/material/timepicker/h;-><init>(Lcom/google/android/material/timepicker/i;I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p2, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 96
    .line 97
    .line 98
    iget p3, p0, Lcom/google/android/material/timepicker/i;->G:I

    .line 99
    .line 100
    if-eqz p3, :cond_2

    .line 101
    .line 102
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(I)V

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_2
    iget-object p3, p0, Lcom/google/android/material/timepicker/i;->H:Ljava/lang/CharSequence;

    .line 107
    .line 108
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 109
    .line 110
    .line 111
    move-result p3

    .line 112
    if-nez p3, :cond_3

    .line 113
    .line 114
    iget-object p3, p0, Lcom/google/android/material/timepicker/i;->H:Ljava/lang/CharSequence;

    .line 115
    .line 116
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 117
    .line 118
    .line 119
    :cond_3
    :goto_1
    const p2, 0x7f0a01c7

    .line 120
    .line 121
    .line 122
    invoke-virtual {p1, p2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    check-cast p2, Landroid/widget/Button;

    .line 127
    .line 128
    iput-object p2, p0, Lcom/google/android/material/timepicker/i;->L:Landroid/widget/Button;

    .line 129
    .line 130
    new-instance p3, Lcom/google/android/material/timepicker/h;

    .line 131
    .line 132
    const/4 v0, 0x1

    .line 133
    invoke-direct {p3, p0, v0}, Lcom/google/android/material/timepicker/h;-><init>(Lcom/google/android/material/timepicker/i;I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p2, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 137
    .line 138
    .line 139
    iget p2, p0, Lcom/google/android/material/timepicker/i;->I:I

    .line 140
    .line 141
    if-eqz p2, :cond_4

    .line 142
    .line 143
    iget-object p3, p0, Lcom/google/android/material/timepicker/i;->L:Landroid/widget/Button;

    .line 144
    .line 145
    invoke-virtual {p3, p2}, Landroid/widget/TextView;->setText(I)V

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_4
    iget-object p2, p0, Lcom/google/android/material/timepicker/i;->J:Ljava/lang/CharSequence;

    .line 150
    .line 151
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 152
    .line 153
    .line 154
    move-result p2

    .line 155
    if-nez p2, :cond_5

    .line 156
    .line 157
    iget-object p2, p0, Lcom/google/android/material/timepicker/i;->L:Landroid/widget/Button;

    .line 158
    .line 159
    iget-object p3, p0, Lcom/google/android/material/timepicker/i;->J:Ljava/lang/CharSequence;

    .line 160
    .line 161
    invoke-virtual {p2, p3}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 162
    .line 163
    .line 164
    :cond_5
    :goto_2
    iget-object p2, p0, Lcom/google/android/material/timepicker/i;->L:Landroid/widget/Button;

    .line 165
    .line 166
    if-eqz p2, :cond_7

    .line 167
    .line 168
    iget-boolean p3, p0, Landroidx/fragment/app/x;->j:Z

    .line 169
    .line 170
    if-eqz p3, :cond_6

    .line 171
    .line 172
    const/4 p3, 0x0

    .line 173
    goto :goto_3

    .line 174
    :cond_6
    const/16 p3, 0x8

    .line 175
    .line 176
    :goto_3
    invoke-virtual {p2, p3}, Landroid/view/View;->setVisibility(I)V

    .line 177
    .line 178
    .line 179
    :cond_7
    iget-object p2, p0, Lcom/google/android/material/timepicker/i;->K:Lcom/google/android/material/button/MaterialButton;

    .line 180
    .line 181
    new-instance p3, Lcom/google/android/material/timepicker/h;

    .line 182
    .line 183
    const/4 v0, 0x2

    .line 184
    invoke-direct {p3, p0, v0}, Lcom/google/android/material/timepicker/h;-><init>(Lcom/google/android/material/timepicker/i;I)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p2, p3}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 188
    .line 189
    .line 190
    return-object p1
.end method

.method public final onDestroyView()V
    .locals 2

    .line 1
    invoke-super {p0}, Landroidx/fragment/app/x;->onDestroyView()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->B:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->z:Lcom/google/android/material/timepicker/n;

    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->A:Lcom/google/android/material/timepicker/t;

    .line 10
    .line 11
    iget-object v1, p0, Lcom/google/android/material/timepicker/i;->x:Lcom/google/android/material/timepicker/TimePickerView;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iput-object v0, v1, Lcom/google/android/material/timepicker/TimePickerView;->k:Lcom/google/android/material/timepicker/i;

    .line 16
    .line 17
    iput-object v0, p0, Lcom/google/android/material/timepicker/i;->x:Lcom/google/android/material/timepicker/TimePickerView;

    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public final onDismiss(Landroid/content/DialogInterface;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/i;->w:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

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
    invoke-super {p0, p1}, Landroidx/fragment/app/x;->onDismiss(Landroid/content/DialogInterface;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final onSaveInstanceState(Landroid/os/Bundle;)V
    .locals 2

    .line 1
    invoke-super {p0, p1}, Landroidx/fragment/app/x;->onSaveInstanceState(Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    const-string v0, "TIME_PICKER_TIME_MODEL"

    .line 5
    .line 6
    iget-object v1, p0, Lcom/google/android/material/timepicker/i;->N:Lcom/google/android/material/timepicker/l;

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "TIME_PICKER_INPUT_MODE"

    .line 12
    .line 13
    iget v1, p0, Lcom/google/android/material/timepicker/i;->M:I

    .line 14
    .line 15
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 16
    .line 17
    .line 18
    const-string v0, "TIME_PICKER_TITLE_RES"

    .line 19
    .line 20
    iget v1, p0, Lcom/google/android/material/timepicker/i;->E:I

    .line 21
    .line 22
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    const-string v0, "TIME_PICKER_TITLE_TEXT"

    .line 26
    .line 27
    iget-object v1, p0, Lcom/google/android/material/timepicker/i;->F:Ljava/lang/CharSequence;

    .line 28
    .line 29
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 30
    .line 31
    .line 32
    const-string v0, "TIME_PICKER_POSITIVE_BUTTON_TEXT_RES"

    .line 33
    .line 34
    iget v1, p0, Lcom/google/android/material/timepicker/i;->G:I

    .line 35
    .line 36
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    const-string v0, "TIME_PICKER_POSITIVE_BUTTON_TEXT"

    .line 40
    .line 41
    iget-object v1, p0, Lcom/google/android/material/timepicker/i;->H:Ljava/lang/CharSequence;

    .line 42
    .line 43
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 44
    .line 45
    .line 46
    const-string v0, "TIME_PICKER_NEGATIVE_BUTTON_TEXT_RES"

    .line 47
    .line 48
    iget v1, p0, Lcom/google/android/material/timepicker/i;->I:I

    .line 49
    .line 50
    invoke-virtual {p1, v0, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 51
    .line 52
    .line 53
    const-string v0, "TIME_PICKER_NEGATIVE_BUTTON_TEXT"

    .line 54
    .line 55
    iget-object v1, p0, Lcom/google/android/material/timepicker/i;->J:Ljava/lang/CharSequence;

    .line 56
    .line 57
    invoke-virtual {p1, v0, v1}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 58
    .line 59
    .line 60
    const-string v0, "TIME_PICKER_OVERRIDE_THEME_RES_ID"

    .line 61
    .line 62
    iget p0, p0, Lcom/google/android/material/timepicker/i;->O:I

    .line 63
    .line 64
    invoke-virtual {p1, v0, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public final onViewCreated(Landroid/view/View;Landroid/os/Bundle;)V
    .locals 2

    .line 1
    invoke-super {p0, p1, p2}, Landroidx/fragment/app/j0;->onViewCreated(Landroid/view/View;Landroid/os/Bundle;)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lcom/google/android/material/timepicker/i;->B:Ljava/lang/Object;

    .line 5
    .line 6
    instance-of p2, p2, Lcom/google/android/material/timepicker/t;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    new-instance p2, Lcom/google/android/material/timepicker/g;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-direct {p2, p0, v0}, Lcom/google/android/material/timepicker/g;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    const-wide/16 v0, 0x64

    .line 17
    .line 18
    invoke-virtual {p1, p2, v0, v1}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method
