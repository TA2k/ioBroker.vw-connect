.class public final Lcom/google/android/material/datepicker/o;
.super Ld6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/material/datepicker/o;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ld6/b;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public c(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Ld6/b;->c(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    invoke-super {p0, p1, p2}, Ld6/b;->c(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)V

    .line 11
    .line 12
    .line 13
    check-cast p1, Landroidx/core/widget/NestedScrollView;

    .line 14
    .line 15
    const-class p0, Landroid/widget/ScrollView;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setClassName(Ljava/lang/CharSequence;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-lez p0, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    :goto_0
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setScrollable(Z)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Landroid/view/View;->getScrollX()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setScrollX(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setScrollY(I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1}, Landroid/view/View;->getScrollX()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setMaxScrollX(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setMaxScrollY(I)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Landroid/view/View;Le6/d;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p2, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 7
    .line 8
    iget-object p0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setVisibleToUser(Z)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_0
    iget-object p0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 19
    .line 20
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 21
    .line 22
    invoke-virtual {p0, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 23
    .line 24
    .line 25
    check-cast p1, Landroidx/core/widget/NestedScrollView;

    .line 26
    .line 27
    const-class p0, Landroid/widget/ScrollView;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p2, p0}, Le6/d;->h(Ljava/lang/CharSequence;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Landroid/view/View;->isEnabled()Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-eqz p0, :cond_1

    .line 41
    .line 42
    invoke-virtual {p1}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-lez p0, :cond_1

    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    invoke-virtual {p2, v0}, Le6/d;->k(Z)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-lez v0, :cond_0

    .line 57
    .line 58
    sget-object v0, Le6/c;->i:Le6/c;

    .line 59
    .line 60
    invoke-virtual {p2, v0}, Le6/d;->b(Le6/c;)V

    .line 61
    .line 62
    .line 63
    sget-object v0, Le6/c;->m:Le6/c;

    .line 64
    .line 65
    invoke-virtual {p2, v0}, Le6/d;->b(Le6/c;)V

    .line 66
    .line 67
    .line 68
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-ge p1, p0, :cond_1

    .line 73
    .line 74
    sget-object p0, Le6/c;->h:Le6/c;

    .line 75
    .line 76
    invoke-virtual {p2, p0}, Le6/d;->b(Le6/c;)V

    .line 77
    .line 78
    .line 79
    sget-object p0, Le6/c;->o:Le6/c;

    .line 80
    .line 81
    invoke-virtual {p2, p0}, Le6/d;->b(Le6/c;)V

    .line 82
    .line 83
    .line 84
    :cond_1
    return-void

    .line 85
    :pswitch_1
    iget-object p0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 86
    .line 87
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 88
    .line 89
    invoke-virtual {p0, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x0

    .line 93
    invoke-virtual {p2, p0}, Le6/d;->i(Lkp/c0;)V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :pswitch_2
    iget-object p0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 98
    .line 99
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 100
    .line 101
    invoke-virtual {p0, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 102
    .line 103
    .line 104
    const/4 p0, 0x0

    .line 105
    invoke-virtual {p2, p0}, Le6/d;->k(Z)V

    .line 106
    .line 107
    .line 108
    return-void

    .line 109
    :pswitch_3
    iget-object p0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 110
    .line 111
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 112
    .line 113
    invoke-virtual {p0, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 114
    .line 115
    .line 116
    const/4 p0, 0x0

    .line 117
    invoke-virtual {p2, p0}, Le6/d;->i(Lkp/c0;)V

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public g(Landroid/view/View;ILandroid/os/Bundle;)Z
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3}, Ld6/b;->g(Landroid/view/View;ILandroid/os/Bundle;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    invoke-super {p0, p1, p2, p3}, Ld6/b;->g(Landroid/view/View;ILandroid/os/Bundle;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/4 p3, 0x1

    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    goto/16 :goto_1

    .line 19
    .line 20
    :cond_0
    check-cast p1, Landroidx/core/widget/NestedScrollView;

    .line 21
    .line 22
    invoke-virtual {p1}, Landroid/view/View;->isEnabled()Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    const/4 v0, 0x0

    .line 27
    if-nez p0, :cond_1

    .line 28
    .line 29
    goto/16 :goto_0

    .line 30
    .line 31
    :cond_1
    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    new-instance v1, Landroid/graphics/Rect;

    .line 36
    .line 37
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/view/View;->getMatrix()Landroid/graphics/Matrix;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    invoke-virtual {v2}, Landroid/graphics/Matrix;->isIdentity()Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    invoke-virtual {p1, v1}, Landroid/view/View;->getGlobalVisibleRect(Landroid/graphics/Rect;)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-eqz v2, :cond_2

    .line 55
    .line 56
    invoke-virtual {v1}, Landroid/graphics/Rect;->height()I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    :cond_2
    const/16 v1, 0x1000

    .line 61
    .line 62
    if-eq p2, v1, :cond_4

    .line 63
    .line 64
    const/16 v1, 0x2000

    .line 65
    .line 66
    if-eq p2, v1, :cond_3

    .line 67
    .line 68
    const v1, 0x1020038

    .line 69
    .line 70
    .line 71
    if-eq p2, v1, :cond_3

    .line 72
    .line 73
    const v1, 0x102003a

    .line 74
    .line 75
    .line 76
    if-eq p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_3
    invoke-virtual {p1}, Landroid/view/View;->getPaddingBottom()I

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    sub-int/2addr p0, p2

    .line 84
    invoke-virtual {p1}, Landroid/view/View;->getPaddingTop()I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    sub-int/2addr p0, p2

    .line 89
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 90
    .line 91
    .line 92
    move-result p2

    .line 93
    sub-int/2addr p2, p0

    .line 94
    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    if-eq p0, p2, :cond_5

    .line 103
    .line 104
    invoke-virtual {p1}, Landroid/view/View;->getScrollX()I

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    sub-int/2addr v0, p2

    .line 109
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    sub-int/2addr p0, p2

    .line 114
    invoke-virtual {p1, v0, p0, p3}, Landroidx/core/widget/NestedScrollView;->v(IIZ)V

    .line 115
    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_4
    invoke-virtual {p1}, Landroid/view/View;->getPaddingBottom()I

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    sub-int/2addr p0, p2

    .line 123
    invoke-virtual {p1}, Landroid/view/View;->getPaddingTop()I

    .line 124
    .line 125
    .line 126
    move-result p2

    .line 127
    sub-int/2addr p0, p2

    .line 128
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 129
    .line 130
    .line 131
    move-result p2

    .line 132
    add-int/2addr p2, p0

    .line 133
    invoke-virtual {p1}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 134
    .line 135
    .line 136
    move-result p0

    .line 137
    invoke-static {p2, p0}, Ljava/lang/Math;->min(II)I

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 142
    .line 143
    .line 144
    move-result p2

    .line 145
    if-eq p0, p2, :cond_5

    .line 146
    .line 147
    invoke-virtual {p1}, Landroid/view/View;->getScrollX()I

    .line 148
    .line 149
    .line 150
    move-result p2

    .line 151
    sub-int/2addr v0, p2

    .line 152
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    sub-int/2addr p0, p2

    .line 157
    invoke-virtual {p1, v0, p0, p3}, Landroidx/core/widget/NestedScrollView;->v(IIZ)V

    .line 158
    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_5
    :goto_0
    move p3, v0

    .line 162
    :goto_1
    return p3

    .line 163
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method
