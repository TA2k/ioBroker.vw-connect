.class public final Lcom/google/android/material/datepicker/r;
.super Ld6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/android/material/datepicker/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcom/google/android/material/datepicker/r;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ld6/b;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public c(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/r;->d:I

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
    iget-object p0, p0, Lcom/google/android/material/datepicker/r;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lcom/google/android/material/internal/CheckableImageButton;

    .line 16
    .line 17
    iget-boolean p0, p0, Lcom/google/android/material/internal/CheckableImageButton;->g:Z

    .line 18
    .line 19
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityRecord;->setChecked(Z)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Landroid/view/View;Le6/d;)V
    .locals 9

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/r;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/android/material/datepicker/r;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iget-object p0, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object p2, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 11
    .line 12
    invoke-virtual {p0, p1, p2}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 13
    .line 14
    .line 15
    check-cast v1, Lcom/google/android/material/internal/NavigationMenuItemView;

    .line 16
    .line 17
    iget-boolean p0, v1, Lcom/google/android/material/internal/NavigationMenuItemView;->A:Z

    .line 18
    .line 19
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCheckable(Z)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    iget-object p2, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 24
    .line 25
    invoke-virtual {p0, p1, p2}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 26
    .line 27
    .line 28
    check-cast v1, Lcom/google/android/material/internal/CheckableImageButton;

    .line 29
    .line 30
    iget-boolean p0, v1, Lcom/google/android/material/internal/CheckableImageButton;->h:Z

    .line 31
    .line 32
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCheckable(Z)V

    .line 33
    .line 34
    .line 35
    iget-boolean p0, v1, Lcom/google/android/material/internal/CheckableImageButton;->g:Z

    .line 36
    .line 37
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setChecked(Z)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :pswitch_1
    iget-object p2, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 42
    .line 43
    invoke-virtual {p0, p1, p2}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 44
    .line 45
    .line 46
    check-cast v1, Lcom/google/android/material/button/MaterialButtonToggleGroup;

    .line 47
    .line 48
    sget p0, Lcom/google/android/material/button/MaterialButtonToggleGroup;->t:I

    .line 49
    .line 50
    instance-of p0, p1, Lcom/google/android/material/button/MaterialButton;

    .line 51
    .line 52
    const/4 v0, -0x1

    .line 53
    if-nez p0, :cond_1

    .line 54
    .line 55
    :cond_0
    move v5, v0

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    const/4 p0, 0x0

    .line 58
    move v2, p0

    .line 59
    :goto_0
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getChildCount()I

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-ge p0, v3, :cond_0

    .line 64
    .line 65
    invoke-virtual {v1, p0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    if-ne v3, p1, :cond_2

    .line 70
    .line 71
    move v5, v2

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    invoke-virtual {v1, p0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    instance-of v3, v3, Lcom/google/android/material/button/MaterialButton;

    .line 78
    .line 79
    if-eqz v3, :cond_3

    .line 80
    .line 81
    invoke-virtual {v1, p0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    invoke-virtual {v3}, Landroid/view/View;->getVisibility()I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    const/16 v4, 0x8

    .line 90
    .line 91
    if-eq v3, v4, :cond_3

    .line 92
    .line 93
    add-int/lit8 v2, v2, 0x1

    .line 94
    .line 95
    :cond_3
    add-int/lit8 p0, p0, 0x1

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :goto_1
    check-cast p1, Lcom/google/android/material/button/MaterialButton;

    .line 99
    .line 100
    iget-boolean v8, p1, Lcom/google/android/material/button/MaterialButton;->r:Z

    .line 101
    .line 102
    const/4 v7, 0x0

    .line 103
    const/4 v3, 0x0

    .line 104
    const/4 v4, 0x1

    .line 105
    const/4 v6, 0x1

    .line 106
    invoke-static/range {v3 .. v8}, Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;->obtain(IIIIZZ)Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    invoke-virtual {p2, p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCollectionItemInfo(Landroid/view/accessibility/AccessibilityNodeInfo$CollectionItemInfo;)V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    :pswitch_2
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 115
    .line 116
    invoke-virtual {p0, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 117
    .line 118
    .line 119
    check-cast v1, Lcom/google/android/material/datepicker/u;

    .line 120
    .line 121
    iget-object p0, v1, Lcom/google/android/material/datepicker/u;->p:Landroid/view/View;

    .line 122
    .line 123
    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-nez p0, :cond_4

    .line 128
    .line 129
    const p0, 0x7f1207f1

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, p0}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    goto :goto_2

    .line 137
    :cond_4
    const p0, 0x7f1207ef

    .line 138
    .line 139
    .line 140
    invoke-virtual {v1, p0}, Landroidx/fragment/app/j0;->getString(I)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    :goto_2
    new-instance p1, Le6/c;

    .line 145
    .line 146
    const/16 v0, 0x10

    .line 147
    .line 148
    invoke-direct {p1, v0, p0}, Le6/c;-><init>(ILjava/lang/String;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {p2, p1}, Le6/d;->b(Le6/c;)V

    .line 152
    .line 153
    .line 154
    return-void

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
