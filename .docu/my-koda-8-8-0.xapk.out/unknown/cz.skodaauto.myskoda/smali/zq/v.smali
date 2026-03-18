.class public final Lzq/v;
.super Ld6/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lcom/google/android/material/textfield/TextInputLayout;


# direct methods
.method public constructor <init>(Lcom/google/android/material/textfield/TextInputLayout;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ld6/b;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzq/v;->d:Lcom/google/android/material/textfield/TextInputLayout;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final d(Landroid/view/View;Le6/d;)V
    .locals 13

    .line 1
    iget-object v0, p2, Le6/d;->a:Landroid/view/accessibility/AccessibilityNodeInfo;

    .line 2
    .line 3
    iget-object v1, p0, Ld6/b;->a:Landroid/view/View$AccessibilityDelegate;

    .line 4
    .line 5
    invoke-virtual {v1, p1, v0}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lzq/v;->d:Lcom/google/android/material/textfield/TextInputLayout;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p1, 0x0

    .line 22
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/material/textfield/TextInputLayout;->getHint()Ljava/lang/CharSequence;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {p0}, Lcom/google/android/material/textfield/TextInputLayout;->getError()Ljava/lang/CharSequence;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-virtual {p0}, Lcom/google/android/material/textfield/TextInputLayout;->getPlaceholderText()Ljava/lang/CharSequence;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-virtual {p0}, Lcom/google/android/material/textfield/TextInputLayout;->getCounterMaxLength()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    invoke-virtual {p0}, Lcom/google/android/material/textfield/TextInputLayout;->getCounterOverflowDescription()Ljava/lang/CharSequence;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    iget-boolean v8, p0, Lcom/google/android/material/textfield/TextInputLayout;->H1:Z

    .line 51
    .line 52
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 53
    .line 54
    .line 55
    move-result v9

    .line 56
    if-eqz v9, :cond_2

    .line 57
    .line 58
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 59
    .line 60
    .line 61
    move-result v10

    .line 62
    if-nez v10, :cond_1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    const/4 v10, 0x0

    .line 66
    goto :goto_2

    .line 67
    :cond_2
    :goto_1
    const/4 v10, 0x1

    .line 68
    :goto_2
    if-nez v7, :cond_3

    .line 69
    .line 70
    invoke-interface {v1}, Ljava/lang/CharSequence;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    goto :goto_3

    .line 75
    :cond_3
    const-string v1, ""

    .line 76
    .line 77
    :goto_3
    iget-object v7, p0, Lcom/google/android/material/textfield/TextInputLayout;->e:Lzq/t;

    .line 78
    .line 79
    iget-object v11, v7, Lzq/t;->e:Lm/x0;

    .line 80
    .line 81
    invoke-virtual {v11}, Landroid/view/View;->getVisibility()I

    .line 82
    .line 83
    .line 84
    move-result v12

    .line 85
    if-nez v12, :cond_4

    .line 86
    .line 87
    invoke-virtual {v0, v11}, Landroid/view/accessibility/AccessibilityNodeInfo;->setLabelFor(Landroid/view/View;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v11}, Landroid/view/accessibility/AccessibilityNodeInfo;->setTraversalAfter(Landroid/view/View;)V

    .line 91
    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_4
    iget-object v7, v7, Lzq/t;->g:Lcom/google/android/material/internal/CheckableImageButton;

    .line 95
    .line 96
    invoke-virtual {v0, v7}, Landroid/view/accessibility/AccessibilityNodeInfo;->setTraversalAfter(Landroid/view/View;)V

    .line 97
    .line 98
    .line 99
    :goto_4
    if-nez v6, :cond_5

    .line 100
    .line 101
    invoke-virtual {p2, p1}, Le6/d;->l(Ljava/lang/CharSequence;)V

    .line 102
    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_5
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 106
    .line 107
    .line 108
    move-result v7

    .line 109
    if-nez v7, :cond_6

    .line 110
    .line 111
    invoke-virtual {p2, v1}, Le6/d;->l(Ljava/lang/CharSequence;)V

    .line 112
    .line 113
    .line 114
    if-nez v8, :cond_7

    .line 115
    .line 116
    if-eqz v3, :cond_7

    .line 117
    .line 118
    new-instance v7, Ljava/lang/StringBuilder;

    .line 119
    .line 120
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v8, ", "

    .line 127
    .line 128
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v3

    .line 138
    invoke-virtual {p2, v3}, Le6/d;->l(Ljava/lang/CharSequence;)V

    .line 139
    .line 140
    .line 141
    goto :goto_5

    .line 142
    :cond_6
    if-eqz v3, :cond_7

    .line 143
    .line 144
    invoke-virtual {p2, v3}, Le6/d;->l(Ljava/lang/CharSequence;)V

    .line 145
    .line 146
    .line 147
    :cond_7
    :goto_5
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    if-nez v3, :cond_8

    .line 152
    .line 153
    invoke-virtual {v0, v1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setHintText(Ljava/lang/CharSequence;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v0, v6}, Landroid/view/accessibility/AccessibilityNodeInfo;->setShowingHintText(Z)V

    .line 157
    .line 158
    .line 159
    :cond_8
    if-eqz p1, :cond_9

    .line 160
    .line 161
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 162
    .line 163
    .line 164
    move-result p1

    .line 165
    if-ne p1, v4, :cond_9

    .line 166
    .line 167
    goto :goto_6

    .line 168
    :cond_9
    const/4 v4, -0x1

    .line 169
    :goto_6
    invoke-virtual {v0, v4}, Landroid/view/accessibility/AccessibilityNodeInfo;->setMaxTextLength(I)V

    .line 170
    .line 171
    .line 172
    if-eqz v10, :cond_b

    .line 173
    .line 174
    if-nez v9, :cond_a

    .line 175
    .line 176
    goto :goto_7

    .line 177
    :cond_a
    move-object v2, v5

    .line 178
    :goto_7
    invoke-virtual {v0, v2}, Landroid/view/accessibility/AccessibilityNodeInfo;->setError(Ljava/lang/CharSequence;)V

    .line 179
    .line 180
    .line 181
    :cond_b
    iget-object p1, p0, Lcom/google/android/material/textfield/TextInputLayout;->n:Lzq/p;

    .line 182
    .line 183
    iget-object p1, p1, Lzq/p;->y:Lm/x0;

    .line 184
    .line 185
    if-eqz p1, :cond_c

    .line 186
    .line 187
    invoke-virtual {v0, p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setLabelFor(Landroid/view/View;)V

    .line 188
    .line 189
    .line 190
    :cond_c
    iget-object p0, p0, Lcom/google/android/material/textfield/TextInputLayout;->f:Lzq/l;

    .line 191
    .line 192
    invoke-virtual {p0}, Lzq/l;->b()Lzq/m;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    invoke-virtual {p0, p2}, Lzq/m;->m(Le6/d;)V

    .line 197
    .line 198
    .line 199
    return-void
.end method

.method public final e(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Ld6/b;->e(Landroid/view/View;Landroid/view/accessibility/AccessibilityEvent;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lzq/v;->d:Lcom/google/android/material/textfield/TextInputLayout;

    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/material/textfield/TextInputLayout;->f:Lzq/l;

    .line 7
    .line 8
    invoke-virtual {p0}, Lzq/l;->b()Lzq/m;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0, p2}, Lzq/m;->n(Landroid/view/accessibility/AccessibilityEvent;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
