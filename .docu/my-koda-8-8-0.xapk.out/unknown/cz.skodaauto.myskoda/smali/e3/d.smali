.class public final Le3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Le3/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le3/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private final a(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final b(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final c(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final d(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final e(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method private final f(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 1

    .line 1
    iget v0, p0, Le3/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lzq/l;

    .line 9
    .line 10
    iget-object p1, p0, Lzq/l;->w:Landroid/view/accessibility/AccessibilityManager;

    .line 11
    .line 12
    iget-object v0, p0, Lzq/l;->x:Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lzq/l;->x:Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;

    .line 25
    .line 26
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityManager;->addTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 27
    .line 28
    .line 29
    :cond_0
    :pswitch_0
    return-void

    .line 30
    :pswitch_1
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lw3/z;

    .line 33
    .line 34
    iget-object p1, p0, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 35
    .line 36
    const/4 v0, -0x1

    .line 37
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityManager;->getEnabledAccessibilityServiceList(I)Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    iput-object v0, p0, Lw3/z;->k:Ljava/util/List;

    .line 42
    .line 43
    iget-object v0, p0, Lw3/z;->i:Lw3/u;

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityManager;->addAccessibilityStateChangeListener(Landroid/view/accessibility/AccessibilityManager$AccessibilityStateChangeListener;)Z

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lw3/z;->j:Lw3/v;

    .line 49
    .line 50
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityManager;->addTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 51
    .line 52
    .line 53
    :pswitch_2
    return-void

    .line 54
    :pswitch_3
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p0, Le3/e;

    .line 57
    .line 58
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iget-boolean v0, p0, Le3/e;->c:Z

    .line 63
    .line 64
    if-nez v0, :cond_1

    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iget-object v0, p0, Le3/e;->d:Le3/c;

    .line 71
    .line 72
    invoke-virtual {p1, v0}, Landroid/content/Context;->registerComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 73
    .line 74
    .line 75
    const/4 p1, 0x1

    .line 76
    iput-boolean p1, p0, Le3/e;->c:Z

    .line 77
    .line 78
    :cond_1
    return-void

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 3

    .line 1
    iget v0, p0, Le3/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lzq/l;

    .line 9
    .line 10
    iget-object p1, p0, Lzq/l;->x:Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Lzq/l;->w:Landroid/view/accessibility/AccessibilityManager;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Landroid/view/accessibility/AccessibilityManager;->removeTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :pswitch_0
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lvy0/x1;

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    invoke-virtual {p0, p1}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_1
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lw3/a;

    .line 37
    .line 38
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    sget-object v0, Ld6/u0;->d:Ld6/u0;

    .line 43
    .line 44
    invoke-static {p1, v0}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-interface {p1}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    const/4 v1, 0x0

    .line 57
    if-eqz v0, :cond_4

    .line 58
    .line 59
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    check-cast v0, Landroid/view/ViewParent;

    .line 64
    .line 65
    instance-of v2, v0, Landroid/view/View;

    .line 66
    .line 67
    if-eqz v2, :cond_1

    .line 68
    .line 69
    check-cast v0, Landroid/view/View;

    .line 70
    .line 71
    const-string v2, "<this>"

    .line 72
    .line 73
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const v2, 0x7f0a01a1

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0, v2}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    instance-of v2, v0, Ljava/lang/Boolean;

    .line 84
    .line 85
    if-eqz v2, :cond_2

    .line 86
    .line 87
    check-cast v0, Ljava/lang/Boolean;

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_2
    const/4 v0, 0x0

    .line 91
    :goto_0
    if-eqz v0, :cond_3

    .line 92
    .line 93
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    :cond_3
    if-eqz v1, :cond_1

    .line 98
    .line 99
    const/4 v1, 0x1

    .line 100
    :cond_4
    if-nez v1, :cond_5

    .line 101
    .line 102
    invoke-virtual {p0}, Lw3/a;->d()V

    .line 103
    .line 104
    .line 105
    :cond_5
    return-void

    .line 106
    :pswitch_2
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast p0, Lw3/z;

    .line 109
    .line 110
    iget-object p1, p0, Lw3/z;->l:Landroid/os/Handler;

    .line 111
    .line 112
    iget-object v0, p0, Lw3/z;->N:Lm8/o;

    .line 113
    .line 114
    invoke-virtual {p1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 115
    .line 116
    .line 117
    iget-object p1, p0, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 118
    .line 119
    iget-object v0, p0, Lw3/z;->i:Lw3/u;

    .line 120
    .line 121
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityManager;->removeAccessibilityStateChangeListener(Landroid/view/accessibility/AccessibilityManager$AccessibilityStateChangeListener;)Z

    .line 122
    .line 123
    .line 124
    iget-object p0, p0, Lw3/z;->j:Lw3/v;

    .line 125
    .line 126
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityManager;->removeTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 127
    .line 128
    .line 129
    return-void

    .line 130
    :pswitch_3
    iget-object v0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v0, Ll/c0;

    .line 133
    .line 134
    iget-object v1, v0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 135
    .line 136
    if-eqz v1, :cond_7

    .line 137
    .line 138
    invoke-virtual {v1}, Landroid/view/ViewTreeObserver;->isAlive()Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_6

    .line 143
    .line 144
    invoke-virtual {p1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    iput-object v1, v0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 149
    .line 150
    :cond_6
    iget-object v1, v0, Ll/c0;->r:Landroid/view/ViewTreeObserver;

    .line 151
    .line 152
    iget-object v0, v0, Ll/c0;->l:Ll/d;

    .line 153
    .line 154
    invoke-virtual {v1, v0}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 155
    .line 156
    .line 157
    :cond_7
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 158
    .line 159
    .line 160
    return-void

    .line 161
    :pswitch_4
    iget-object v0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast v0, Ll/f;

    .line 164
    .line 165
    iget-object v1, v0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 166
    .line 167
    if-eqz v1, :cond_9

    .line 168
    .line 169
    invoke-virtual {v1}, Landroid/view/ViewTreeObserver;->isAlive()Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    if-nez v1, :cond_8

    .line 174
    .line 175
    invoke-virtual {p1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    iput-object v1, v0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 180
    .line 181
    :cond_8
    iget-object v1, v0, Ll/f;->A:Landroid/view/ViewTreeObserver;

    .line 182
    .line 183
    iget-object v0, v0, Ll/f;->l:Ll/d;

    .line 184
    .line 185
    invoke-virtual {v1, v0}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 186
    .line 187
    .line 188
    :cond_9
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :pswitch_5
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast p0, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;

    .line 195
    .line 196
    iget-object p1, p0, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;->c:Lgq/a;

    .line 197
    .line 198
    if-eqz p1, :cond_a

    .line 199
    .line 200
    iget-object v0, p0, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;->b:Landroid/view/accessibility/AccessibilityManager;

    .line 201
    .line 202
    if-eqz v0, :cond_a

    .line 203
    .line 204
    invoke-virtual {v0, p1}, Landroid/view/accessibility/AccessibilityManager;->removeTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 205
    .line 206
    .line 207
    const/4 p1, 0x0

    .line 208
    iput-object p1, p0, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;->c:Lgq/a;

    .line 209
    .line 210
    :cond_a
    return-void

    .line 211
    :pswitch_6
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast p0, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;

    .line 214
    .line 215
    iget-object p1, p0, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;->h:Lgq/a;

    .line 216
    .line 217
    if-eqz p1, :cond_b

    .line 218
    .line 219
    iget-object v0, p0, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 220
    .line 221
    if-eqz v0, :cond_b

    .line 222
    .line 223
    invoke-virtual {v0, p1}, Landroid/view/accessibility/AccessibilityManager;->removeTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    .line 224
    .line 225
    .line 226
    const/4 p1, 0x0

    .line 227
    iput-object p1, p0, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;->h:Lgq/a;

    .line 228
    .line 229
    :cond_b
    return-void

    .line 230
    :pswitch_7
    iget-object p0, p0, Le3/d;->e:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast p0, Le3/e;

    .line 233
    .line 234
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    iget-boolean v0, p0, Le3/e;->c:Z

    .line 239
    .line 240
    if-eqz v0, :cond_c

    .line 241
    .line 242
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 243
    .line 244
    .line 245
    move-result-object p1

    .line 246
    iget-object v0, p0, Le3/e;->d:Le3/c;

    .line 247
    .line 248
    invoke-virtual {p1, v0}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 249
    .line 250
    .line 251
    const/4 p1, 0x0

    .line 252
    iput-boolean p1, p0, Le3/e;->c:Z

    .line 253
    .line 254
    :cond_c
    return-void

    .line 255
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
.end method
