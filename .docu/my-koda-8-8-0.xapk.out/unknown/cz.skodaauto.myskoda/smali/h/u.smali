.class public final Lh/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/Window$Callback;


# instance fields
.field public final d:Landroid/view/Window$Callback;

.field public e:Z

.field public f:Z

.field public g:Z

.field public final synthetic h:Lh/z;


# direct methods
.method public constructor <init>(Lh/z;Landroid/view/Window$Callback;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh/u;->h:Lh/z;

    .line 5
    .line 6
    if-eqz p2, :cond_0

    .line 7
    .line 8
    iput-object p2, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 12
    .line 13
    const-string p1, "Window callback may not be null"

    .line 14
    .line 15
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method


# virtual methods
.method public final a(Landroid/view/Window$Callback;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    :try_start_0
    iput-boolean v0, p0, Lh/u;->e:Z

    .line 4
    .line 5
    invoke-interface {p1}, Landroid/view/Window$Callback;->onContentChanged()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    .line 7
    .line 8
    iput-boolean v1, p0, Lh/u;->e:Z

    .line 9
    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p1

    .line 12
    iput-boolean v1, p0, Lh/u;->e:Z

    .line 13
    .line 14
    throw p1
.end method

.method public final b(ILandroid/view/Menu;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final c(ILandroid/view/Menu;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d(Ljava/util/List;Landroid/view/Menu;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-static {p0, p1, p2, p3}, Lk/l;->a(Landroid/view/Window$Callback;Ljava/util/List;Landroid/view/Menu;I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lh/u;->f:Z

    .line 2
    .line 3
    iget-object v1, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v1, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    iget-object p0, p0, Lh/u;->h:Lh/z;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lh/z;->y(Landroid/view/KeyEvent;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-nez p0, :cond_2

    .line 19
    .line 20
    invoke-interface {v1, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 p0, 0x0

    .line 28
    return p0

    .line 29
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 30
    return p0
.end method

.method public final dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-nez v0, :cond_8

    .line 9
    .line 10
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iget-object p0, p0, Lh/u;->h:Lh/z;

    .line 15
    .line 16
    invoke-virtual {p0}, Lh/z;->E()V

    .line 17
    .line 18
    .line 19
    iget-object v2, p0, Lh/z;->r:Lh/i0;

    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    if-eqz v2, :cond_4

    .line 23
    .line 24
    iget-object v2, v2, Lh/i0;->i:Lh/h0;

    .line 25
    .line 26
    if-nez v2, :cond_1

    .line 27
    .line 28
    :cond_0
    move v0, v3

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    iget-object v2, v2, Lh/h0;->g:Ll/l;

    .line 31
    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getDeviceId()I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    invoke-static {v4}, Landroid/view/KeyCharacterMap;->load(I)Landroid/view/KeyCharacterMap;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    invoke-virtual {v4}, Landroid/view/KeyCharacterMap;->getKeyboardType()I

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-eq v4, v1, :cond_2

    .line 47
    .line 48
    move v4, v1

    .line 49
    goto :goto_0

    .line 50
    :cond_2
    move v4, v3

    .line 51
    :goto_0
    invoke-virtual {v2, v4}, Ll/l;->setQwertyMode(Z)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v2, v0, p1, v3}, Ll/l;->performShortcut(ILandroid/view/KeyEvent;I)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    :goto_1
    if-eqz v0, :cond_4

    .line 59
    .line 60
    :cond_3
    :goto_2
    move p0, v1

    .line 61
    goto :goto_3

    .line 62
    :cond_4
    iget-object v0, p0, Lh/z;->P:Lh/y;

    .line 63
    .line 64
    if-eqz v0, :cond_5

    .line 65
    .line 66
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-virtual {p0, v0, v2, p1}, Lh/z;->J(Lh/y;ILandroid/view/KeyEvent;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_5

    .line 75
    .line 76
    iget-object p0, p0, Lh/z;->P:Lh/y;

    .line 77
    .line 78
    if-eqz p0, :cond_3

    .line 79
    .line 80
    iput-boolean v1, p0, Lh/y;->l:Z

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    iget-object v0, p0, Lh/z;->P:Lh/y;

    .line 84
    .line 85
    if-nez v0, :cond_6

    .line 86
    .line 87
    invoke-virtual {p0, v3}, Lh/z;->D(I)Lh/y;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    invoke-virtual {p0, v0, p1}, Lh/z;->K(Lh/y;Landroid/view/KeyEvent;)Z

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    invoke-virtual {p0, v0, v2, p1}, Lh/z;->J(Lh/y;ILandroid/view/KeyEvent;)Z

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    iput-boolean v3, v0, Lh/y;->k:Z

    .line 103
    .line 104
    if-eqz p0, :cond_6

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_6
    move p0, v3

    .line 108
    :goto_3
    if-eqz p0, :cond_7

    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_7
    return v3

    .line 112
    :cond_8
    :goto_4
    return v1
.end method

.method public final dispatchPopulateAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchPopulateAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final dispatchTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchTouchEvent(Landroid/view/MotionEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final dispatchTrackballEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchTrackballEvent(Landroid/view/MotionEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final onActionModeFinished(Landroid/view/ActionMode;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onActionModeFinished(Landroid/view/ActionMode;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onActionModeStarted(Landroid/view/ActionMode;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onActionModeStarted(Landroid/view/ActionMode;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onAttachedToWindow()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/view/Window$Callback;->onAttachedToWindow()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onContentChanged()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh/u;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 6
    .line 7
    invoke-interface {p0}, Landroid/view/Window$Callback;->onContentChanged()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public final onCreatePanelMenu(ILandroid/view/Menu;)Z
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    instance-of v0, p2, Ll/l;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 10
    .line 11
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onCreatePanelMenu(ILandroid/view/Menu;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public final onCreatePanelView(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onCreatePanelView(I)Landroid/view/View;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final onDetachedFromWindow()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/view/Window$Callback;->onDetachedFromWindow()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onMenuItemSelected(ILandroid/view/MenuItem;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final onMenuOpened(ILandroid/view/Menu;)Z
    .locals 1

    .line 1
    invoke-virtual {p0, p1, p2}, Lh/u;->b(ILandroid/view/Menu;)Z

    .line 2
    .line 3
    .line 4
    const/16 p2, 0x6c

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    if-ne p1, p2, :cond_2

    .line 8
    .line 9
    iget-object p0, p0, Lh/u;->h:Lh/z;

    .line 10
    .line 11
    invoke-virtual {p0}, Lh/z;->E()V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lh/z;->r:Lh/i0;

    .line 15
    .line 16
    if-eqz p0, :cond_2

    .line 17
    .line 18
    iget-object p1, p0, Lh/i0;->m:Ljava/util/ArrayList;

    .line 19
    .line 20
    iget-boolean p2, p0, Lh/i0;->l:Z

    .line 21
    .line 22
    if-ne v0, p2, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iput-boolean v0, p0, Lh/i0;->l:Z

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-gtz p0, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    const/4 p0, 0x0

    .line 35
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    new-instance p0, Ljava/lang/ClassCastException;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    :goto_0
    return v0
.end method

.method public final onPanelClosed(ILandroid/view/Menu;)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh/u;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 6
    .line 7
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    invoke-virtual {p0, p1, p2}, Lh/u;->c(ILandroid/view/Menu;)V

    .line 12
    .line 13
    .line 14
    const/16 p2, 0x6c

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iget-object p0, p0, Lh/u;->h:Lh/z;

    .line 18
    .line 19
    if-ne p1, p2, :cond_3

    .line 20
    .line 21
    invoke-virtual {p0}, Lh/z;->E()V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Lh/z;->r:Lh/i0;

    .line 25
    .line 26
    if-eqz p0, :cond_4

    .line 27
    .line 28
    iget-object p1, p0, Lh/i0;->m:Ljava/util/ArrayList;

    .line 29
    .line 30
    iget-boolean p2, p0, Lh/i0;->l:Z

    .line 31
    .line 32
    if-nez p2, :cond_1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    iput-boolean v0, p0, Lh/i0;->l:Z

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-gtz p0, :cond_2

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    new-instance p0, Ljava/lang/ClassCastException;

    .line 52
    .line 53
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_3
    if-nez p1, :cond_4

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lh/z;->D(I)Lh/y;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    iget-boolean p2, p1, Lh/y;->m:Z

    .line 64
    .line 65
    if-eqz p2, :cond_4

    .line 66
    .line 67
    invoke-virtual {p0, p1, v0}, Lh/z;->w(Lh/y;Z)V

    .line 68
    .line 69
    .line 70
    :cond_4
    :goto_0
    return-void
.end method

.method public final onPointerCaptureChanged(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lk/m;->a(Landroid/view/Window$Callback;Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z
    .locals 3

    .line 1
    instance-of v0, p3, Ll/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Ll/l;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    const/4 v1, 0x0

    .line 11
    if-nez p1, :cond_1

    .line 12
    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    return v1

    .line 16
    :cond_1
    if-eqz v0, :cond_2

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    iput-boolean v2, v0, Ll/l;->x:Z

    .line 20
    .line 21
    :cond_2
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 22
    .line 23
    invoke-interface {p0, p1, p2, p3}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz v0, :cond_3

    .line 28
    .line 29
    iput-boolean v1, v0, Ll/l;->x:Z

    .line 30
    .line 31
    :cond_3
    return p0
.end method

.method public final onProvideKeyboardShortcuts(Ljava/util/List;Landroid/view/Menu;I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lh/u;->h:Lh/z;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Lh/z;->D(I)Lh/y;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iget-object v0, v0, Lh/y;->h:Ll/l;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, p1, v0, p3}, Lh/u;->d(Ljava/util/List;Landroid/view/Menu;I)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lh/u;->d(Ljava/util/List;Landroid/view/Menu;I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final onSearchRequested()Z
    .locals 0

    .line 2
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    invoke-interface {p0}, Landroid/view/Window$Callback;->onSearchRequested()Z

    move-result p0

    return p0
.end method

.method public final onSearchRequested(Landroid/view/SearchEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    invoke-static {p0, p1}, Lk/k;->a(Landroid/view/Window$Callback;Landroid/view/SearchEvent;)Z

    move-result p0

    return p0
.end method

.method public final onWindowAttributesChanged(Landroid/view/WindowManager$LayoutParams;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onWindowAttributesChanged(Landroid/view/WindowManager$LayoutParams;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onWindowFocusChanged(Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onWindowFocusChanged(Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onWindowStartingActionMode(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;
    .locals 0

    .line 95
    const/4 p0, 0x0

    return-object p0
.end method

.method public final onWindowStartingActionMode(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;
    .locals 8

    if-eqz p2, :cond_0

    .line 1
    iget-object p0, p0, Lh/u;->d:Landroid/view/Window$Callback;

    invoke-static {p0, p1, p2}, Lk/k;->b(Landroid/view/Window$Callback;Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;

    move-result-object p0

    return-object p0

    .line 2
    :cond_0
    new-instance p2, Lcom/google/firebase/messaging/w;

    iget-object p0, p0, Lh/u;->h:Lh/z;

    iget-object v0, p0, Lh/z;->n:Landroid/content/Context;

    invoke-direct {p2, v0, p1}, Lcom/google/firebase/messaging/w;-><init>(Landroid/content/Context;Landroid/view/ActionMode$Callback;)V

    .line 3
    iget-object p1, p0, Lh/z;->x:Lk/a;

    if-eqz p1, :cond_1

    .line 4
    invoke-virtual {p1}, Lk/a;->a()V

    .line 5
    :cond_1
    new-instance p1, Lb81/b;

    const/16 v1, 0x8

    const/4 v2, 0x0

    invoke-direct {p1, p0, p2, v2, v1}, Lb81/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 6
    invoke-virtual {p0}, Lh/z;->E()V

    .line 7
    iget-object v1, p0, Lh/z;->r:Lh/i0;

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v1, :cond_4

    .line 8
    iget-object v5, v1, Lh/i0;->i:Lh/h0;

    if-eqz v5, :cond_2

    .line 9
    invoke-virtual {v5}, Lh/h0;->a()V

    .line 10
    :cond_2
    iget-object v5, v1, Lh/i0;->c:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    invoke-virtual {v5, v2}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setHideOnContentScrollEnabled(Z)V

    .line 11
    iget-object v5, v1, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v5}, Landroidx/appcompat/widget/ActionBarContextView;->e()V

    .line 12
    new-instance v5, Lh/h0;

    iget-object v6, v1, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v6}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v6

    invoke-direct {v5, v1, v6, p1}, Lh/h0;-><init>(Lh/i0;Landroid/content/Context;Lb81/b;)V

    .line 13
    iget-object v6, v5, Lh/h0;->g:Ll/l;

    invoke-virtual {v6}, Ll/l;->w()V

    .line 14
    :try_start_0
    iget-object v7, v5, Lh/h0;->h:Lb81/b;

    .line 15
    iget-object v7, v7, Lb81/b;->e:Ljava/lang/Object;

    check-cast v7, Lcom/google/firebase/messaging/w;

    invoke-virtual {v7, v5, v6}, Lcom/google/firebase/messaging/w;->p(Lk/a;Landroid/view/Menu;)Z

    move-result v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    invoke-virtual {v6}, Ll/l;->v()V

    if-eqz v7, :cond_3

    .line 17
    iput-object v5, v1, Lh/i0;->i:Lh/h0;

    .line 18
    invoke-virtual {v5}, Lh/h0;->h()V

    .line 19
    iget-object v6, v1, Lh/i0;->f:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v6, v5}, Landroidx/appcompat/widget/ActionBarContextView;->c(Lk/a;)V

    .line 20
    invoke-virtual {v1, v3}, Lh/i0;->c(Z)V

    goto :goto_0

    :cond_3
    move-object v5, v4

    .line 21
    :goto_0
    iput-object v5, p0, Lh/z;->x:Lk/a;

    goto :goto_1

    :catchall_0
    move-exception p0

    .line 22
    invoke-virtual {v6}, Ll/l;->v()V

    .line 23
    throw p0

    .line 24
    :cond_4
    :goto_1
    iget-object v1, p0, Lh/z;->x:Lk/a;

    if-nez v1, :cond_11

    .line 25
    iget-object v1, p0, Lh/z;->B:Ld6/w0;

    if-eqz v1, :cond_5

    .line 26
    invoke-virtual {v1}, Ld6/w0;->b()V

    .line 27
    :cond_5
    iget-object v1, p0, Lh/z;->x:Lk/a;

    if-eqz v1, :cond_6

    .line 28
    invoke-virtual {v1}, Lk/a;->a()V

    .line 29
    :cond_6
    iget-object v1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    if-nez v1, :cond_b

    .line 30
    iget-boolean v1, p0, Lh/z;->L:Z

    if-eqz v1, :cond_8

    .line 31
    new-instance v1, Landroid/util/TypedValue;

    invoke-direct {v1}, Landroid/util/TypedValue;-><init>()V

    .line 32
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v5

    const v6, 0x7f04000c

    .line 33
    invoke-virtual {v5, v6, v1, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 34
    iget v6, v1, Landroid/util/TypedValue;->resourceId:I

    if-eqz v6, :cond_7

    .line 35
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    invoke-virtual {v6}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    move-result-object v6

    .line 36
    invoke-virtual {v6, v5}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    .line 37
    iget v5, v1, Landroid/util/TypedValue;->resourceId:I

    invoke-virtual {v6, v5, v3}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    .line 38
    new-instance v5, Lk/c;

    invoke-direct {v5, v0, v2}, Lk/c;-><init>(Landroid/content/Context;I)V

    .line 39
    invoke-virtual {v5}, Lk/c;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v0

    invoke-virtual {v0, v6}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    move-object v0, v5

    .line 40
    :cond_7
    new-instance v5, Landroidx/appcompat/widget/ActionBarContextView;

    .line 41
    invoke-direct {v5, v0, v4}, Landroidx/appcompat/widget/ActionBarContextView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 42
    iput-object v5, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 43
    new-instance v5, Landroid/widget/PopupWindow;

    const v6, 0x7f04001b

    invoke-direct {v5, v0, v4, v6}, Landroid/widget/PopupWindow;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    iput-object v5, p0, Lh/z;->z:Landroid/widget/PopupWindow;

    const/4 v6, 0x2

    .line 44
    invoke-virtual {v5, v6}, Landroid/widget/PopupWindow;->setWindowLayoutType(I)V

    .line 45
    iget-object v5, p0, Lh/z;->z:Landroid/widget/PopupWindow;

    iget-object v6, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v5, v6}, Landroid/widget/PopupWindow;->setContentView(Landroid/view/View;)V

    .line 46
    iget-object v5, p0, Lh/z;->z:Landroid/widget/PopupWindow;

    const/4 v6, -0x1

    invoke-virtual {v5, v6}, Landroid/widget/PopupWindow;->setWidth(I)V

    .line 47
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v5

    const v6, 0x7f040006

    invoke-virtual {v5, v6, v1, v3}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 48
    iget v1, v1, Landroid/util/TypedValue;->data:I

    .line 49
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v0

    .line 50
    invoke-static {v1, v0}, Landroid/util/TypedValue;->complexToDimensionPixelSize(ILandroid/util/DisplayMetrics;)I

    move-result v0

    .line 51
    iget-object v1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v1, v0}, Landroidx/appcompat/widget/ActionBarContextView;->setContentHeight(I)V

    .line 52
    iget-object v0, p0, Lh/z;->z:Landroid/widget/PopupWindow;

    const/4 v1, -0x2

    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setHeight(I)V

    .line 53
    new-instance v0, Lh/o;

    invoke-direct {v0, p0, v3}, Lh/o;-><init>(Lh/z;I)V

    iput-object v0, p0, Lh/z;->A:Lh/o;

    goto :goto_4

    .line 54
    :cond_8
    iget-object v1, p0, Lh/z;->D:Landroid/view/ViewGroup;

    const v5, 0x7f0a0041

    invoke-virtual {v1, v5}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/widget/ViewStubCompat;

    if-eqz v1, :cond_b

    .line 55
    invoke-virtual {p0}, Lh/z;->E()V

    .line 56
    iget-object v5, p0, Lh/z;->r:Lh/i0;

    if-eqz v5, :cond_9

    .line 57
    invoke-virtual {v5}, Lh/i0;->d()Landroid/content/Context;

    move-result-object v5

    goto :goto_2

    :cond_9
    move-object v5, v4

    :goto_2
    if-nez v5, :cond_a

    goto :goto_3

    :cond_a
    move-object v0, v5

    .line 58
    :goto_3
    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    invoke-virtual {v1, v0}, Landroidx/appcompat/widget/ViewStubCompat;->setLayoutInflater(Landroid/view/LayoutInflater;)V

    .line 59
    invoke-virtual {v1}, Landroidx/appcompat/widget/ViewStubCompat;->a()Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/widget/ActionBarContextView;

    iput-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 60
    :cond_b
    :goto_4
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    if-eqz v0, :cond_10

    .line 61
    iget-object v0, p0, Lh/z;->B:Ld6/w0;

    if-eqz v0, :cond_c

    .line 62
    invoke-virtual {v0}, Ld6/w0;->b()V

    .line 63
    :cond_c
    iget-object v0, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarContextView;->e()V

    .line 64
    new-instance v0, Lk/d;

    iget-object v1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    iget-object v5, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    .line 65
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 66
    iput-object v1, v0, Lk/d;->f:Landroid/content/Context;

    .line 67
    iput-object v5, v0, Lk/d;->g:Landroidx/appcompat/widget/ActionBarContextView;

    .line 68
    iput-object p1, v0, Lk/d;->h:Lb81/b;

    .line 69
    new-instance p1, Ll/l;

    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {p1, v1}, Ll/l;-><init>(Landroid/content/Context;)V

    .line 70
    iput v3, p1, Ll/l;->l:I

    .line 71
    iput-object p1, v0, Lk/d;->k:Ll/l;

    .line 72
    iput-object v0, p1, Ll/l;->e:Ll/j;

    .line 73
    invoke-virtual {p2, v0, p1}, Lcom/google/firebase/messaging/w;->p(Lk/a;Landroid/view/Menu;)Z

    move-result p1

    if-eqz p1, :cond_f

    .line 74
    invoke-virtual {v0}, Lk/d;->h()V

    .line 75
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1, v0}, Landroidx/appcompat/widget/ActionBarContextView;->c(Lk/a;)V

    .line 76
    iput-object v0, p0, Lh/z;->x:Lk/a;

    .line 77
    iget-boolean p1, p0, Lh/z;->C:Z

    const/high16 v0, 0x3f800000    # 1.0f

    if-eqz p1, :cond_d

    iget-object p1, p0, Lh/z;->D:Landroid/view/ViewGroup;

    if-eqz p1, :cond_d

    invoke-virtual {p1}, Landroid/view/View;->isLaidOut()Z

    move-result p1

    if-eqz p1, :cond_d

    .line 78
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    const/4 v1, 0x0

    invoke-virtual {p1, v1}, Landroid/view/View;->setAlpha(F)V

    .line 79
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-static {p1}, Ld6/r0;->a(Landroid/view/View;)Ld6/w0;

    move-result-object p1

    invoke-virtual {p1, v0}, Ld6/w0;->a(F)V

    iput-object p1, p0, Lh/z;->B:Ld6/w0;

    .line 80
    new-instance v0, Lh/q;

    invoke-direct {v0, p0, v3}, Lh/q;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Ld6/w0;->d(Ld6/x0;)V

    goto :goto_5

    .line 81
    :cond_d
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1, v0}, Landroid/view/View;->setAlpha(F)V

    .line 82
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1, v2}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    .line 83
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    instance-of p1, p1, Landroid/view/View;

    if-eqz p1, :cond_e

    .line 84
    iget-object p1, p0, Lh/z;->y:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 85
    invoke-static {p1}, Ld6/i0;->c(Landroid/view/View;)V

    .line 86
    :cond_e
    :goto_5
    iget-object p1, p0, Lh/z;->z:Landroid/widget/PopupWindow;

    if-eqz p1, :cond_10

    .line 87
    iget-object p1, p0, Lh/z;->o:Landroid/view/Window;

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    iget-object v0, p0, Lh/z;->A:Lh/o;

    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    goto :goto_6

    .line 88
    :cond_f
    iput-object v4, p0, Lh/z;->x:Lk/a;

    .line 89
    :cond_10
    :goto_6
    invoke-virtual {p0}, Lh/z;->M()V

    .line 90
    iget-object p1, p0, Lh/z;->x:Lk/a;

    .line 91
    iput-object p1, p0, Lh/z;->x:Lk/a;

    .line 92
    :cond_11
    invoke-virtual {p0}, Lh/z;->M()V

    .line 93
    iget-object p0, p0, Lh/z;->x:Lk/a;

    if-eqz p0, :cond_12

    .line 94
    invoke-virtual {p2, p0}, Lcom/google/firebase/messaging/w;->j(Lk/a;)Lk/e;

    move-result-object p0

    return-object p0

    :cond_12
    return-object v4
.end method
