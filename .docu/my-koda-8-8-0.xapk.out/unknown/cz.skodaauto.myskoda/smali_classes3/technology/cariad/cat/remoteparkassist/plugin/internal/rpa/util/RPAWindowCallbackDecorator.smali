.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/Window$Callback;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000v\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008\u0001\u0018\u00002\u00020\u0001:\u0001EB\u000f\u0012\u0006\u0010\u0002\u001a\u00020\u0001\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u0019\u0010\u0008\u001a\u00020\u00072\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0019\u0010\r\u001a\u0004\u0018\u00010\u000c2\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0017\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0010\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u001f\u0010\u0016\u001a\u00020\u00112\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0015\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u001b\u0010\u001a\u001a\u0004\u0018\u00010\u00052\u0008\u0010\u0019\u001a\u0004\u0018\u00010\u0018H\u0016\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ#\u0010\u001a\u001a\u0004\u0018\u00010\u00052\u0008\u0010\u0019\u001a\u0004\u0018\u00010\u00182\u0006\u0010\u001c\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u001a\u0010\u001dJ\u000f\u0010\u001e\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u0019\u0010 \u001a\u00020\u00112\u0008\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0016\u00a2\u0006\u0004\u0008 \u0010\u0013J\u0019\u0010\"\u001a\u00020\u00112\u0008\u0010\u0010\u001a\u0004\u0018\u00010!H\u0016\u00a2\u0006\u0004\u0008\"\u0010#J\u0019\u0010$\u001a\u00020\u00112\u0008\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0016\u00a2\u0006\u0004\u0008$\u0010\u0013J\u0019\u0010&\u001a\u00020\u00112\u0008\u0010\u0010\u001a\u0004\u0018\u00010%H\u0016\u00a2\u0006\u0004\u0008&\u0010\'J\u0019\u0010(\u001a\u00020\u00112\u0008\u0010\u0010\u001a\u0004\u0018\u00010%H\u0016\u00a2\u0006\u0004\u0008(\u0010\'J\u001f\u0010)\u001a\u00020\u00112\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0015\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008)\u0010\u0017J\u001f\u0010*\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0015\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008*\u0010+J\u001f\u0010.\u001a\u00020\u00112\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010-\u001a\u00020,H\u0016\u00a2\u0006\u0004\u0008.\u0010/J\u000f\u00100\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u00080\u0010\u001fJ)\u00102\u001a\u00020\u00112\u0006\u0010\u000b\u001a\u00020\n2\u0008\u00101\u001a\u0004\u0018\u00010\u000c2\u0006\u0010\u0015\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u00082\u00103J\u0019\u00106\u001a\u00020\u00072\u0008\u00105\u001a\u0004\u0018\u000104H\u0016\u00a2\u0006\u0004\u00086\u00107J\u0017\u00109\u001a\u00020\u00072\u0006\u00108\u001a\u00020\u0011H\u0016\u00a2\u0006\u0004\u00089\u0010:J\u000f\u0010;\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008;\u0010\u001fJ\u000f\u0010<\u001a\u00020\u0011H\u0016\u00a2\u0006\u0004\u0008<\u0010=J\u0019\u0010<\u001a\u00020\u00112\u0008\u0010?\u001a\u0004\u0018\u00010>H\u0016\u00a2\u0006\u0004\u0008<\u0010@J\u0019\u0010A\u001a\u00020\u00072\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016\u00a2\u0006\u0004\u0008A\u0010\tR\u0017\u0010\u0002\u001a\u00020\u00018\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0002\u0010B\u001a\u0004\u0008C\u0010DR$\u0010F\u001a\u0004\u0018\u00010E8\u0000@\u0000X\u0080\u000e\u00a2\u0006\u0012\n\u0004\u0008F\u0010G\u001a\u0004\u0008H\u0010I\"\u0004\u0008J\u0010K\u00a8\u0006L"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;",
        "Landroid/view/Window$Callback;",
        "concreteWindowCallback",
        "<init>",
        "(Landroid/view/Window$Callback;)V",
        "Landroid/view/ActionMode;",
        "mode",
        "Llx0/b0;",
        "onActionModeFinished",
        "(Landroid/view/ActionMode;)V",
        "",
        "featureId",
        "Landroid/view/View;",
        "onCreatePanelView",
        "(I)Landroid/view/View;",
        "Landroid/view/MotionEvent;",
        "event",
        "",
        "dispatchTouchEvent",
        "(Landroid/view/MotionEvent;)Z",
        "Landroid/view/Menu;",
        "menu",
        "onCreatePanelMenu",
        "(ILandroid/view/Menu;)Z",
        "Landroid/view/ActionMode$Callback;",
        "callback",
        "onWindowStartingActionMode",
        "(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;",
        "type",
        "(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;",
        "onAttachedToWindow",
        "()V",
        "dispatchGenericMotionEvent",
        "Landroid/view/accessibility/AccessibilityEvent;",
        "dispatchPopulateAccessibilityEvent",
        "(Landroid/view/accessibility/AccessibilityEvent;)Z",
        "dispatchTrackballEvent",
        "Landroid/view/KeyEvent;",
        "dispatchKeyShortcutEvent",
        "(Landroid/view/KeyEvent;)Z",
        "dispatchKeyEvent",
        "onMenuOpened",
        "onPanelClosed",
        "(ILandroid/view/Menu;)V",
        "Landroid/view/MenuItem;",
        "item",
        "onMenuItemSelected",
        "(ILandroid/view/MenuItem;)Z",
        "onDetachedFromWindow",
        "view",
        "onPreparePanel",
        "(ILandroid/view/View;Landroid/view/Menu;)Z",
        "Landroid/view/WindowManager$LayoutParams;",
        "attrs",
        "onWindowAttributesChanged",
        "(Landroid/view/WindowManager$LayoutParams;)V",
        "hasFocus",
        "onWindowFocusChanged",
        "(Z)V",
        "onContentChanged",
        "onSearchRequested",
        "()Z",
        "Landroid/view/SearchEvent;",
        "searchEvent",
        "(Landroid/view/SearchEvent;)Z",
        "onActionModeStarted",
        "Landroid/view/Window$Callback;",
        "getConcreteWindowCallback",
        "()Landroid/view/Window$Callback;",
        "Lt61/p;",
        "windowEventDelegate",
        "Lt61/p;",
        "getWindowEventDelegate$remoteparkassistplugin_release",
        "()Lt61/p;",
        "setWindowEventDelegate$remoteparkassistplugin_release",
        "(Lt61/p;)V",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private final concreteWindowCallback:Landroid/view/Window$Callback;

.field private windowEventDelegate:Lt61/p;


# direct methods
.method public constructor <init>(Landroid/view/Window$Callback;)V
    .locals 1

    .line 1
    const-string v0, "concreteWindowCallback"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

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

.method public dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public dispatchPopulateAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

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

.method public dispatchTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->windowEventDelegate:Lt61/p;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-interface {v0, p1}, Lt61/p;->dispatchTouchEvent(Landroid/view/MotionEvent;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->dispatchTouchEvent(Landroid/view/MotionEvent;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public dispatchTrackballEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

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

.method public final getConcreteWindowCallback()Landroid/view/Window$Callback;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWindowEventDelegate$remoteparkassistplugin_release()Lt61/p;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->windowEventDelegate:Lt61/p;

    .line 2
    .line 3
    return-object p0
.end method

.method public onActionModeFinished(Landroid/view/ActionMode;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onActionModeFinished(Landroid/view/ActionMode;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onActionModeStarted(Landroid/view/ActionMode;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onActionModeStarted(Landroid/view/ActionMode;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onAttachedToWindow()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/view/Window$Callback;->onAttachedToWindow()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onContentChanged()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/view/Window$Callback;->onContentChanged()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onCreatePanelMenu(ILandroid/view/Menu;)Z
    .locals 1

    .line 1
    const-string v0, "menu"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onCreatePanelMenu(ILandroid/view/Menu;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public onCreatePanelView(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

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

.method public onDetachedFromWindow()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/view/Window$Callback;->onDetachedFromWindow()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onMenuItemSelected(ILandroid/view/MenuItem;)Z
    .locals 1

    .line 1
    const-string v0, "item"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public onMenuOpened(ILandroid/view/Menu;)Z
    .locals 1

    .line 1
    const-string v0, "menu"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public onPanelClosed(ILandroid/view/Menu;)V
    .locals 1

    .line 1
    const-string v0, "menu"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z
    .locals 1

    .line 1
    const-string v0, "menu"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2, p3}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public onSearchRequested()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    invoke-interface {p0}, Landroid/view/Window$Callback;->onSearchRequested()Z

    move-result p0

    return p0
.end method

.method public onSearchRequested(Landroid/view/SearchEvent;)Z
    .locals 0

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onSearchRequested(Landroid/view/SearchEvent;)Z

    move-result p0

    return p0
.end method

.method public onWindowAttributesChanged(Landroid/view/WindowManager$LayoutParams;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onWindowAttributesChanged(Landroid/view/WindowManager$LayoutParams;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onWindowFocusChanged(Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->windowEventDelegate:Lt61/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0, p1}, Lt61/p;->windowFocusChanged(Z)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onWindowFocusChanged(Z)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public onWindowStartingActionMode(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    invoke-interface {p0, p1}, Landroid/view/Window$Callback;->onWindowStartingActionMode(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;

    move-result-object p0

    return-object p0
.end method

.method public onWindowStartingActionMode(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;
    .locals 0

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->concreteWindowCallback:Landroid/view/Window$Callback;

    invoke-interface {p0, p1, p2}, Landroid/view/Window$Callback;->onWindowStartingActionMode(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;

    move-result-object p0

    return-object p0
.end method

.method public final setWindowEventDelegate$remoteparkassistplugin_release(Lt61/p;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPAWindowCallbackDecorator;->windowEventDelegate:Lt61/p;

    .line 2
    .line 3
    return-void
.end method
