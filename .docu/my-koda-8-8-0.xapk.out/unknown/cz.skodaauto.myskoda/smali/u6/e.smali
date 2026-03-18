.class public final Lu6/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/text/method/KeyListener;


# instance fields
.field public final a:Landroid/text/method/KeyListener;

.field public final b:Lwq/f;


# direct methods
.method public constructor <init>(Landroid/text/method/KeyListener;)V
    .locals 2

    .line 1
    new-instance v0, Lwq/f;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lwq/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lu6/e;->a:Landroid/text/method/KeyListener;

    .line 12
    .line 13
    iput-object v0, p0, Lu6/e;->b:Lwq/f;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final clearMetaKeyState(Landroid/view/View;Landroid/text/Editable;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lu6/e;->a:Landroid/text/method/KeyListener;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3}, Landroid/text/method/KeyListener;->clearMetaKeyState(Landroid/view/View;Landroid/text/Editable;I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final getInputType()I
    .locals 0

    .line 1
    iget-object p0, p0, Lu6/e;->a:Landroid/text/method/KeyListener;

    .line 2
    .line 3
    invoke-interface {p0}, Landroid/text/method/KeyListener;->getInputType()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final onKeyDown(Landroid/view/View;Landroid/text/Editable;ILandroid/view/KeyEvent;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lu6/e;->b:Lwq/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x43

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eq p3, v0, :cond_1

    .line 11
    .line 12
    const/16 v0, 0x70

    .line 13
    .line 14
    if-eq p3, v0, :cond_0

    .line 15
    .line 16
    move v0, v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-static {p2, p4, v1}, Lrn/i;->r(Landroid/text/Editable;Landroid/view/KeyEvent;Z)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    goto :goto_0

    .line 23
    :cond_1
    invoke-static {p2, p4, v2}, Lrn/i;->r(Landroid/text/Editable;Landroid/view/KeyEvent;Z)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    :goto_0
    if-eqz v0, :cond_2

    .line 28
    .line 29
    invoke-static {p2}, Landroid/text/method/MetaKeyKeyListener;->adjustMetaAfterKeypress(Landroid/text/Spannable;)V

    .line 30
    .line 31
    .line 32
    move v0, v1

    .line 33
    goto :goto_1

    .line 34
    :cond_2
    move v0, v2

    .line 35
    :goto_1
    if-nez v0, :cond_4

    .line 36
    .line 37
    iget-object p0, p0, Lu6/e;->a:Landroid/text/method/KeyListener;

    .line 38
    .line 39
    invoke-interface {p0, p1, p2, p3, p4}, Landroid/text/method/KeyListener;->onKeyDown(Landroid/view/View;Landroid/text/Editable;ILandroid/view/KeyEvent;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-eqz p0, :cond_3

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_3
    return v2

    .line 47
    :cond_4
    :goto_2
    return v1
.end method

.method public final onKeyOther(Landroid/view/View;Landroid/text/Editable;Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu6/e;->a:Landroid/text/method/KeyListener;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3}, Landroid/text/method/KeyListener;->onKeyOther(Landroid/view/View;Landroid/text/Editable;Landroid/view/KeyEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final onKeyUp(Landroid/view/View;Landroid/text/Editable;ILandroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lu6/e;->a:Landroid/text/method/KeyListener;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3, p4}, Landroid/text/method/KeyListener;->onKeyUp(Landroid/view/View;Landroid/text/Editable;ILandroid/view/KeyEvent;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
