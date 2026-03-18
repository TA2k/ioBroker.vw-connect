.class public abstract Lm/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Landroid/view/DragEvent;Landroid/widget/TextView;Landroid/app/Activity;)Z
    .locals 2

    .line 1
    invoke-virtual {p2, p0}, Landroid/app/Activity;->requestDragAndDropPermissions(Landroid/view/DragEvent;)Landroid/view/DragAndDropPermissions;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/DragEvent;->getX()F

    .line 5
    .line 6
    .line 7
    move-result p2

    .line 8
    invoke-virtual {p0}, Landroid/view/DragEvent;->getY()F

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-virtual {p1, p2, v0}, Landroid/widget/TextView;->getOffsetForPosition(FF)I

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    invoke-virtual {p1}, Landroid/widget/TextView;->beginBatchEdit()V

    .line 17
    .line 18
    .line 19
    :try_start_0
    invoke-virtual {p1}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Landroid/text/Spannable;

    .line 24
    .line 25
    invoke-static {v0, p2}, Landroid/text/Selection;->setSelection(Landroid/text/Spannable;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Landroid/view/DragEvent;->getClipData()Landroid/content/ClipData;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 33
    .line 34
    const/16 v0, 0x1f

    .line 35
    .line 36
    const/4 v1, 0x3

    .line 37
    if-lt p2, v0, :cond_0

    .line 38
    .line 39
    new-instance p2, Laq/a;

    .line 40
    .line 41
    invoke-direct {p2, p0, v1}, Laq/a;-><init>(Landroid/content/ClipData;I)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    new-instance p2, Ld6/d;

    .line 46
    .line 47
    invoke-direct {p2}, Ld6/d;-><init>()V

    .line 48
    .line 49
    .line 50
    iput-object p0, p2, Ld6/d;->e:Landroid/content/ClipData;

    .line 51
    .line 52
    iput v1, p2, Ld6/d;->f:I

    .line 53
    .line 54
    :goto_0
    invoke-interface {p2}, Ld6/c;->build()Ld6/f;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-static {p1, p0}, Ld6/r0;->f(Landroid/view/View;Ld6/f;)Ld6/f;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1}, Landroid/widget/TextView;->endBatchEdit()V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x1

    .line 65
    return p0

    .line 66
    :catchall_0
    move-exception p0

    .line 67
    invoke-virtual {p1}, Landroid/widget/TextView;->endBatchEdit()V

    .line 68
    .line 69
    .line 70
    throw p0
.end method

.method public static b(Landroid/view/DragEvent;Landroid/view/View;Landroid/app/Activity;)Z
    .locals 2

    .line 1
    invoke-virtual {p2, p0}, Landroid/app/Activity;->requestDragAndDropPermissions(Landroid/view/DragEvent;)Landroid/view/DragAndDropPermissions;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/DragEvent;->getClipData()Landroid/content/ClipData;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v0, 0x1f

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    if-lt p2, v0, :cond_0

    .line 14
    .line 15
    new-instance p2, Laq/a;

    .line 16
    .line 17
    invoke-direct {p2, p0, v1}, Laq/a;-><init>(Landroid/content/ClipData;I)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p2, Ld6/d;

    .line 22
    .line 23
    invoke-direct {p2}, Ld6/d;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p0, p2, Ld6/d;->e:Landroid/content/ClipData;

    .line 27
    .line 28
    iput v1, p2, Ld6/d;->f:I

    .line 29
    .line 30
    :goto_0
    invoke-interface {p2}, Ld6/c;->build()Ld6/f;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-static {p1, p0}, Ld6/r0;->f(Landroid/view/View;Ld6/f;)Ld6/f;

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    return p0
.end method
