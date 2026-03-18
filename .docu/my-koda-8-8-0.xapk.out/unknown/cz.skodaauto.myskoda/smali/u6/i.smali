.class public final Lu6/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/text/TextWatcher;


# instance fields
.field public final d:Landroid/widget/EditText;

.field public e:Lu6/h;

.field public f:Z


# direct methods
.method public constructor <init>(Landroid/widget/EditText;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu6/i;->d:Landroid/widget/EditText;

    .line 5
    .line 6
    const/4 p1, 0x1

    .line 7
    iput-boolean p1, p0, Lu6/i;->f:Z

    .line 8
    .line 9
    return-void
.end method

.method public static a(Landroid/widget/EditText;I)V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, v0, :cond_3

    .line 3
    .line 4
    if-eqz p0, :cond_3

    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_3

    .line 11
    .line 12
    invoke-virtual {p0}, Landroid/widget/TextView;->getEditableText()Landroid/text/Editable;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-static {p0}, Landroid/text/Selection;->getSelectionStart(Ljava/lang/CharSequence;)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    invoke-static {p0}, Landroid/text/Selection;->getSelectionEnd(Ljava/lang/CharSequence;)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    const/4 v2, 0x0

    .line 29
    if-nez p0, :cond_0

    .line 30
    .line 31
    move v3, v2

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    :goto_0
    invoke-virtual {v1, v2, v3, v2, p0}, Ls6/h;->g(IIILjava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 41
    .line 42
    .line 43
    if-ltz p1, :cond_1

    .line 44
    .line 45
    if-ltz v0, :cond_1

    .line 46
    .line 47
    invoke-static {p0, p1, v0}, Landroid/text/Selection;->setSelection(Landroid/text/Spannable;II)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_1
    if-ltz p1, :cond_2

    .line 52
    .line 53
    invoke-static {p0, p1}, Landroid/text/Selection;->setSelection(Landroid/text/Spannable;I)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_2
    if-ltz v0, :cond_3

    .line 58
    .line 59
    invoke-static {p0, v0}, Landroid/text/Selection;->setSelection(Landroid/text/Spannable;I)V

    .line 60
    .line 61
    .line 62
    :cond_3
    return-void
.end method


# virtual methods
.method public final afterTextChanged(Landroid/text/Editable;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final beforeTextChanged(Ljava/lang/CharSequence;III)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onTextChanged(Ljava/lang/CharSequence;III)V
    .locals 2

    .line 1
    iget-object v0, p0, Lu6/i;->d:Landroid/widget/EditText;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->isInEditMode()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_4

    .line 8
    .line 9
    iget-boolean v1, p0, Lu6/i;->f:Z

    .line 10
    .line 11
    if-eqz v1, :cond_4

    .line 12
    .line 13
    invoke-static {}, Ls6/h;->d()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    if-gt p3, p4, :cond_4

    .line 21
    .line 22
    instance-of p3, p1, Landroid/text/Spannable;

    .line 23
    .line 24
    if-eqz p3, :cond_4

    .line 25
    .line 26
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 27
    .line 28
    .line 29
    move-result-object p3

    .line 30
    invoke-virtual {p3}, Ls6/h;->c()I

    .line 31
    .line 32
    .line 33
    move-result p3

    .line 34
    if-eqz p3, :cond_2

    .line 35
    .line 36
    const/4 v1, 0x1

    .line 37
    if-eq p3, v1, :cond_1

    .line 38
    .line 39
    const/4 p1, 0x3

    .line 40
    if-eq p3, p1, :cond_2

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    check-cast p1, Landroid/text/Spannable;

    .line 44
    .line 45
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    add-int/2addr p4, p2

    .line 50
    const/4 p3, 0x0

    .line 51
    invoke-virtual {p0, p2, p4, p3, p1}, Ls6/h;->g(IIILjava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iget-object p2, p0, Lu6/i;->e:Lu6/h;

    .line 60
    .line 61
    if-nez p2, :cond_3

    .line 62
    .line 63
    new-instance p2, Lu6/h;

    .line 64
    .line 65
    invoke-direct {p2, v0}, Lu6/h;-><init>(Landroid/widget/EditText;)V

    .line 66
    .line 67
    .line 68
    iput-object p2, p0, Lu6/i;->e:Lu6/h;

    .line 69
    .line 70
    :cond_3
    iget-object p0, p0, Lu6/i;->e:Lu6/h;

    .line 71
    .line 72
    invoke-virtual {p1, p0}, Ls6/h;->h(Ls6/f;)V

    .line 73
    .line 74
    .line 75
    :cond_4
    :goto_0
    return-void
.end method
