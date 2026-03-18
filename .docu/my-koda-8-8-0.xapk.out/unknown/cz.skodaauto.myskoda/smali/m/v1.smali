.class public final Lm/v1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm/z1;


# direct methods
.method public synthetic constructor <init>(Lm/z1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lm/v1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm/v1;->e:Lm/z1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    .line 1
    iget v0, p0, Lm/v1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm/v1;->e:Lm/z1;

    .line 7
    .line 8
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 19
    .line 20
    invoke-virtual {v0}, Landroid/widget/AdapterView;->getCount()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object v1, p0, Lm/z1;->f:Lm/m1;

    .line 25
    .line 26
    invoke-virtual {v1}, Landroid/view/ViewGroup;->getChildCount()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-le v0, v1, :cond_0

    .line 31
    .line 32
    iget-object v0, p0, Lm/z1;->f:Lm/m1;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iget v1, p0, Lm/z1;->p:I

    .line 39
    .line 40
    if-gt v0, v1, :cond_0

    .line 41
    .line 42
    iget-object v0, p0, Lm/z1;->C:Lm/z;

    .line 43
    .line 44
    const/4 v1, 0x2

    .line 45
    invoke-virtual {v0, v1}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Lm/z1;->b()V

    .line 49
    .line 50
    .line 51
    :cond_0
    return-void

    .line 52
    :pswitch_0
    iget-object p0, p0, Lm/v1;->e:Lm/z1;

    .line 53
    .line 54
    iget-object p0, p0, Lm/z1;->f:Lm/m1;

    .line 55
    .line 56
    if-eqz p0, :cond_1

    .line 57
    .line 58
    const/4 v0, 0x1

    .line 59
    invoke-virtual {p0, v0}, Lm/m1;->setListSelectionHidden(Z)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 63
    .line 64
    .line 65
    :cond_1
    return-void

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
