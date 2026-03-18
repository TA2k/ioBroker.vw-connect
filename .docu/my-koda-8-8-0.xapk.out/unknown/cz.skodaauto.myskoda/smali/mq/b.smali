.class public final Lmq/b;
.super Llp/y9;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lmq/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lmq/b;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private final d(I)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final b(I)V
    .locals 0

    .line 1
    iget p1, p0, Lmq/b;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lmq/b;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lrq/i;

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    iput-boolean p1, p0, Lrq/i;->d:Z

    .line 12
    .line 13
    iget-object p0, p0, Lrq/i;->e:Ljava/lang/ref/WeakReference;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lrq/h;

    .line 20
    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    check-cast p0, Lmq/f;

    .line 24
    .line 25
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 29
    .line 30
    .line 31
    :cond_0
    :pswitch_0
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Landroid/graphics/Typeface;Z)V
    .locals 0

    .line 1
    iget p1, p0, Lmq/b;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    if-eqz p2, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget-object p0, p0, Lmq/b;->b:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lrq/i;

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    iput-boolean p1, p0, Lrq/i;->d:Z

    .line 15
    .line 16
    iget-object p0, p0, Lrq/i;->e:Ljava/lang/ref/WeakReference;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lrq/h;

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    check-cast p0, Lmq/f;

    .line 27
    .line 28
    invoke-virtual {p0}, Lmq/f;->z()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 32
    .line 33
    .line 34
    :cond_1
    :goto_0
    return-void

    .line 35
    :pswitch_0
    iget-object p0, p0, Lmq/b;->b:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lcom/google/android/material/chip/Chip;

    .line 38
    .line 39
    iget-object p1, p0, Lcom/google/android/material/chip/Chip;->h:Lmq/f;

    .line 40
    .line 41
    iget-boolean p2, p1, Lmq/f;->U1:Z

    .line 42
    .line 43
    if-eqz p2, :cond_2

    .line 44
    .line 45
    iget-object p1, p1, Lmq/f;->N:Ljava/lang/CharSequence;

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    invoke-virtual {p0}, Landroid/widget/TextView;->getText()Ljava/lang/CharSequence;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    :goto_1
    invoke-virtual {p0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
