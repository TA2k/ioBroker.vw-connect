.class public final Lzq/d;
.super Lzq/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(Lzq/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Lzq/d;->e:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lzq/m;-><init>(Lzq/l;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public q()V
    .locals 1

    .line 1
    iget v0, p0, Lzq/d;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lzq/m;->b:Lzq/l;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput-object v0, p0, Lzq/l;->r:Landroid/view/View$OnLongClickListener;

    .line 11
    .line 12
    iget-object p0, p0, Lzq/l;->j:Lcom/google/android/material/internal/CheckableImageButton;

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Landroid/view/View;->setOnLongClickListener(Landroid/view/View$OnLongClickListener;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v0}, Ljp/k1;->p(Lcom/google/android/material/internal/CheckableImageButton;Landroid/view/View$OnLongClickListener;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
