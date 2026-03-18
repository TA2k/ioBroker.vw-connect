.class public final synthetic Lb/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lb/r;


# direct methods
.method public synthetic constructor <init>(Lb/r;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb/h;->e:Lb/r;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 1

    .line 1
    iget v0, p0, Lb/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb/h;->e:Lb/r;

    .line 7
    .line 8
    invoke-static {p0, p1, p2}, Lb/r;->c(Lb/r;Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    sget-object p1, Landroidx/lifecycle/p;->ON_STOP:Landroidx/lifecycle/p;

    .line 13
    .line 14
    if-ne p2, p1, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lb/h;->e:Lb/r;

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/Window;->peekDecorView()Landroid/view/View;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    if-eqz p0, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0}, Landroid/view/View;->cancelPendingInputEvents()V

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
