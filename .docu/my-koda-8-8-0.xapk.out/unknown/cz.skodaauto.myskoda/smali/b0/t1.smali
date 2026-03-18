.class public final synthetic Lb0/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc6/a;

.field public final synthetic f:Landroid/view/Surface;


# direct methods
.method public synthetic constructor <init>(Lc6/a;Landroid/view/Surface;I)V
    .locals 0

    .line 1
    iput p3, p0, Lb0/t1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb0/t1;->e:Lc6/a;

    .line 4
    .line 5
    iput-object p2, p0, Lb0/t1;->f:Landroid/view/Surface;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    .line 1
    iget v0, p0, Lb0/t1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb0/i;

    .line 7
    .line 8
    const/4 v1, 0x4

    .line 9
    iget-object v2, p0, Lb0/t1;->f:Landroid/view/Surface;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2}, Lb0/i;-><init>(ILandroid/view/Surface;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lb0/t1;->e:Lc6/a;

    .line 15
    .line 16
    invoke-interface {p0, v0}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :pswitch_0
    new-instance v0, Lb0/i;

    .line 21
    .line 22
    const/4 v1, 0x3

    .line 23
    iget-object v2, p0, Lb0/t1;->f:Landroid/view/Surface;

    .line 24
    .line 25
    invoke-direct {v0, v1, v2}, Lb0/i;-><init>(ILandroid/view/Surface;)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lb0/t1;->e:Lc6/a;

    .line 29
    .line 30
    invoke-interface {p0, v0}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_1
    new-instance v0, Lb0/i;

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    iget-object v2, p0, Lb0/t1;->f:Landroid/view/Surface;

    .line 38
    .line 39
    invoke-direct {v0, v1, v2}, Lb0/i;-><init>(ILandroid/view/Surface;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lb0/t1;->e:Lc6/a;

    .line 43
    .line 44
    invoke-interface {p0, v0}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
