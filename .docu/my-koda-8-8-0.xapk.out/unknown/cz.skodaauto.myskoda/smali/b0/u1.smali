.class public final Lb0/u1;
.super Lh0/t0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic o:I

.field public final p:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/view/Surface;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lb0/u1;->o:I

    .line 3
    sget-object v0, Lh0/t0;->k:Landroid/util/Size;

    const/4 v1, 0x0

    invoke-direct {p0, v0, v1}, Lh0/t0;-><init>(Landroid/util/Size;I)V

    .line 4
    iput-object p1, p0, Lb0/u1;->p:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/Surface;Landroid/util/Size;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lb0/u1;->o:I

    .line 1
    invoke-direct {p0, p2, p3}, Lh0/t0;-><init>(Landroid/util/Size;I)V

    .line 2
    iput-object p1, p0, Lb0/u1;->p:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lb0/x1;Landroid/util/Size;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb0/u1;->o:I

    .line 5
    iput-object p1, p0, Lb0/u1;->p:Ljava/lang/Object;

    const/16 p1, 0x22

    invoke-direct {p0, p2, p1}, Lh0/t0;-><init>(Landroid/util/Size;I)V

    return-void
.end method


# virtual methods
.method public final f()Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 1

    .line 1
    iget v0, p0, Lb0/u1;->o:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb0/u1;->p:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Landroid/view/Surface;

    .line 9
    .line 10
    invoke-static {p0}, Lk0/h;->c(Ljava/lang/Object;)Lk0/j;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lb0/u1;->p:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lb0/x1;

    .line 18
    .line 19
    iget-object p0, p0, Lb0/x1;->f:Ly4/k;

    .line 20
    .line 21
    return-object p0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
