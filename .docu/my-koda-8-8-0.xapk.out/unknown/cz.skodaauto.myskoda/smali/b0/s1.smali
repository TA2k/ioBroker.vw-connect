.class public final synthetic Lb0/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lb0/x1;


# direct methods
.method public synthetic constructor <init>(Lb0/x1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb0/s1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb0/s1;->e:Lb0/x1;

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
    .locals 1

    .line 1
    iget v0, p0, Lb0/s1;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lb0/s1;->e:Lb0/x1;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lb0/x1;->c()Z

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Lb0/x1;->f:Ly4/k;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    invoke-virtual {p0, v0}, Ly4/k;->cancel(Z)Z

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
