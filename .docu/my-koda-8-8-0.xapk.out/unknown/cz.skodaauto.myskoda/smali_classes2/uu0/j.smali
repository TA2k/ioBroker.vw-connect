.class public final synthetic Luu0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lfp0/d;


# direct methods
.method public synthetic constructor <init>(Lfp0/d;I)V
    .locals 0

    .line 1
    iput p2, p0, Luu0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu0/j;->e:Lfp0/d;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Luu0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb70/a;

    .line 7
    .line 8
    iget-object p0, p0, Luu0/j;->e:Lfp0/d;

    .line 9
    .line 10
    invoke-direct {v0, p0}, Lb70/a;-><init>(Lfp0/d;)V

    .line 11
    .line 12
    .line 13
    return-object v0

    .line 14
    :pswitch_0
    new-instance v0, Lb70/b;

    .line 15
    .line 16
    iget-object p0, p0, Luu0/j;->e:Lfp0/d;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Lb70/b;-><init>(Lfp0/d;)V

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
