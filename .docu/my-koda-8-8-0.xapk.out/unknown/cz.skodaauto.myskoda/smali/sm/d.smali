.class public final Lsm/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/f;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lvy0/l;


# direct methods
.method public synthetic constructor <init>(Lvy0/l;I)V
    .locals 0

    .line 1
    iput p2, p0, Lsm/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsm/d;->e:Lvy0/l;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onStart(Landroidx/lifecycle/x;)V
    .locals 0

    .line 1
    iget p1, p0, Lsm/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lsm/d;->e:Lvy0/l;

    .line 7
    .line 8
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Lsm/d;->e:Lvy0/l;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
