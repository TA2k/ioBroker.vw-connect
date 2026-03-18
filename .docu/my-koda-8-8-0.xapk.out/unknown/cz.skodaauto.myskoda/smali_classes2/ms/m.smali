.class public final synthetic Lms/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lms/p;

.field public final synthetic f:Lqn/s;


# direct methods
.method public synthetic constructor <init>(Lms/p;Lqn/s;I)V
    .locals 0

    .line 1
    iput p3, p0, Lms/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lms/m;->e:Lms/p;

    .line 4
    .line 5
    iput-object p2, p0, Lms/m;->f:Lqn/s;

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
    .locals 1

    .line 1
    iget v0, p0, Lms/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lms/m;->e:Lms/p;

    .line 7
    .line 8
    iget-object p0, p0, Lms/m;->f:Lqn/s;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Lms/p;->a(Lqn/s;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Lms/m;->e:Lms/p;

    .line 15
    .line 16
    iget-object p0, p0, Lms/m;->f:Lqn/s;

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Lms/p;->a(Lqn/s;)V

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
