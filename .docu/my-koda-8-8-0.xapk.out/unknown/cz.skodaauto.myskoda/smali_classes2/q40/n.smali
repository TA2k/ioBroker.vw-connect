.class public final Lq40/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lq40/o;

.field public final synthetic f:Lqr0/s;


# direct methods
.method public synthetic constructor <init>(Lq40/o;Lqr0/s;I)V
    .locals 0

    .line 1
    iput p3, p0, Lq40/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq40/n;->e:Lq40/o;

    .line 4
    .line 5
    iput-object p2, p0, Lq40/n;->f:Lqr0/s;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p2, p0, Lq40/n;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    iget-object p2, p0, Lq40/n;->e:Lq40/o;

    .line 9
    .line 10
    iget-object p0, p0, Lq40/n;->f:Lqr0/s;

    .line 11
    .line 12
    invoke-static {p2, p1, p0}, Lq40/o;->j(Lq40/o;Lne0/s;Lqr0/s;)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 19
    .line 20
    iget-object p2, p0, Lq40/n;->e:Lq40/o;

    .line 21
    .line 22
    iget-object p0, p0, Lq40/n;->f:Lqr0/s;

    .line 23
    .line 24
    invoke-static {p2, p1, p0}, Lq40/o;->j(Lq40/o;Lne0/s;Lqr0/s;)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
