.class public final Lrn0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/h2;

.field public final synthetic f:Lun0/a;


# direct methods
.method public synthetic constructor <init>(Lyy0/h2;Lun0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lrn0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrn0/e;->e:Lyy0/h2;

    .line 4
    .line 5
    iput-object p2, p0, Lrn0/e;->f:Lun0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lrn0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lrn0/d;

    .line 7
    .line 8
    iget-object v1, p0, Lrn0/e;->f:Lun0/a;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    invoke-direct {v0, p1, v1, v2}, Lrn0/d;-><init>(Lyy0/j;Lun0/a;I)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lrn0/e;->e:Lyy0/h2;

    .line 15
    .line 16
    invoke-virtual {p0, v0, p2}, Lyy0/h2;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_0
    new-instance v0, Lrn0/d;

    .line 23
    .line 24
    iget-object v1, p0, Lrn0/e;->f:Lun0/a;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    invoke-direct {v0, p1, v1, v2}, Lrn0/d;-><init>(Lyy0/j;Lun0/a;I)V

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lrn0/e;->e:Lyy0/h2;

    .line 31
    .line 32
    invoke-virtual {p0, v0, p2}, Lyy0/h2;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
