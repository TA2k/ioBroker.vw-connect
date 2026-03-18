.class public final synthetic Lhh/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lhh/h;


# direct methods
.method public synthetic constructor <init>(Lhh/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhh/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhh/f;->e:Lhh/h;

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
    iget v0, p0, Lhh/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhh/f;->e:Lhh/h;

    .line 7
    .line 8
    invoke-virtual {p0}, Lhh/h;->d()V

    .line 9
    .line 10
    .line 11
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_0
    iget-object p0, p0, Lhh/f;->e:Lhh/h;

    .line 15
    .line 16
    invoke-virtual {p0}, Lhh/h;->g()V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :pswitch_1
    new-instance v0, Ljava/util/concurrent/TimeoutException;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/util/concurrent/TimeoutException;-><init>()V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lhh/f;->e:Lhh/h;

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lhh/h;->f(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
