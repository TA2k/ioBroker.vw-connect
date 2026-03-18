.class public final Lvy0/y1;
.super Laz0/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lpx0/g;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvy0/y1;->h:I

    .line 2
    .line 3
    invoke-direct {p0, p2, p1}, Laz0/p;-><init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final F(Ljava/lang/Throwable;)Z
    .locals 1

    .line 1
    iget v0, p0, Lvy0/y1;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lzy0/k;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lvy0/p1;->z(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    :goto_0
    return p0

    .line 17
    :pswitch_0
    const/4 p0, 0x0

    .line 18
    return p0

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
