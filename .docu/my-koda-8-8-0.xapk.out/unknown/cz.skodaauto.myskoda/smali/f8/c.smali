.class public final synthetic Lf8/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgr/m;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lf8/c;->d:I

    .line 2
    .line 3
    iput p1, p0, Lf8/c;->e:I

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lf8/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroid/os/HandlerThread;

    .line 7
    .line 8
    const-string v1, "ExoPlayer:MediaCodecQueueingThread:"

    .line 9
    .line 10
    iget p0, p0, Lf8/c;->e:I

    .line 11
    .line 12
    invoke-static {p0, v1}, Lf8/d;->s(ILjava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, p0}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v0, Landroid/os/HandlerThread;

    .line 21
    .line 22
    const-string v1, "ExoPlayer:MediaCodecAsyncAdapter:"

    .line 23
    .line 24
    iget p0, p0, Lf8/c;->e:I

    .line 25
    .line 26
    invoke-static {p0, v1}, Lf8/d;->s(ILjava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-direct {v0, p0}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    return-object v0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
