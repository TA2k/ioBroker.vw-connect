.class public final synthetic Lf8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/media/MediaCodec$OnFrameRenderedListener;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lm8/k;


# direct methods
.method public synthetic constructor <init>(Lf8/m;Lm8/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lf8/b;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lf8/b;->b:Lm8/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onFrameRendered(Landroid/media/MediaCodec;JJ)V
    .locals 0

    .line 1
    iget p1, p0, Lf8/b;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lf8/b;->b:Lm8/k;

    .line 7
    .line 8
    iget-object p1, p0, Lm8/k;->d:Landroid/os/Handler;

    .line 9
    .line 10
    sget p4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 11
    .line 12
    const/16 p5, 0x1e

    .line 13
    .line 14
    if-ge p4, p5, :cond_0

    .line 15
    .line 16
    const/16 p0, 0x20

    .line 17
    .line 18
    shr-long p4, p2, p0

    .line 19
    .line 20
    long-to-int p0, p4

    .line 21
    long-to-int p2, p2

    .line 22
    const/4 p3, 0x0

    .line 23
    invoke-static {p1, p3, p0, p2}, Landroid/os/Message;->obtain(Landroid/os/Handler;III)Landroid/os/Message;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {p1, p0}, Landroid/os/Handler;->sendMessageAtFrontOfQueue(Landroid/os/Message;)Z

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {p0, p2, p3}, Lm8/k;->a(J)V

    .line 32
    .line 33
    .line 34
    :goto_0
    return-void

    .line 35
    :pswitch_0
    iget-object p0, p0, Lf8/b;->b:Lm8/k;

    .line 36
    .line 37
    iget-object p1, p0, Lm8/k;->d:Landroid/os/Handler;

    .line 38
    .line 39
    sget p4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 40
    .line 41
    const/16 p5, 0x1e

    .line 42
    .line 43
    if-ge p4, p5, :cond_1

    .line 44
    .line 45
    const/16 p0, 0x20

    .line 46
    .line 47
    shr-long p4, p2, p0

    .line 48
    .line 49
    long-to-int p0, p4

    .line 50
    long-to-int p2, p2

    .line 51
    const/4 p3, 0x0

    .line 52
    invoke-static {p1, p3, p0, p2}, Landroid/os/Message;->obtain(Landroid/os/Handler;III)Landroid/os/Message;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p1, p0}, Landroid/os/Handler;->sendMessageAtFrontOfQueue(Landroid/os/Message;)Z

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    invoke-virtual {p0, p2, p3}, Lm8/k;->a(J)V

    .line 61
    .line 62
    .line 63
    :goto_1
    return-void

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
