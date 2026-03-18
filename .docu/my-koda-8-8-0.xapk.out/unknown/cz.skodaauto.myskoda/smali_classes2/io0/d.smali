.class public final synthetic Lio0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroidx/media3/exoplayer/ExoPlayer;


# direct methods
.method public synthetic constructor <init>(Landroidx/media3/exoplayer/ExoPlayer;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lio0/d;->e:Landroidx/media3/exoplayer/ExoPlayer;

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
    .locals 2

    .line 1
    iget v0, p0, Lio0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lhz/a;

    .line 7
    .line 8
    const/16 v1, 0x1c

    .line 9
    .line 10
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    sget-object v1, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 14
    .line 15
    invoke-static {v1, v0}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lio0/d;->e:Landroidx/media3/exoplayer/ExoPlayer;

    .line 19
    .line 20
    check-cast p0, Lap0/o;

    .line 21
    .line 22
    check-cast p0, La8/i0;

    .line 23
    .line 24
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 25
    .line 26
    .line 27
    const/4 v0, 0x1

    .line 28
    const/4 v1, 0x0

    .line 29
    invoke-virtual {p0, v0, v1}, La8/i0;->I0(IZ)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    iget-object p0, p0, Lio0/d;->e:Landroidx/media3/exoplayer/ExoPlayer;

    .line 36
    .line 37
    check-cast p0, La8/i0;

    .line 38
    .line 39
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, La8/i0;->X:Lt7/o;

    .line 43
    .line 44
    if-eqz p0, :cond_0

    .line 45
    .line 46
    iget-object p0, p0, Lt7/o;->k:Ljava/lang/String;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    const/4 p0, 0x0

    .line 50
    :goto_0
    const-string v0, "VideoPlayer: Audio Format: "

    .line 51
    .line 52
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
