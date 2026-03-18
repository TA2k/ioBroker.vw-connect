.class public final synthetic Lio0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroidx/media3/exoplayer/ExoPlayer;


# direct methods
.method public synthetic constructor <init>(Landroidx/media3/exoplayer/ExoPlayer;I)V
    .locals 0

    .line 1
    iput p2, p0, Lio0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lio0/a;->e:Landroidx/media3/exoplayer/ExoPlayer;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lio0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Landroid/content/Context;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const v0, 0x7f0d02bc

    .line 18
    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    const/4 v2, 0x0

    .line 22
    invoke-virtual {p1, v0, v1, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    const-string v0, "null cannot be cast to non-null type androidx.media3.ui.PlayerView"

    .line 27
    .line 28
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    check-cast p1, Landroidx/media3/ui/PlayerView;

    .line 32
    .line 33
    invoke-virtual {p1, v2}, Landroid/view/View;->setBackgroundColor(I)V

    .line 34
    .line 35
    .line 36
    new-instance v0, Landroid/widget/FrameLayout$LayoutParams;

    .line 37
    .line 38
    const/4 v1, -0x1

    .line 39
    invoke-direct {v0, v1, v1}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p1, v2}, Landroidx/media3/ui/PlayerView;->setUseController(Z)V

    .line 46
    .line 47
    .line 48
    const/4 v0, 0x3

    .line 49
    invoke-virtual {p1, v0}, Landroidx/media3/ui/PlayerView;->setResizeMode(I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1, v2}, Landroidx/media3/ui/PlayerView;->setShutterBackgroundColor(I)V

    .line 53
    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-virtual {p1, v0}, Landroidx/media3/ui/PlayerView;->setKeepContentOnPlayerReset(Z)V

    .line 57
    .line 58
    .line 59
    iget-object p0, p0, Lio0/a;->e:Landroidx/media3/exoplayer/ExoPlayer;

    .line 60
    .line 61
    invoke-virtual {p1, p0}, Landroidx/media3/ui/PlayerView;->setPlayer(Lt7/l0;)V

    .line 62
    .line 63
    .line 64
    return-object p1

    .line 65
    :pswitch_0
    const-string v0, "it"

    .line 66
    .line 67
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    const v0, 0x7f0d02bc

    .line 75
    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    const/4 v2, 0x0

    .line 79
    invoke-virtual {p1, v0, v1, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    const-string v0, "null cannot be cast to non-null type androidx.media3.ui.PlayerView"

    .line 84
    .line 85
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    check-cast p1, Landroidx/media3/ui/PlayerView;

    .line 89
    .line 90
    invoke-virtual {p1, v2}, Landroid/view/View;->setBackgroundColor(I)V

    .line 91
    .line 92
    .line 93
    new-instance v0, Landroid/widget/FrameLayout$LayoutParams;

    .line 94
    .line 95
    const/4 v1, -0x1

    .line 96
    invoke-direct {v0, v1, v1}, Landroid/widget/FrameLayout$LayoutParams;-><init>(II)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, v2}, Landroidx/media3/ui/PlayerView;->setUseController(Z)V

    .line 103
    .line 104
    .line 105
    const/4 v0, 0x4

    .line 106
    invoke-virtual {p1, v0}, Landroidx/media3/ui/PlayerView;->setResizeMode(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p1, v2}, Landroidx/media3/ui/PlayerView;->setShutterBackgroundColor(I)V

    .line 110
    .line 111
    .line 112
    const/4 v0, 0x1

    .line 113
    invoke-virtual {p1, v0}, Landroidx/media3/ui/PlayerView;->setKeepContentOnPlayerReset(Z)V

    .line 114
    .line 115
    .line 116
    iget-object p0, p0, Lio0/a;->e:Landroidx/media3/exoplayer/ExoPlayer;

    .line 117
    .line 118
    invoke-virtual {p1, p0}, Landroidx/media3/ui/PlayerView;->setPlayer(Lt7/l0;)V

    .line 119
    .line 120
    .line 121
    return-object p1

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
