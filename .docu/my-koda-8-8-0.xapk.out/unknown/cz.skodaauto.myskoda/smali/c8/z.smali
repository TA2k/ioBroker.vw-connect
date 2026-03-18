.class public final Lc8/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc8/z;

.field public static final b:Lc8/z;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lc8/z;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc8/z;->a:Lc8/z;

    .line 7
    .line 8
    new-instance v0, Lc8/z;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lc8/z;->b:Lc8/z;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public a(Lc8/j;Lt7/c;ILandroid/content/Context;)Landroid/media/AudioTrack;
    .locals 4

    .line 1
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    iget v0, p1, Lc8/j;->b:I

    .line 4
    .line 5
    iget v1, p1, Lc8/j;->c:I

    .line 6
    .line 7
    iget v2, p1, Lc8/j;->a:I

    .line 8
    .line 9
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 10
    .line 11
    new-instance v3, Landroid/media/AudioFormat$Builder;

    .line 12
    .line 13
    invoke-direct {v3}, Landroid/media/AudioFormat$Builder;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Landroid/media/AudioFormat$Builder;->setSampleRate(I)Landroid/media/AudioFormat$Builder;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0, v1}, Landroid/media/AudioFormat$Builder;->setChannelMask(I)Landroid/media/AudioFormat$Builder;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v0, v2}, Landroid/media/AudioFormat$Builder;->setEncoding(I)Landroid/media/AudioFormat$Builder;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0}, Landroid/media/AudioFormat$Builder;->build()Landroid/media/AudioFormat;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iget-boolean v1, p1, Lc8/j;->d:Z

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    new-instance p2, Landroid/media/AudioAttributes$Builder;

    .line 38
    .line 39
    invoke-direct {p2}, Landroid/media/AudioAttributes$Builder;-><init>()V

    .line 40
    .line 41
    .line 42
    const/4 v1, 0x3

    .line 43
    invoke-virtual {p2, v1}, Landroid/media/AudioAttributes$Builder;->setContentType(I)Landroid/media/AudioAttributes$Builder;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    const/16 v1, 0x10

    .line 48
    .line 49
    invoke-virtual {p2, v1}, Landroid/media/AudioAttributes$Builder;->setFlags(I)Landroid/media/AudioAttributes$Builder;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-virtual {p2, v2}, Landroid/media/AudioAttributes$Builder;->setUsage(I)Landroid/media/AudioAttributes$Builder;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-virtual {p2}, Landroid/media/AudioAttributes$Builder;->build()Landroid/media/AudioAttributes;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    goto :goto_0

    .line 62
    :cond_0
    invoke-virtual {p2}, Lt7/c;->a()Lpv/g;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    iget-object p2, p2, Lpv/g;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p2, Landroid/media/AudioAttributes;

    .line 69
    .line 70
    :goto_0
    new-instance v1, Landroid/media/AudioTrack$Builder;

    .line 71
    .line 72
    invoke-direct {v1}, Landroid/media/AudioTrack$Builder;-><init>()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1, p2}, Landroid/media/AudioTrack$Builder;->setAudioAttributes(Landroid/media/AudioAttributes;)Landroid/media/AudioTrack$Builder;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    invoke-virtual {p2, v0}, Landroid/media/AudioTrack$Builder;->setAudioFormat(Landroid/media/AudioFormat;)Landroid/media/AudioTrack$Builder;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    invoke-virtual {p2, v2}, Landroid/media/AudioTrack$Builder;->setTransferMode(I)Landroid/media/AudioTrack$Builder;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    iget v0, p1, Lc8/j;->f:I

    .line 88
    .line 89
    invoke-virtual {p2, v0}, Landroid/media/AudioTrack$Builder;->setBufferSizeInBytes(I)Landroid/media/AudioTrack$Builder;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    invoke-virtual {p2, p3}, Landroid/media/AudioTrack$Builder;->setSessionId(I)Landroid/media/AudioTrack$Builder;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    iget-boolean p1, p1, Lc8/j;->e:Z

    .line 98
    .line 99
    invoke-virtual {p2, p1}, Landroid/media/AudioTrack$Builder;->setOffloadedPlayback(Z)Landroid/media/AudioTrack$Builder;

    .line 100
    .line 101
    .line 102
    const/16 p1, 0x22

    .line 103
    .line 104
    if-lt p0, p1, :cond_1

    .line 105
    .line 106
    if-eqz p4, :cond_1

    .line 107
    .line 108
    invoke-static {p2, p4}, Lc2/h;->w(Landroid/media/AudioTrack$Builder;Landroid/content/Context;)V

    .line 109
    .line 110
    .line 111
    :cond_1
    invoke-virtual {p2}, Landroid/media/AudioTrack$Builder;->build()Landroid/media/AudioTrack;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0
.end method
