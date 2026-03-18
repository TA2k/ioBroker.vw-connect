.class public final Lc8/c;
.super Landroid/media/AudioDeviceCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lc8/f;


# direct methods
.method public constructor <init>(Lc8/f;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc8/c;->a:Lc8/f;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/media/AudioDeviceCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onAudioDevicesAdded([Landroid/media/AudioDeviceInfo;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lc8/c;->a:Lc8/f;

    .line 2
    .line 3
    iget-object p1, p0, Lc8/f;->b:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Landroid/content/Context;

    .line 6
    .line 7
    iget-object v0, p0, Lc8/f;->j:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lt7/c;

    .line 10
    .line 11
    iget-object v1, p0, Lc8/f;->i:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, La0/j;

    .line 14
    .line 15
    invoke-static {p1, v0, v1}, Lc8/b;->c(Landroid/content/Context;Lt7/c;La0/j;)Lc8/b;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, p1}, Lc8/f;->d(Lc8/b;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final onAudioDevicesRemoved([Landroid/media/AudioDeviceInfo;)V
    .locals 4

    .line 1
    iget-object p0, p0, Lc8/c;->a:Lc8/f;

    .line 2
    .line 3
    iget-object v0, p0, Lc8/f;->i:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, La0/j;

    .line 6
    .line 7
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 8
    .line 9
    array-length v1, p1

    .line 10
    const/4 v2, 0x0

    .line 11
    :goto_0
    if-ge v2, v1, :cond_1

    .line 12
    .line 13
    aget-object v3, p1, v2

    .line 14
    .line 15
    invoke-static {v3, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    iput-object p1, p0, Lc8/f;->i:Ljava/lang/Object;

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    :goto_1
    iget-object p1, p0, Lc8/f;->b:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p1, Landroid/content/Context;

    .line 31
    .line 32
    iget-object v0, p0, Lc8/f;->j:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lt7/c;

    .line 35
    .line 36
    iget-object v1, p0, Lc8/f;->i:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, La0/j;

    .line 39
    .line 40
    invoke-static {p1, v0, v1}, Lc8/b;->c(Landroid/content/Context;Lt7/c;La0/j;)Lc8/b;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-virtual {p0, p1}, Lc8/f;->d(Lc8/b;)V

    .line 45
    .line 46
    .line 47
    return-void
.end method
