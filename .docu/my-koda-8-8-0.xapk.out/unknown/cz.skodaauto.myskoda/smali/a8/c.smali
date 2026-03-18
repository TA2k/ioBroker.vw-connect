.class public final synthetic La8/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/media/AudioManager$OnAudioFocusChangeListener;


# instance fields
.field public final synthetic a:La8/e;


# direct methods
.method public synthetic constructor <init>(La8/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La8/c;->a:La8/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onAudioFocusChange(I)V
    .locals 2

    .line 1
    iget-object p0, p0, La8/c;->a:La8/e;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 v0, -0x3

    .line 7
    const/4 v1, -0x2

    .line 8
    if-eq p1, v0, :cond_2

    .line 9
    .line 10
    if-eq p1, v1, :cond_2

    .line 11
    .line 12
    const/4 v0, -0x1

    .line 13
    const/4 v1, 0x1

    .line 14
    if-eq p1, v0, :cond_1

    .line 15
    .line 16
    if-eq p1, v1, :cond_0

    .line 17
    .line 18
    const-string p0, "AudioFocusManager"

    .line 19
    .line 20
    const-string v0, "Unknown focus change type: "

    .line 21
    .line 22
    invoke-static {v0, p1, p0}, Lvj/b;->w(Ljava/lang/String;ILjava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    const/4 p1, 0x2

    .line 27
    invoke-virtual {p0, p1}, La8/e;->c(I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, v1}, La8/e;->b(I)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_1
    invoke-virtual {p0, v0}, La8/e;->b(I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, La8/e;->a()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, v1}, La8/e;->c(I)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :cond_2
    if-eq p1, v1, :cond_3

    .line 45
    .line 46
    const/4 p1, 0x4

    .line 47
    invoke-virtual {p0, p1}, La8/e;->c(I)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_3
    const/4 p1, 0x0

    .line 52
    invoke-virtual {p0, p1}, La8/e;->b(I)V

    .line 53
    .line 54
    .line 55
    const/4 p1, 0x3

    .line 56
    invoke-virtual {p0, p1}, La8/e;->c(I)V

    .line 57
    .line 58
    .line 59
    return-void
.end method
