.class public final Lc8/x;
.super Landroid/media/AudioTrack$StreamEventCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lgw0/c;


# direct methods
.method public constructor <init>(Lgw0/c;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc8/x;->a:Lgw0/c;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/media/AudioTrack$StreamEventCallback;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onDataRequest(Landroid/media/AudioTrack;I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc8/x;->a:Lgw0/c;

    .line 2
    .line 3
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lc8/y;

    .line 6
    .line 7
    iget-object p2, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 8
    .line 9
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object p1, p0, Lc8/y;->s:Laq/a;

    .line 17
    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    iget-boolean p0, p0, Lc8/y;->U:Z

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    iget-object p0, p1, Laq/a;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lc8/a0;

    .line 27
    .line 28
    iget-object p0, p0, Lf8/s;->J:La8/l0;

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, La8/l0;->a()V

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method

.method public final onPresentationEnded(Landroid/media/AudioTrack;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lc8/x;->a:Lgw0/c;

    .line 2
    .line 3
    iget-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lc8/y;

    .line 6
    .line 7
    iget-object v0, v0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lc8/y;

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    iput-boolean p1, p0, Lc8/y;->T:Z

    .line 22
    .line 23
    return-void
.end method

.method public final onTearDown(Landroid/media/AudioTrack;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lc8/x;->a:Lgw0/c;

    .line 2
    .line 3
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lc8/y;

    .line 6
    .line 7
    iget-object v0, p0, Lc8/y;->w:Landroid/media/AudioTrack;

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget-object p1, p0, Lc8/y;->s:Laq/a;

    .line 17
    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    iget-boolean p0, p0, Lc8/y;->U:Z

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    iget-object p0, p1, Laq/a;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lc8/a0;

    .line 27
    .line 28
    iget-object p0, p0, Lf8/s;->J:La8/l0;

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, La8/l0;->a()V

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method
