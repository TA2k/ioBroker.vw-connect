.class public final Lz10/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt7/j0;


# instance fields
.field public final synthetic d:Ll2/b1;

.field public final synthetic e:Ll2/f1;

.field public final synthetic f:Landroidx/media3/exoplayer/ExoPlayer;


# direct methods
.method public constructor <init>(Ll2/b1;Ll2/f1;Landroidx/media3/exoplayer/ExoPlayer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz10/j;->d:Ll2/b1;

    .line 5
    .line 6
    iput-object p2, p0, Lz10/j;->e:Ll2/f1;

    .line 7
    .line 8
    iput-object p3, p0, Lz10/j;->f:Landroidx/media3/exoplayer/ExoPlayer;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final i(I)V
    .locals 3

    .line 1
    const/4 v0, 0x4

    .line 2
    if-ne p1, v0, :cond_0

    .line 3
    .line 4
    iget-object p1, p0, Lz10/j;->d:Ll2/b1;

    .line 5
    .line 6
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-interface {p1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lz10/j;->f:Landroidx/media3/exoplayer/ExoPlayer;

    .line 12
    .line 13
    move-object v0, p1

    .line 14
    check-cast v0, La8/i0;

    .line 15
    .line 16
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 17
    .line 18
    .line 19
    iget v0, v0, La8/i0;->q1:F

    .line 20
    .line 21
    iget-object p0, p0, Lz10/j;->e:Ll2/f1;

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Ll2/f1;->p(F)V

    .line 24
    .line 25
    .line 26
    check-cast p1, Lap0/o;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-object p0, p1

    .line 32
    check-cast p0, La8/i0;

    .line 33
    .line 34
    invoke-virtual {p0}, La8/i0;->h0()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    const-wide/16 v0, 0x0

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-virtual {p1, v0, v1, p0, v2}, Lap0/o;->P(JIZ)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    check-cast p1, La8/i0;

    .line 48
    .line 49
    invoke-virtual {p1}, La8/i0;->L0()V

    .line 50
    .line 51
    .line 52
    const/4 p0, 0x1

    .line 53
    invoke-virtual {p1, p0, v2}, La8/i0;->I0(IZ)V

    .line 54
    .line 55
    .line 56
    :cond_0
    return-void
.end method

.method public final y(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lz10/j;->e:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
