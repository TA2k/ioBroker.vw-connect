.class public final synthetic Lc8/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/media/AudioRouting$OnRoutingChangedListener;


# instance fields
.field public final synthetic a:Lgw0/c;


# direct methods
.method public synthetic constructor <init>(Lgw0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc8/v;->a:Lgw0/c;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onRoutingChanged(Landroid/media/AudioRouting;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lc8/v;->a:Lgw0/c;

    .line 2
    .line 3
    iget-object v0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lc8/v;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-interface {p1}, Landroid/media/AudioRouting;->getRoutedDevice()Landroid/media/AudioDeviceInfo;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lc8/f;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lc8/f;->f(Landroid/media/AudioDeviceInfo;)V

    .line 21
    .line 22
    .line 23
    :cond_1
    :goto_0
    return-void
.end method
