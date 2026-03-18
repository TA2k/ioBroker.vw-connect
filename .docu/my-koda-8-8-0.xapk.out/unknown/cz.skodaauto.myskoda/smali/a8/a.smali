.class public final La8/a;
.super Landroid/content/BroadcastReceiver;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:La8/f0;

.field public final b:Lw7/t;

.field public final synthetic c:La8/b;


# direct methods
.method public constructor <init>(La8/b;Lw7/t;La8/f0;)V
    .locals 0

    .line 1
    iput-object p1, p0, La8/a;->c:La8/b;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, La8/a;->b:Lw7/t;

    .line 7
    .line 8
    iput-object p3, p0, La8/a;->a:La8/f0;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0

    .line 1
    const-string p1, "android.media.AUDIO_BECOMING_NOISY"

    .line 2
    .line 3
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-virtual {p1, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    new-instance p1, La0/d;

    .line 14
    .line 15
    const/4 p2, 0x2

    .line 16
    invoke-direct {p1, p0, p2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, La8/a;->b:Lw7/t;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method
