.class public final Landroidx/core/app/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;

.field public e:Ljava/lang/CharSequence;

.field public f:Ljava/lang/CharSequence;

.field public g:Landroid/app/PendingIntent;

.field public h:Landroidx/core/graphics/drawable/IconCompat;

.field public i:I

.field public j:I

.field public k:Z

.field public l:Landroidx/core/app/a0;

.field public m:Ljava/lang/String;

.field public n:Z

.field public o:Z

.field public p:Landroid/os/Bundle;

.field public q:I

.field public r:I

.field public s:Landroid/widget/RemoteViews;

.field public t:Landroid/widget/RemoteViews;

.field public u:Ljava/lang/String;

.field public v:J

.field public w:I

.field public final x:Z

.field public final y:Landroid/app/Notification;

.field public final z:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Landroidx/core/app/x;->b:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Landroidx/core/app/x;->c:Ljava/util/ArrayList;

    .line 17
    .line 18
    new-instance v0, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Landroidx/core/app/x;->d:Ljava/util/ArrayList;

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    iput-boolean v0, p0, Landroidx/core/app/x;->k:Z

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    iput-boolean v1, p0, Landroidx/core/app/x;->o:Z

    .line 30
    .line 31
    iput v1, p0, Landroidx/core/app/x;->q:I

    .line 32
    .line 33
    iput v1, p0, Landroidx/core/app/x;->r:I

    .line 34
    .line 35
    iput v1, p0, Landroidx/core/app/x;->w:I

    .line 36
    .line 37
    new-instance v2, Landroid/app/Notification;

    .line 38
    .line 39
    invoke-direct {v2}, Landroid/app/Notification;-><init>()V

    .line 40
    .line 41
    .line 42
    iput-object v2, p0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 43
    .line 44
    iput-object p1, p0, Landroidx/core/app/x;->a:Landroid/content/Context;

    .line 45
    .line 46
    iput-object p2, p0, Landroidx/core/app/x;->u:Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 49
    .line 50
    .line 51
    move-result-wide p1

    .line 52
    iput-wide p1, v2, Landroid/app/Notification;->when:J

    .line 53
    .line 54
    const/4 p1, -0x1

    .line 55
    iput p1, v2, Landroid/app/Notification;->audioStreamType:I

    .line 56
    .line 57
    iput v1, p0, Landroidx/core/app/x;->j:I

    .line 58
    .line 59
    new-instance p1, Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-object p1, p0, Landroidx/core/app/x;->z:Ljava/util/ArrayList;

    .line 65
    .line 66
    iput-boolean v0, p0, Landroidx/core/app/x;->x:Z

    .line 67
    .line 68
    return-void
.end method

.method public static b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    return-object p0

    .line 4
    :cond_0
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const/16 v1, 0x1400

    .line 9
    .line 10
    if-le v0, v1, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-interface {p0, v0, v1}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :cond_1
    return-object p0
.end method


# virtual methods
.method public final a()Landroid/app/Notification;
    .locals 4

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/core/app/x;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Landroidx/core/app/x;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/core/app/x;->l:Landroidx/core/app/a0;

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {v1, v0}, Landroidx/core/app/a0;->a(Lcom/google/firebase/messaging/w;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Landroid/app/Notification$Builder;

    .line 20
    .line 21
    invoke-virtual {v0}, Landroid/app/Notification$Builder;->build()Landroid/app/Notification;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-object v2, p0, Landroidx/core/app/x;->s:Landroid/widget/RemoteViews;

    .line 26
    .line 27
    if-eqz v2, :cond_1

    .line 28
    .line 29
    iput-object v2, v0, Landroid/app/Notification;->contentView:Landroid/widget/RemoteViews;

    .line 30
    .line 31
    :cond_1
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget-object p0, p0, Landroidx/core/app/x;->l:Landroidx/core/app/a0;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    :cond_2
    if-eqz v1, :cond_5

    .line 39
    .line 40
    iget-object p0, v0, Landroid/app/Notification;->extras:Landroid/os/Bundle;

    .line 41
    .line 42
    if-eqz p0, :cond_5

    .line 43
    .line 44
    iget-boolean v2, v1, Landroidx/core/app/a0;->a:Z

    .line 45
    .line 46
    if-eqz v2, :cond_3

    .line 47
    .line 48
    iget-object v2, v1, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v2, Ljava/lang/CharSequence;

    .line 51
    .line 52
    const-string v3, "android.summaryText"

    .line 53
    .line 54
    invoke-virtual {p0, v3, v2}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    iget-object v2, v1, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v2, Ljava/lang/CharSequence;

    .line 60
    .line 61
    if-eqz v2, :cond_4

    .line 62
    .line 63
    const-string v3, "android.title.big"

    .line 64
    .line 65
    invoke-virtual {p0, v3, v2}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 66
    .line 67
    .line 68
    :cond_4
    invoke-virtual {v1}, Landroidx/core/app/a0;->b()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    const-string v2, "androidx.core.app.extra.COMPAT_TEMPLATE"

    .line 73
    .line 74
    invoke-virtual {p0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    :cond_5
    return-object v0
.end method

.method public final c(Ljava/lang/CharSequence;)V
    .locals 0

    .line 1
    invoke-static {p1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iput-object p1, p0, Landroidx/core/app/x;->f:Ljava/lang/CharSequence;

    .line 6
    .line 7
    return-void
.end method

.method public final d(IZ)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget p2, p0, Landroid/app/Notification;->flags:I

    .line 6
    .line 7
    or-int/2addr p1, p2

    .line 8
    iput p1, p0, Landroid/app/Notification;->flags:I

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget p2, p0, Landroid/app/Notification;->flags:I

    .line 12
    .line 13
    not-int p1, p1

    .line 14
    and-int/2addr p1, p2

    .line 15
    iput p1, p0, Landroid/app/Notification;->flags:I

    .line 16
    .line 17
    return-void
.end method

.method public final e(Landroid/net/Uri;)V
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 2
    .line 3
    iput-object p1, p0, Landroid/app/Notification;->sound:Landroid/net/Uri;

    .line 4
    .line 5
    const/4 p1, -0x1

    .line 6
    iput p1, p0, Landroid/app/Notification;->audioStreamType:I

    .line 7
    .line 8
    invoke-static {}, Landroidx/core/app/w;->b()Landroid/media/AudioAttributes$Builder;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const/4 v0, 0x4

    .line 13
    invoke-static {p1, v0}, Landroidx/core/app/w;->c(Landroid/media/AudioAttributes$Builder;I)Landroid/media/AudioAttributes$Builder;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    const/4 v0, 0x5

    .line 18
    invoke-static {p1, v0}, Landroidx/core/app/w;->d(Landroid/media/AudioAttributes$Builder;I)Landroid/media/AudioAttributes$Builder;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-static {p1}, Landroidx/core/app/w;->a(Landroid/media/AudioAttributes$Builder;)Landroid/media/AudioAttributes;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Landroid/app/Notification;->audioAttributes:Landroid/media/AudioAttributes;

    .line 27
    .line 28
    return-void
.end method

.method public final f(Landroidx/core/app/a0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/core/app/x;->l:Landroidx/core/app/a0;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput-object p1, p0, Landroidx/core/app/x;->l:Landroidx/core/app/a0;

    .line 6
    .line 7
    iget-object v0, p1, Landroidx/core/app/a0;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Landroidx/core/app/x;

    .line 10
    .line 11
    if-eq v0, p0, :cond_0

    .line 12
    .line 13
    iput-object p0, p1, Landroidx/core/app/a0;->b:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final g(Ljava/lang/CharSequence;)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 2
    .line 3
    invoke-static {p1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iput-object p1, p0, Landroid/app/Notification;->tickerText:Ljava/lang/CharSequence;

    .line 8
    .line 9
    return-void
.end method
