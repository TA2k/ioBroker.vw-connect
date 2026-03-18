.class public final synthetic Lpv/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/n;
.implements Lkx0/a;
.implements Lk0/c;
.implements Lvp/q0;
.implements Lxo/a;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lpv/g;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void

    .line 6
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    .line 7
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    const-class p1, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;

    .line 9
    sget-object v0, Lx/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    .line 10
    check-cast p1, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void

    .line 11
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    const/16 v0, 0x10

    invoke-direct {p1, v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(I)V

    .line 13
    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void

    .line 14
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x14 -> :sswitch_3
        0x16 -> :sswitch_2
        0x1a -> :sswitch_1
        0x1d -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lpv/g;->d:I

    iput-object p3, p0, Lpv/g;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/widget/EditText;)V
    .locals 1

    const/16 v0, 0xb

    iput v0, p0, Lpv/g;->d:I

    .line 33
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 34
    new-instance v0, Lvp/y1;

    invoke-direct {v0, p1}, Lvp/y1;-><init>(Landroid/widget/EditText;)V

    iput-object v0, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ld01/x;)V
    .locals 1

    const/16 v0, 0x1b

    iput v0, p0, Lpv/g;->d:I

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    const-class v0, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;

    .line 22
    invoke-virtual {p1, v0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    check-cast p1, Landroidx/camera/camera2/internal/compat/quirk/CaptureSessionOnClosedNotCalledQuirk;

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lil/j;Lpv/g;)V
    .locals 0

    const/4 p2, 0x3

    iput p2, p0, Lpv/g;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lpv/g;->d:I

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lss/b;)V
    .locals 2

    const/16 v0, 0xd

    iput v0, p0, Lpv/g;->d:I

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    new-instance v0, Ljava/io/File;

    iget-object p1, p1, Lss/b;->g:Ljava/lang/Object;

    check-cast p1, Ljava/io/File;

    const-string v1, "com.crashlytics.settings.json"

    invoke-direct {v0, p1, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 19
    iput-object v0, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lt7/c;)V
    .locals 2

    const/4 p1, 0x6

    iput p1, p0, Lpv/g;->d:I

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    new-instance p1, Landroid/media/AudioAttributes$Builder;

    invoke-direct {p1}, Landroid/media/AudioAttributes$Builder;-><init>()V

    const/4 v0, 0x0

    .line 25
    invoke-virtual {p1, v0}, Landroid/media/AudioAttributes$Builder;->setContentType(I)Landroid/media/AudioAttributes$Builder;

    move-result-object p1

    .line 26
    invoke-virtual {p1, v0}, Landroid/media/AudioAttributes$Builder;->setFlags(I)Landroid/media/AudioAttributes$Builder;

    move-result-object p1

    const/4 v0, 0x1

    .line 27
    invoke-virtual {p1, v0}, Landroid/media/AudioAttributes$Builder;->setUsage(I)Landroid/media/AudioAttributes$Builder;

    move-result-object p1

    .line 28
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 29
    invoke-virtual {p1, v0}, Landroid/media/AudioAttributes$Builder;->setAllowedCapturePolicy(I)Landroid/media/AudioAttributes$Builder;

    const/16 v0, 0x20

    if-lt v1, v0, :cond_0

    .line 30
    invoke-static {p1}, Le6/b;->k(Landroid/media/AudioAttributes$Builder;)V

    .line 31
    invoke-static {p1}, Le6/b;->e(Landroid/media/AudioAttributes$Builder;)V

    .line 32
    :cond_0
    invoke-virtual {p1}, Landroid/media/AudioAttributes$Builder;->build()Landroid/media/AudioAttributes;

    move-result-object p1

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lyo/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lpv/g;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object p1, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>([J)V
    .locals 5

    const/16 v0, 0x10

    iput v0, p0, Lpv/g;->d:I

    .line 35
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_4

    .line 36
    array-length v0, p1

    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    move-result-object p1

    .line 37
    new-instance v0, Landroidx/collection/d0;

    array-length v1, p1

    invoke-direct {v0, v1}, Landroidx/collection/d0;-><init>(I)V

    .line 38
    iget v1, v0, Landroidx/collection/d0;->b:I

    if-ltz v1, :cond_3

    .line 39
    array-length v2, p1

    if-nez v2, :cond_0

    goto :goto_0

    .line 40
    :cond_0
    array-length v2, p1

    add-int/2addr v2, v1

    .line 41
    iget-object v3, v0, Landroidx/collection/d0;->a:[J

    .line 42
    array-length v4, v3

    if-ge v4, v2, :cond_1

    .line 43
    array-length v4, v3

    mul-int/lit8 v4, v4, 0x3

    div-int/lit8 v4, v4, 0x2

    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    move-result v2

    .line 44
    invoke-static {v3, v2}, Ljava/util/Arrays;->copyOf([JI)[J

    move-result-object v2

    const-string v3, "copyOf(...)"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object v2, v0, Landroidx/collection/d0;->a:[J

    .line 45
    :cond_1
    iget-object v2, v0, Landroidx/collection/d0;->a:[J

    .line 46
    iget v3, v0, Landroidx/collection/d0;->b:I

    if-eq v1, v3, :cond_2

    .line 47
    array-length v4, p1

    add-int/2addr v4, v1

    .line 48
    invoke-static {v2, v2, v4, v1, v3}, Lmx0/n;->k([J[JIII)V

    :cond_2
    const/4 v3, 0x0

    .line 49
    array-length v4, p1

    invoke-static {p1, v2, v1, v3, v4}, Lmx0/n;->k([J[JIII)V

    .line 50
    iget v1, v0, Landroidx/collection/d0;->b:I

    array-length p1, p1

    add-int/2addr v1, p1

    iput v1, v0, Landroidx/collection/d0;->b:I

    goto :goto_0

    .line 51
    :cond_3
    const-string p0, ""

    invoke-static {p0}, La1/a;->d(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0

    .line 52
    :cond_4
    new-instance v0, Landroidx/collection/d0;

    const/16 p1, 0x10

    .line 53
    invoke-direct {v0, p1}, Landroidx/collection/d0;-><init>(I)V

    .line 54
    :goto_0
    iput-object v0, p0, Lpv/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public static b(Ltl/h;Ljava/lang/Throwable;)Ltl/d;
    .locals 3

    .line 1
    new-instance v0, Ltl/d;

    .line 2
    .line 3
    instance-of v1, p1, Ltl/k;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v1, p0, Ltl/h;->z:Ltl/b;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object v2, Lxl/b;->a:Ltl/b;

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    iget-object v1, p0, Ltl/h;->z:Ltl/b;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    sget-object v1, Lxl/b;->a:Ltl/b;

    .line 27
    .line 28
    :goto_0
    const/4 v1, 0x0

    .line 29
    invoke-direct {v0, v1, p0, p1}, Ltl/d;-><init>(Landroid/graphics/drawable/Drawable;Ltl/h;Ljava/lang/Throwable;)V

    .line 30
    .line 31
    .line 32
    return-object v0
.end method

.method public static d(Lv/b;)Lpv/g;
    .locals 4

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x21

    .line 5
    .line 6
    if-lt v0, v2, :cond_2

    .line 7
    .line 8
    invoke-static {}, Li2/p0;->e()Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    invoke-virtual {p0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-static {p0}, Li2/p0;->f(Ljava/lang/Object;)Landroid/hardware/camera2/params/DynamicRangeProfiles;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-nez p0, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    if-lt v0, v2, :cond_1

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 v0, 0x0

    .line 28
    :goto_0
    const-string v1, "DynamicRangeProfiles can only be converted to DynamicRangesCompat on API 33 or higher."

    .line 29
    .line 30
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    new-instance v1, Lpv/g;

    .line 34
    .line 35
    new-instance v0, Lw/c;

    .line 36
    .line 37
    invoke-direct {v0, p0}, Lw/c;-><init>(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    const/16 p0, 0x13

    .line 41
    .line 42
    invoke-direct {v1, v0, p0}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    :cond_2
    :goto_1
    if-nez v1, :cond_3

    .line 46
    .line 47
    sget-object p0, Lw/d;->a:Lpv/g;

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_3
    return-object v1
.end method

.method public static k(Lb0/n1;Ltl/h;Lrl/a;Lrl/b;)Ltl/n;
    .locals 8

    .line 1
    new-instance v0, Ltl/n;

    .line 2
    .line 3
    iget-object v1, p3, Lrl/b;->a:Landroid/graphics/Bitmap;

    .line 4
    .line 5
    iget-object v2, p1, Ltl/h;->a:Landroid/content/Context;

    .line 6
    .line 7
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    move-object v3, v1

    .line 12
    new-instance v1, Landroid/graphics/drawable/BitmapDrawable;

    .line 13
    .line 14
    invoke-direct {v1, v2, v3}, Landroid/graphics/drawable/BitmapDrawable;-><init>(Landroid/content/res/Resources;Landroid/graphics/Bitmap;)V

    .line 15
    .line 16
    .line 17
    sget-object v3, Lkl/e;->d:Lkl/e;

    .line 18
    .line 19
    iget-object p3, p3, Lrl/b;->b:Ljava/util/Map;

    .line 20
    .line 21
    const-string v2, "coil#disk_cache_key"

    .line 22
    .line 23
    invoke-interface {p3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    instance-of v4, v2, Ljava/lang/String;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    if-eqz v4, :cond_0

    .line 31
    .line 32
    check-cast v2, Ljava/lang/String;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move-object v2, v5

    .line 36
    :goto_0
    const-string v4, "coil#is_sampled"

    .line 37
    .line 38
    invoke-interface {p3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p3

    .line 42
    instance-of v4, p3, Ljava/lang/Boolean;

    .line 43
    .line 44
    if-eqz v4, :cond_1

    .line 45
    .line 46
    move-object v5, p3

    .line 47
    check-cast v5, Ljava/lang/Boolean;

    .line 48
    .line 49
    :cond_1
    const/4 p3, 0x0

    .line 50
    if-eqz v5, :cond_2

    .line 51
    .line 52
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    move v6, v4

    .line 57
    goto :goto_1

    .line 58
    :cond_2
    move v6, p3

    .line 59
    :goto_1
    sget-object v4, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 60
    .line 61
    if-eqz p0, :cond_3

    .line 62
    .line 63
    iget-boolean p0, p0, Lb0/n1;->e:Z

    .line 64
    .line 65
    if-eqz p0, :cond_3

    .line 66
    .line 67
    const/4 p3, 0x1

    .line 68
    :cond_3
    move-object v4, p2

    .line 69
    move v7, p3

    .line 70
    move-object v5, v2

    .line 71
    move-object v2, p1

    .line 72
    invoke-direct/range {v0 .. v7}, Ltl/n;-><init>(Landroid/graphics/drawable/Drawable;Ltl/h;Lkl/e;Lrl/a;Ljava/lang/String;ZZ)V

    .line 73
    .line 74
    .line 75
    return-object v0
.end method


# virtual methods
.method public a()Lau/a0;
    .locals 6

    .line 1
    invoke-static {}, Lau/a0;->L()Lau/x;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 8
    .line 9
    iget-object v1, v1, Lcom/google/firebase/perf/metrics/Trace;->g:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lau/x;->o(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 17
    .line 18
    iget-object v1, v1, Lcom/google/firebase/perf/metrics/Trace;->n:Lzt/h;

    .line 19
    .line 20
    iget-wide v1, v1, Lzt/h;->d:J

    .line 21
    .line 22
    invoke-virtual {v0, v1, v2}, Lau/x;->m(J)V

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 28
    .line 29
    iget-object v2, v1, Lcom/google/firebase/perf/metrics/Trace;->n:Lzt/h;

    .line 30
    .line 31
    iget-object v1, v1, Lcom/google/firebase/perf/metrics/Trace;->o:Lzt/h;

    .line 32
    .line 33
    invoke-virtual {v2, v1}, Lzt/h;->k(Lzt/h;)J

    .line 34
    .line 35
    .line 36
    move-result-wide v1

    .line 37
    invoke-virtual {v0, v1, v2}, Lau/x;->n(J)V

    .line 38
    .line 39
    .line 40
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 43
    .line 44
    iget-object v1, v1, Lcom/google/firebase/perf/metrics/Trace;->h:Ljava/util/concurrent/ConcurrentHashMap;

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_0

    .line 59
    .line 60
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Ltt/c;

    .line 65
    .line 66
    iget-object v3, v2, Ltt/c;->d:Ljava/lang/String;

    .line 67
    .line 68
    iget-object v2, v2, Ltt/c;->e:Ljava/util/concurrent/atomic/AtomicLong;

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicLong;->get()J

    .line 71
    .line 72
    .line 73
    move-result-wide v4

    .line 74
    invoke-virtual {v0, v4, v5, v3}, Lau/x;->l(JLjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_0
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 81
    .line 82
    iget-object v1, v1, Lcom/google/firebase/perf/metrics/Trace;->k:Ljava/util/ArrayList;

    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-nez v2, :cond_1

    .line 89
    .line 90
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-eqz v2, :cond_1

    .line 99
    .line 100
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    check-cast v2, Lcom/google/firebase/perf/metrics/Trace;

    .line 105
    .line 106
    new-instance v3, Lpv/g;

    .line 107
    .line 108
    const/16 v4, 0x8

    .line 109
    .line 110
    invoke-direct {v3, v2, v4}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v3}, Lpv/g;->a()Lau/a0;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    invoke-virtual {v0, v2}, Lau/x;->k(Lau/a0;)V

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_1
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v1, Lcom/google/firebase/perf/metrics/Trace;

    .line 124
    .line 125
    invoke-virtual {v1}, Lcom/google/firebase/perf/metrics/Trace;->getAttributes()Ljava/util/Map;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 130
    .line 131
    .line 132
    iget-object v2, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 133
    .line 134
    check-cast v2, Lau/a0;

    .line 135
    .line 136
    invoke-static {v2}, Lau/a0;->w(Lau/a0;)Lcom/google/protobuf/i0;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    invoke-virtual {v2, v1}, Lcom/google/protobuf/i0;->putAll(Ljava/util/Map;)V

    .line 141
    .line 142
    .line 143
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p0, Lcom/google/firebase/perf/metrics/Trace;

    .line 146
    .line 147
    iget-object v1, p0, Lcom/google/firebase/perf/metrics/Trace;->j:Ljava/util/List;

    .line 148
    .line 149
    monitor-enter v1

    .line 150
    :try_start_0
    new-instance v2, Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 153
    .line 154
    .line 155
    iget-object p0, p0, Lcom/google/firebase/perf/metrics/Trace;->j:Ljava/util/List;

    .line 156
    .line 157
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    :cond_2
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    if-eqz v3, :cond_3

    .line 166
    .line 167
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    check-cast v3, Lwt/a;

    .line 172
    .line 173
    if-eqz v3, :cond_2

    .line 174
    .line 175
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    goto :goto_2

    .line 179
    :catchall_0
    move-exception p0

    .line 180
    goto :goto_3

    .line 181
    :cond_3
    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 186
    invoke-static {p0}, Lwt/a;->i(Ljava/util/List;)[Lau/w;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    if-eqz p0, :cond_4

    .line 191
    .line 192
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    invoke-virtual {v0}, Lcom/google/protobuf/n;->j()V

    .line 197
    .line 198
    .line 199
    iget-object v1, v0, Lcom/google/protobuf/n;->e:Lcom/google/protobuf/p;

    .line 200
    .line 201
    check-cast v1, Lau/a0;

    .line 202
    .line 203
    check-cast p0, Ljava/util/List;

    .line 204
    .line 205
    invoke-static {v1, p0}, Lau/a0;->y(Lau/a0;Ljava/util/List;)V

    .line 206
    .line 207
    .line 208
    :cond_4
    invoke-virtual {v0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    check-cast p0, Lau/a0;

    .line 213
    .line 214
    return-object p0

    .line 215
    :goto_3
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 216
    throw p0
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget v0, p0, Lpv/g;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    packed-switch v0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    check-cast p2, Laq/k;

    .line 8
    .line 9
    check-cast p1, Lxo/i;

    .line 10
    .line 11
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lxo/k;

    .line 16
    .line 17
    new-instance v0, Lxo/e;

    .line 18
    .line 19
    sget-object v2, Lgv/a;->n:Lgv/a;

    .line 20
    .line 21
    invoke-direct {v0, p2, v2}, Lxo/e;-><init>(Laq/k;Lxo/a;)V

    .line 22
    .line 23
    .line 24
    invoke-static {}, Lkp/b8;->b()Lko/f;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Lxo/c;

    .line 31
    .line 32
    invoke-virtual {p1}, Lxo/k;->a()Landroid/os/Parcel;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    sget v3, Lfp/a;->a:I

    .line 37
    .line 38
    invoke-virtual {v2, p0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 45
    .line 46
    .line 47
    const/4 p0, 0x0

    .line 48
    invoke-virtual {p2, v2, p0}, Lko/f;->writeToParcel(Landroid/os/Parcel;I)V

    .line 49
    .line 50
    .line 51
    const/16 p0, 0x2d

    .line 52
    .line 53
    invoke-virtual {p1, v2, p0}, Lxo/k;->b(Landroid/os/Parcel;I)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :pswitch_0
    check-cast p1, Lro/i;

    .line 58
    .line 59
    check-cast p2, Laq/k;

    .line 60
    .line 61
    new-instance v0, Lro/g;

    .line 62
    .line 63
    invoke-direct {v0, v1, p2}, Lro/g;-><init>(ILaq/k;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    check-cast p1, Lro/e;

    .line 71
    .line 72
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Lro/a;

    .line 75
    .line 76
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    iget-object v1, p1, Lbp/a;->e:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {p2, v1}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    sget v1, Lcp/a;->a:I

    .line 86
    .line 87
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 88
    .line 89
    .line 90
    invoke-static {p2, p0}, Lcp/a;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 91
    .line 92
    .line 93
    const/4 p0, 0x0

    .line 94
    invoke-virtual {p2, p0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 95
    .line 96
    .line 97
    const/4 p0, 0x2

    .line 98
    invoke-virtual {p1, p2, p0}, Lbp/a;->a(Landroid/os/Parcel;I)V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic c(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget p0, p0, Lpv/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Void;

    .line 7
    .line 8
    return-void

    .line 9
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 10
    .line 11
    return-void

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method

.method public e(Lsz0/g;Lwz0/q;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/util/Map;

    .line 15
    .line 16
    const/4 p1, 0x0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    invoke-interface {p0, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move-object p0, p1

    .line 25
    :goto_0
    if-nez p0, :cond_1

    .line 26
    .line 27
    return-object p1

    .line 28
    :cond_1
    return-object p0
.end method

.method public f(Ltl/h;Lrl/a;Lul/g;Lul/f;)Lrl/b;
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    iget-object v3, v0, Ltl/h;->n:Ltl/a;

    .line 8
    .line 9
    iget-boolean v3, v3, Ltl/a;->d:Z

    .line 10
    .line 11
    if-nez v3, :cond_1

    .line 12
    .line 13
    :cond_0
    const/16 v16, 0x0

    .line 14
    .line 15
    goto/16 :goto_12

    .line 16
    .line 17
    :cond_1
    move-object/from16 v3, p0

    .line 18
    .line 19
    iget-object v3, v3, Lpv/g;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v3, Lil/j;

    .line 22
    .line 23
    iget-object v3, v3, Lil/j;->b:Llx0/q;

    .line 24
    .line 25
    invoke-virtual {v3}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v3, Lrl/c;

    .line 30
    .line 31
    if-eqz v3, :cond_7

    .line 32
    .line 33
    iget-object v5, v3, Lrl/c;->a:Lrl/g;

    .line 34
    .line 35
    invoke-interface {v5, v1}, Lrl/g;->a(Lrl/a;)Lrl/b;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    if-nez v5, :cond_8

    .line 40
    .line 41
    iget-object v3, v3, Lrl/c;->b:Lhm/g;

    .line 42
    .line 43
    monitor-enter v3

    .line 44
    :try_start_0
    iget-object v5, v3, Lhm/g;->a:Ljava/util/LinkedHashMap;

    .line 45
    .line 46
    invoke-virtual {v5, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    check-cast v5, Ljava/util/ArrayList;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    if-nez v5, :cond_2

    .line 54
    .line 55
    monitor-exit v3

    .line 56
    :goto_0
    move-object v5, v6

    .line 57
    goto :goto_5

    .line 58
    :cond_2
    :try_start_1
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 59
    .line 60
    .line 61
    move-result v7

    .line 62
    const/4 v8, 0x0

    .line 63
    :goto_1
    if-ge v8, v7, :cond_5

    .line 64
    .line 65
    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    check-cast v9, Lrl/f;

    .line 70
    .line 71
    iget-object v10, v9, Lrl/f;->b:Ljava/lang/ref/WeakReference;

    .line 72
    .line 73
    invoke-virtual {v10}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v10

    .line 77
    check-cast v10, Landroid/graphics/Bitmap;

    .line 78
    .line 79
    if-eqz v10, :cond_3

    .line 80
    .line 81
    new-instance v11, Lrl/b;

    .line 82
    .line 83
    iget-object v9, v9, Lrl/f;->c:Ljava/util/Map;

    .line 84
    .line 85
    invoke-direct {v11, v10, v9}, Lrl/b;-><init>(Landroid/graphics/Bitmap;Ljava/util/Map;)V

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :catchall_0
    move-exception v0

    .line 90
    goto :goto_4

    .line 91
    :cond_3
    move-object v11, v6

    .line 92
    :goto_2
    if-eqz v11, :cond_4

    .line 93
    .line 94
    move-object v6, v11

    .line 95
    goto :goto_3

    .line 96
    :cond_4
    add-int/lit8 v8, v8, 0x1

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_5
    :goto_3
    iget v5, v3, Lhm/g;->b:I

    .line 100
    .line 101
    add-int/lit8 v7, v5, 0x1

    .line 102
    .line 103
    iput v7, v3, Lhm/g;->b:I

    .line 104
    .line 105
    const/16 v7, 0xa

    .line 106
    .line 107
    if-lt v5, v7, :cond_6

    .line 108
    .line 109
    invoke-virtual {v3}, Lhm/g;->a()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 110
    .line 111
    .line 112
    :cond_6
    monitor-exit v3

    .line 113
    goto :goto_0

    .line 114
    :goto_4
    :try_start_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 115
    throw v0

    .line 116
    :cond_7
    const/4 v5, 0x0

    .line 117
    :cond_8
    :goto_5
    if-eqz v5, :cond_0

    .line 118
    .line 119
    iget-object v3, v5, Lrl/b;->a:Landroid/graphics/Bitmap;

    .line 120
    .line 121
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 122
    .line 123
    .line 124
    move-result-object v6

    .line 125
    if-nez v6, :cond_9

    .line 126
    .line 127
    sget-object v6, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 128
    .line 129
    :cond_9
    sget-object v7, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 130
    .line 131
    const/4 v8, 0x0

    .line 132
    if-ne v6, v7, :cond_a

    .line 133
    .line 134
    iget-boolean v6, v0, Ltl/h;->k:Z

    .line 135
    .line 136
    if-nez v6, :cond_a

    .line 137
    .line 138
    :goto_6
    move-object/from16 p0, v5

    .line 139
    .line 140
    const/16 v16, 0x0

    .line 141
    .line 142
    goto/16 :goto_11

    .line 143
    .line 144
    :cond_a
    iget-object v6, v5, Lrl/b;->b:Ljava/util/Map;

    .line 145
    .line 146
    const-string v7, "coil#is_sampled"

    .line 147
    .line 148
    invoke-interface {v6, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    instance-of v7, v6, Ljava/lang/Boolean;

    .line 153
    .line 154
    if-eqz v7, :cond_b

    .line 155
    .line 156
    check-cast v6, Ljava/lang/Boolean;

    .line 157
    .line 158
    goto :goto_7

    .line 159
    :cond_b
    const/4 v6, 0x0

    .line 160
    :goto_7
    if-eqz v6, :cond_c

    .line 161
    .line 162
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    goto :goto_8

    .line 167
    :cond_c
    move v6, v8

    .line 168
    :goto_8
    sget-object v7, Lul/g;->c:Lul/g;

    .line 169
    .line 170
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v7

    .line 174
    const/4 v9, 0x1

    .line 175
    if-eqz v7, :cond_e

    .line 176
    .line 177
    if-eqz v6, :cond_d

    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_d
    move-object/from16 p0, v5

    .line 181
    .line 182
    const/16 v16, 0x0

    .line 183
    .line 184
    goto/16 :goto_10

    .line 185
    .line 186
    :cond_e
    iget-object v1, v1, Lrl/a;->e:Ljava/util/Map;

    .line 187
    .line 188
    const-string v7, "coil#transformation_size"

    .line 189
    .line 190
    invoke-interface {v1, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    check-cast v1, Ljava/lang/String;

    .line 195
    .line 196
    if-eqz v1, :cond_f

    .line 197
    .line 198
    invoke-virtual {v2}, Lul/g;->toString()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v8

    .line 206
    goto :goto_6

    .line 207
    :cond_f
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    iget-object v7, v2, Lul/g;->a:Llp/u1;

    .line 216
    .line 217
    instance-of v10, v7, Lul/a;

    .line 218
    .line 219
    const v11, 0x7fffffff

    .line 220
    .line 221
    .line 222
    if-eqz v10, :cond_10

    .line 223
    .line 224
    check-cast v7, Lul/a;

    .line 225
    .line 226
    iget v7, v7, Lul/a;->a:I

    .line 227
    .line 228
    goto :goto_9

    .line 229
    :cond_10
    move v7, v11

    .line 230
    :goto_9
    iget-object v2, v2, Lul/g;->b:Llp/u1;

    .line 231
    .line 232
    instance-of v10, v2, Lul/a;

    .line 233
    .line 234
    if-eqz v10, :cond_11

    .line 235
    .line 236
    check-cast v2, Lul/a;

    .line 237
    .line 238
    iget v2, v2, Lul/a;->a:I

    .line 239
    .line 240
    :goto_a
    move-object/from16 v10, p4

    .line 241
    .line 242
    goto :goto_b

    .line 243
    :cond_11
    move v2, v11

    .line 244
    goto :goto_a

    .line 245
    :goto_b
    invoke-static {v1, v3, v7, v2, v10}, Llp/pd;->a(IIIILul/f;)D

    .line 246
    .line 247
    .line 248
    move-result-wide v12

    .line 249
    invoke-static {v0}, Lxl/b;->a(Ltl/h;)Z

    .line 250
    .line 251
    .line 252
    move-result v0

    .line 253
    const-wide/high16 v14, 0x3ff0000000000000L    # 1.0

    .line 254
    .line 255
    if-eqz v0, :cond_13

    .line 256
    .line 257
    cmpl-double v10, v12, v14

    .line 258
    .line 259
    if-lez v10, :cond_12

    .line 260
    .line 261
    move-wide v10, v14

    .line 262
    :goto_c
    move-object/from16 p0, v5

    .line 263
    .line 264
    const/16 v16, 0x0

    .line 265
    .line 266
    goto :goto_d

    .line 267
    :cond_12
    move-wide v10, v12

    .line 268
    goto :goto_c

    .line 269
    :goto_d
    int-to-double v4, v7

    .line 270
    move-wide/from16 p1, v14

    .line 271
    .line 272
    int-to-double v14, v1

    .line 273
    mul-double/2addr v14, v10

    .line 274
    sub-double/2addr v4, v14

    .line 275
    invoke-static {v4, v5}, Ljava/lang/Math;->abs(D)D

    .line 276
    .line 277
    .line 278
    move-result-wide v4

    .line 279
    cmpg-double v1, v4, p1

    .line 280
    .line 281
    if-lez v1, :cond_1a

    .line 282
    .line 283
    int-to-double v1, v2

    .line 284
    int-to-double v3, v3

    .line 285
    mul-double/2addr v10, v3

    .line 286
    sub-double/2addr v1, v10

    .line 287
    invoke-static {v1, v2}, Ljava/lang/Math;->abs(D)D

    .line 288
    .line 289
    .line 290
    move-result-wide v1

    .line 291
    cmpg-double v1, v1, p1

    .line 292
    .line 293
    if-gtz v1, :cond_17

    .line 294
    .line 295
    goto :goto_10

    .line 296
    :cond_13
    move-object/from16 p0, v5

    .line 297
    .line 298
    move-wide/from16 p1, v14

    .line 299
    .line 300
    const/16 v16, 0x0

    .line 301
    .line 302
    const/high16 v4, -0x80000000

    .line 303
    .line 304
    if-eq v7, v4, :cond_15

    .line 305
    .line 306
    if-ne v7, v11, :cond_14

    .line 307
    .line 308
    goto :goto_e

    .line 309
    :cond_14
    sub-int/2addr v7, v1

    .line 310
    invoke-static {v7}, Ljava/lang/Math;->abs(I)I

    .line 311
    .line 312
    .line 313
    move-result v1

    .line 314
    if-gt v1, v9, :cond_17

    .line 315
    .line 316
    :cond_15
    :goto_e
    if-eq v2, v4, :cond_1a

    .line 317
    .line 318
    if-ne v2, v11, :cond_16

    .line 319
    .line 320
    goto :goto_10

    .line 321
    :cond_16
    sub-int/2addr v2, v3

    .line 322
    invoke-static {v2}, Ljava/lang/Math;->abs(I)I

    .line 323
    .line 324
    .line 325
    move-result v1

    .line 326
    if-gt v1, v9, :cond_17

    .line 327
    .line 328
    goto :goto_10

    .line 329
    :cond_17
    cmpg-double v1, v12, p1

    .line 330
    .line 331
    if-nez v1, :cond_18

    .line 332
    .line 333
    goto :goto_f

    .line 334
    :cond_18
    if-nez v0, :cond_19

    .line 335
    .line 336
    goto :goto_11

    .line 337
    :cond_19
    :goto_f
    cmpl-double v0, v12, p1

    .line 338
    .line 339
    if-lez v0, :cond_1a

    .line 340
    .line 341
    if-eqz v6, :cond_1a

    .line 342
    .line 343
    goto :goto_11

    .line 344
    :cond_1a
    :goto_10
    move v8, v9

    .line 345
    :goto_11
    if-eqz v8, :cond_1b

    .line 346
    .line 347
    return-object p0

    .line 348
    :cond_1b
    :goto_12
    return-object v16
.end method

.method public g()Lg1/w1;
    .locals 0

    .line 1
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lm1/l;

    .line 4
    .line 5
    iget-object p0, p0, Lm1/l;->o:Lg1/w1;

    .line 6
    .line 7
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lht/d;

    .line 8
    .line 9
    invoke-static {p0}, Lkp/s6;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public h(Lx21/b;)Lx21/z;
    .locals 6

    .line 1
    iget-object v0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lm1/l;

    .line 4
    .line 5
    const-string v1, "padding"

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget v1, p1, Lx21/b;->a:F

    .line 11
    .line 12
    iget p1, p1, Lx21/b;->b:F

    .line 13
    .line 14
    invoke-virtual {p0}, Lpv/g;->g()Lg1/w1;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-ne p0, v2, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0}, Lm1/l;->e()J

    .line 28
    .line 29
    .line 30
    move-result-wide v2

    .line 31
    const/16 p0, 0x20

    .line 32
    .line 33
    shr-long/2addr v2, p0

    .line 34
    :goto_0
    long-to-int p0, v2

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    new-instance p0, La8/r0;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    invoke-virtual {v0}, Lm1/l;->e()J

    .line 43
    .line 44
    .line 45
    move-result-wide v2

    .line 46
    const-wide v4, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr v2, v4

    .line 52
    goto :goto_0

    .line 53
    :goto_1
    int-to-float p0, p0

    .line 54
    sub-float/2addr p0, p1

    .line 55
    new-instance p1, Lx21/z;

    .line 56
    .line 57
    invoke-direct {p1, v1, p0}, Lx21/z;-><init>(FF)V

    .line 58
    .line 59
    .line 60
    return-object p1
.end method

.method public i()Ljava/util/ArrayList;
    .locals 5

    .line 1
    iget-object v0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lm1/l;

    .line 4
    .line 5
    iget-object v0, v0, Lm1/l;->k:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Ljava/lang/Iterable;

    .line 8
    .line 9
    new-instance v1, Ljava/util/ArrayList;

    .line 10
    .line 11
    const/16 v2, 0xa

    .line 12
    .line 13
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lm1/m;

    .line 35
    .line 36
    invoke-virtual {p0}, Lpv/g;->g()Lg1/w1;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    new-instance v4, Lx21/x;

    .line 41
    .line 42
    invoke-direct {v4, v2, v3}, Lx21/x;-><init>(Lm1/m;Lg1/w1;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    return-object v1
.end method

.method public j(Ltl/h;Ljava/lang/Object;Ltl/l;Lil/d;)Lrl/a;
    .locals 7

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object p4, p1, Ltl/h;->f:Ljava/util/List;

    .line 5
    .line 6
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lil/j;

    .line 9
    .line 10
    iget-object p0, p0, Lil/j;->d:Lil/c;

    .line 11
    .line 12
    iget-object p0, p0, Lil/c;->c:Ljava/util/List;

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    const/4 v1, 0x0

    .line 19
    move v2, v1

    .line 20
    :goto_0
    const/4 v3, 0x0

    .line 21
    if-ge v2, v0, :cond_1

    .line 22
    .line 23
    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    check-cast v4, Llx0/l;

    .line 28
    .line 29
    iget-object v5, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v5, Lpl/b;

    .line 32
    .line 33
    iget-object v4, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v4, Ljava/lang/Class;

    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    invoke-virtual {v4, v6}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_0

    .line 46
    .line 47
    const-string v4, "null cannot be cast to non-null type coil.key.Keyer<kotlin.Any>"

    .line 48
    .line 49
    invoke-static {v5, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v5, p2, p3}, Lpl/b;->a(Ljava/lang/Object;Ltl/l;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    if-eqz v4, :cond_0

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    move-object v4, v3

    .line 63
    :goto_1
    if-nez v4, :cond_2

    .line 64
    .line 65
    return-object v3

    .line 66
    :cond_2
    iget-object p0, p1, Ltl/h;->x:Ltl/m;

    .line 67
    .line 68
    iget-object p0, p0, Ltl/m;->d:Ljava/util/Map;

    .line 69
    .line 70
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    sget-object p2, Lmx0/t;->d:Lmx0/t;

    .line 75
    .line 76
    if-eqz p1, :cond_3

    .line 77
    .line 78
    move-object p1, p2

    .line 79
    goto :goto_2

    .line 80
    :cond_3
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 81
    .line 82
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 83
    .line 84
    .line 85
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-nez v0, :cond_7

    .line 98
    .line 99
    :goto_2
    invoke-interface {p4}, Ljava/util/List;->isEmpty()Z

    .line 100
    .line 101
    .line 102
    move-result p0

    .line 103
    if-eqz p0, :cond_4

    .line 104
    .line 105
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    if-eqz p0, :cond_4

    .line 110
    .line 111
    new-instance p0, Lrl/a;

    .line 112
    .line 113
    invoke-direct {p0, v4, p2}, Lrl/a;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 114
    .line 115
    .line 116
    return-object p0

    .line 117
    :cond_4
    invoke-static {p1}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    move-object p1, p4

    .line 122
    check-cast p1, Ljava/util/Collection;

    .line 123
    .line 124
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    if-nez p1, :cond_6

    .line 129
    .line 130
    invoke-interface {p4}, Ljava/util/List;->size()I

    .line 131
    .line 132
    .line 133
    move-result p1

    .line 134
    if-gtz p1, :cond_5

    .line 135
    .line 136
    iget-object p1, p3, Ltl/l;->d:Lul/g;

    .line 137
    .line 138
    invoke-virtual {p1}, Lul/g;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    const-string p2, "coil#transformation_size"

    .line 143
    .line 144
    invoke-interface {p0, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    goto :goto_3

    .line 148
    :cond_5
    invoke-interface {p4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 153
    .line 154
    .line 155
    new-instance p0, Ljava/lang/ClassCastException;

    .line 156
    .line 157
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 158
    .line 159
    .line 160
    throw p0

    .line 161
    :cond_6
    :goto_3
    new-instance p1, Lrl/a;

    .line 162
    .line 163
    invoke-direct {p1, v4, p0}, Lrl/a;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 164
    .line 165
    .line 166
    return-object p1

    .line 167
    :cond_7
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    check-cast p0, Ljava/util/Map$Entry;

    .line 172
    .line 173
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 178
    .line 179
    .line 180
    new-instance p0, Ljava/lang/ClassCastException;

    .line 181
    .line 182
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 183
    .line 184
    .line 185
    throw p0
.end method

.method public synthetic l(Ljava/lang/String;ILjava/lang/Throwable;[BLjava/util/Map;)V
    .locals 6

    .line 1
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Lvp/z3;

    .line 5
    .line 6
    move-object v1, p1

    .line 7
    move v2, p2

    .line 8
    move-object v3, p3

    .line 9
    move-object v4, p4

    .line 10
    move-object v5, p5

    .line 11
    invoke-virtual/range {v0 .. v5}, Lvp/z3;->A(Ljava/lang/String;ILjava/lang/Throwable;[BLjava/util/Map;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public m(Landroid/view/View;IZ)V
    .locals 0

    .line 1
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/autofill/AutofillManager;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Landroid/view/autofill/AutofillManager;->notifyViewVisibilityChanged(Landroid/view/View;IZ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public n(Ltl/h;Lul/g;)Ltl/l;
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v4, p2

    .line 4
    .line 5
    iget-object v1, v0, Ltl/h;->f:Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    sget-object v1, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 14
    .line 15
    iget-object v2, v0, Ltl/h;->d:Landroid/graphics/Bitmap$Config;

    .line 16
    .line 17
    invoke-static {v2, v1}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    :cond_0
    iget-object v1, v0, Ltl/h;->d:Landroid/graphics/Bitmap$Config;

    .line 24
    .line 25
    sget-object v2, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 26
    .line 27
    if-ne v1, v2, :cond_2

    .line 28
    .line 29
    if-ne v1, v2, :cond_2

    .line 30
    .line 31
    iget-boolean v2, v0, Ltl/h;->k:Z

    .line 32
    .line 33
    if-nez v2, :cond_2

    .line 34
    .line 35
    :cond_1
    sget-object v1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 36
    .line 37
    :cond_2
    move-object v2, v1

    .line 38
    move-object/from16 v1, p0

    .line 39
    .line 40
    iget-object v1, v1, Lpv/g;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lxl/f;

    .line 43
    .line 44
    iget-boolean v1, v1, Lxl/f;->g:Z

    .line 45
    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    iget-object v1, v0, Ltl/h;->p:Ltl/a;

    .line 49
    .line 50
    :goto_0
    move-object v15, v1

    .line 51
    goto :goto_1

    .line 52
    :cond_3
    sget-object v1, Ltl/a;->g:Ltl/a;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :goto_1
    iget-object v1, v4, Lul/g;->a:Llp/u1;

    .line 56
    .line 57
    sget-object v3, Lul/b;->a:Lul/b;

    .line 58
    .line 59
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_5

    .line 64
    .line 65
    iget-object v1, v4, Lul/g;->b:Llp/u1;

    .line 66
    .line 67
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_4

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_4
    iget-object v1, v0, Ltl/h;->w:Lul/f;

    .line 75
    .line 76
    :goto_2
    move-object v5, v1

    .line 77
    goto :goto_4

    .line 78
    :cond_5
    :goto_3
    sget-object v1, Lul/f;->e:Lul/f;

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :goto_4
    iget-boolean v1, v0, Ltl/h;->l:Z

    .line 82
    .line 83
    if-eqz v1, :cond_6

    .line 84
    .line 85
    iget-object v1, v0, Ltl/h;->f:Ljava/util/List;

    .line 86
    .line 87
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    if-eqz v1, :cond_6

    .line 92
    .line 93
    sget-object v1, Landroid/graphics/Bitmap$Config;->ALPHA_8:Landroid/graphics/Bitmap$Config;

    .line 94
    .line 95
    if-eq v2, v1, :cond_6

    .line 96
    .line 97
    const/4 v1, 0x1

    .line 98
    :goto_5
    move v7, v1

    .line 99
    goto :goto_6

    .line 100
    :cond_6
    const/4 v1, 0x0

    .line 101
    goto :goto_5

    .line 102
    :goto_6
    new-instance v1, Ltl/l;

    .line 103
    .line 104
    move-object v3, v1

    .line 105
    iget-object v1, v0, Ltl/h;->a:Landroid/content/Context;

    .line 106
    .line 107
    invoke-static {v0}, Lxl/b;->a(Ltl/h;)Z

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    iget-boolean v8, v0, Ltl/h;->m:Z

    .line 112
    .line 113
    iget-object v10, v0, Ltl/h;->h:Ld01/y;

    .line 114
    .line 115
    iget-object v11, v0, Ltl/h;->i:Ltl/o;

    .line 116
    .line 117
    iget-object v12, v0, Ltl/h;->x:Ltl/m;

    .line 118
    .line 119
    iget-object v13, v0, Ltl/h;->n:Ltl/a;

    .line 120
    .line 121
    iget-object v14, v0, Ltl/h;->o:Ltl/a;

    .line 122
    .line 123
    move-object v0, v3

    .line 124
    const/4 v3, 0x0

    .line 125
    const/4 v9, 0x0

    .line 126
    invoke-direct/range {v0 .. v15}, Ltl/l;-><init>(Landroid/content/Context;Landroid/graphics/Bitmap$Config;Landroid/graphics/ColorSpace;Lul/g;Lul/f;ZZZLjava/lang/String;Ld01/y;Ltl/o;Ltl/m;Ltl/a;Ltl/a;Ltl/a;)V

    .line 127
    .line 128
    .line 129
    return-object v0
.end method

.method public o(Landroid/os/Bundle;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Parcelable$Creator;

    .line 4
    .line 5
    const-string v0, "Result"

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getByteArray(Ljava/lang/String;)[B

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    array-length v1, p1

    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-virtual {v0, p1, v2, v1}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v2}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 25
    .line 26
    .line 27
    :try_start_0
    new-instance p1, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, p1, p0}, Landroid/os/Parcel;->readTypedList(Ljava/util/List;Landroid/os/Parcelable$Creator;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 36
    .line 37
    .line 38
    return-object p1

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public p()Lorg/json/JSONObject;
    .locals 5

    .line 1
    const-string v0, "Error while closing settings cache file."

    .line 2
    .line 3
    const-string v1, "FirebaseCrashlytics"

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    invoke-static {v1, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    const/4 v3, 0x0

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    const-string v2, "Checking for cached settings..."

    .line 14
    .line 15
    invoke-static {v1, v2, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 16
    .line 17
    .line 18
    :cond_0
    :try_start_0
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ljava/io/File;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/io/File;->exists()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    new-instance v2, Ljava/io/FileInputStream;

    .line 29
    .line 30
    invoke-direct {v2, p0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 31
    .line 32
    .line 33
    :try_start_1
    invoke-static {v2}, Lms/f;->i(Ljava/io/FileInputStream;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance v4, Lorg/json/JSONObject;

    .line 38
    .line 39
    invoke-direct {v4, p0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    .line 41
    .line 42
    move-object v3, v2

    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    move-object v3, v2

    .line 46
    goto :goto_2

    .line 47
    :catch_0
    move-exception p0

    .line 48
    goto :goto_1

    .line 49
    :catchall_1
    move-exception p0

    .line 50
    goto :goto_2

    .line 51
    :catch_1
    move-exception p0

    .line 52
    move-object v2, v3

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    :try_start_2
    const-string p0, "Settings file does not exist."

    .line 55
    .line 56
    const/4 v2, 0x2

    .line 57
    invoke-static {v1, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-eqz v2, :cond_2

    .line 62
    .line 63
    invoke-static {v1, p0, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 64
    .line 65
    .line 66
    :cond_2
    move-object v4, v3

    .line 67
    :goto_0
    invoke-static {v3, v0}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    return-object v4

    .line 71
    :goto_1
    :try_start_3
    const-string v4, "Failed to fetch cached settings"

    .line 72
    .line 73
    invoke-static {v1, v4, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 74
    .line 75
    .line 76
    invoke-static {v2, v0}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-object v3

    .line 80
    :goto_2
    invoke-static {v3, v0}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0
.end method

.method public y(Ljava/lang/Throwable;)V
    .locals 6

    .line 1
    iget v0, p0, Lpv/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lu/g1;

    .line 9
    .line 10
    iget-object v0, p0, Lu/g1;->a:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v0

    .line 13
    :try_start_0
    iget-object p1, p0, Lu/g1;->j:Ljava/util/List;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Lh0/t0;

    .line 33
    .line 34
    invoke-virtual {v2}, Lh0/t0;->b()V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    iput-object v1, p0, Lu/g1;->j:Ljava/util/List;

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    goto :goto_7

    .line 43
    :cond_1
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    iget-object p1, p0, Lu/g1;->t:Lb6/f;

    .line 45
    .line 46
    invoke-virtual {p1}, Lb6/f;->x()V

    .line 47
    .line 48
    .line 49
    iget-object p1, p0, Lu/g1;->b:Lu/x0;

    .line 50
    .line 51
    invoke-virtual {p1}, Lu/x0;->h()Ljava/util/ArrayList;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_5

    .line 64
    .line 65
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    check-cast v2, Lu/g1;

    .line 70
    .line 71
    if-ne v2, p0, :cond_2

    .line 72
    .line 73
    goto :goto_6

    .line 74
    :cond_2
    iget-object v3, v2, Lu/g1;->a:Ljava/lang/Object;

    .line 75
    .line 76
    monitor-enter v3

    .line 77
    :try_start_1
    iget-object v4, v2, Lu/g1;->j:Ljava/util/List;

    .line 78
    .line 79
    if-eqz v4, :cond_4

    .line 80
    .line 81
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    :goto_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-eqz v5, :cond_3

    .line 90
    .line 91
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    check-cast v5, Lh0/t0;

    .line 96
    .line 97
    invoke-virtual {v5}, Lh0/t0;->b()V

    .line 98
    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_3
    iput-object v1, v2, Lu/g1;->j:Ljava/util/List;

    .line 102
    .line 103
    goto :goto_4

    .line 104
    :catchall_1
    move-exception p0

    .line 105
    goto :goto_5

    .line 106
    :cond_4
    :goto_4
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 107
    iget-object v2, v2, Lu/g1;->t:Lb6/f;

    .line 108
    .line 109
    invoke-virtual {v2}, Lb6/f;->x()V

    .line 110
    .line 111
    .line 112
    goto :goto_2

    .line 113
    :goto_5
    :try_start_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 114
    throw p0

    .line 115
    :cond_5
    :goto_6
    iget-object v1, p1, Lu/x0;->b:Ljava/lang/Object;

    .line 116
    .line 117
    monitor-enter v1

    .line 118
    :try_start_3
    iget-object p1, p1, Lu/x0;->e:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast p1, Ljava/util/LinkedHashSet;

    .line 121
    .line 122
    invoke-interface {p1, p0}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    monitor-exit v1

    .line 126
    return-void

    .line 127
    :catchall_2
    move-exception p0

    .line 128
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 129
    throw p0

    .line 130
    :goto_7
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 131
    throw p0

    .line 132
    :pswitch_0
    const-string v0, "Opening session with fail "

    .line 133
    .line 134
    iget-object v1, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v1, Lu/p0;

    .line 137
    .line 138
    iget-object v1, v1, Lu/p0;->a:Ljava/lang/Object;

    .line 139
    .line 140
    monitor-enter v1

    .line 141
    :try_start_5
    iget-object v2, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v2, Lu/p0;

    .line 144
    .line 145
    iget-object v2, v2, Lu/p0;->d:Lu/g1;

    .line 146
    .line 147
    invoke-virtual {v2}, Lu/g1;->q()Z

    .line 148
    .line 149
    .line 150
    iget-object v2, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v2, Lu/p0;

    .line 153
    .line 154
    iget v2, v2, Lu/p0;->j:I

    .line 155
    .line 156
    invoke-static {v2}, Lu/w;->o(I)I

    .line 157
    .line 158
    .line 159
    move-result v2

    .line 160
    const/4 v3, 0x4

    .line 161
    if-eq v2, v3, :cond_6

    .line 162
    .line 163
    const/4 v3, 0x5

    .line 164
    if-eq v2, v3, :cond_6

    .line 165
    .line 166
    const/4 v3, 0x6

    .line 167
    if-eq v2, v3, :cond_6

    .line 168
    .line 169
    goto :goto_8

    .line 170
    :cond_6
    instance-of v2, p1, Ljava/util/concurrent/CancellationException;

    .line 171
    .line 172
    if-nez v2, :cond_7

    .line 173
    .line 174
    const-string v2, "CaptureSession"

    .line 175
    .line 176
    iget-object v3, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v3, Lu/p0;

    .line 179
    .line 180
    iget v3, v3, Lu/p0;->j:I

    .line 181
    .line 182
    invoke-static {v3}, Lu/w;->q(I)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    invoke-virtual {v0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-static {v2, v0, p1}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 191
    .line 192
    .line 193
    iget-object p0, p0, Lpv/g;->e:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast p0, Lu/p0;

    .line 196
    .line 197
    invoke-virtual {p0}, Lu/p0;->e()V

    .line 198
    .line 199
    .line 200
    goto :goto_8

    .line 201
    :catchall_3
    move-exception p0

    .line 202
    goto :goto_9

    .line 203
    :cond_7
    :goto_8
    monitor-exit v1

    .line 204
    return-void

    .line 205
    :goto_9
    monitor-exit v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 206
    throw p0

    .line 207
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method
