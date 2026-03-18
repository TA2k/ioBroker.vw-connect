.class public final Lt1/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu/k1;
.implements Lqp/f;
.implements Lb0/j1;
.implements Lua/b;
.implements Llo/n;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lt1/j0;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    new-instance p1, Lb6/f;

    invoke-direct {p1}, Lb6/f;-><init>()V

    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void

    .line 25
    :sswitch_0
    const-class p1, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 26
    sget-object v0, Lx/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    .line 27
    check-cast p1, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void

    .line 30
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    .line 31
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/EnumMap;

    const-class v0, Lvp/r1;

    invoke-direct {p1, v0}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void

    .line 32
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 33
    new-instance p1, Lv3/y1;

    sget-object v0, Lv3/f;->b:Lv3/l1;

    .line 34
    invoke-direct {p1, v0}, Ljava/util/TreeSet;-><init>(Ljava/util/Comparator;)V

    .line 35
    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x9 -> :sswitch_3
        0xa -> :sswitch_2
        0xf -> :sswitch_1
        0x15 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/graphics/Typeface;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lt1/j0;->d:I

    const-string v0, "typeface"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/hardware/camera2/CameraDevice;)V
    .locals 2

    const/16 v0, 0x8

    iput v0, p0, Lt1/j0;->d:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    new-instance v0, Lv/c;

    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    .line 15
    invoke-direct {v0, p1, v1}, Lh/w;-><init>(Landroid/hardware/camera2/CameraDevice;Llp/sa;)V

    .line 16
    iput-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/widget/TextView;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lt1/j0;->d:I

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    new-instance v0, Lu6/g;

    invoke-direct {v0, p1}, Lu6/g;-><init>(Landroid/widget/TextView;)V

    iput-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/sqlite/db/SupportSQLiteOpenHelper;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, Lt1/j0;->d:I

    const-string v0, "openHelper"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcx0/a;)V
    .locals 2

    const/16 v0, 0x10

    iput v0, p0, Lt1/j0;->d:I

    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    new-instance v0, Lwz0/h;

    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    invoke-direct {v0, p1, v1}, Lwz0/h;-><init>(Lcx0/a;Ljava/nio/charset/Charset;)V

    iput-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lj0/h;)V
    .locals 1

    const/4 p1, 0x5

    iput p1, p0, Lt1/j0;->d:I

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt1/j0;->d:I

    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/util/EnumMap;)V
    .locals 2

    const/16 v0, 0xa

    iput v0, p0, Lt1/j0;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/EnumMap;

    const-class v1, Lvp/r1;

    invoke-direct {v0, v1}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    iput-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 6
    invoke-virtual {v0, p1}, Ljava/util/EnumMap;->putAll(Ljava/util/Map;)V

    return-void
.end method

.method public constructor <init>(Lro/f;Lb81/a;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Lt1/j0;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lt1/j0;->e:Ljava/lang/Object;

    new-instance p2, Lxr/b;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Lxr/b;-><init>(Ljava/lang/Object;I)V

    .line 3
    invoke-virtual {p1, p2}, Lro/f;->o(Lxr/b;)V

    return-void
.end method

.method public constructor <init>(Lvp/v1;Lvp/g1;)V
    .locals 0

    const/16 p1, 0xc

    iput p1, p0, Lt1/j0;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvz0/t;)V
    .locals 1

    const/16 v0, 0x17

    iput v0, p0, Lt1/j0;->d:I

    const-string v0, "format"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Landroid/hardware/camera2/TotalCaptureResult;)V
    .locals 0

    .line 1
    return-void
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Laq/k;

    .line 2
    .line 3
    check-cast p1, Lxo/i;

    .line 4
    .line 5
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lxo/k;

    .line 10
    .line 11
    new-instance v0, Lxo/e;

    .line 12
    .line 13
    sget-object v1, Let/d;->o:Let/d;

    .line 14
    .line 15
    invoke-direct {v0, p2, v1}, Lxo/e;-><init>(Laq/k;Lxo/a;)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lkp/b8;->b()Lko/f;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lxo/c;

    .line 25
    .line 26
    invoke-virtual {p1}, Lxo/k;->a()Landroid/os/Parcel;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    sget v2, Lfp/a;->a:I

    .line 31
    .line 32
    invoke-virtual {v1, p0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    invoke-virtual {v1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 40
    .line 41
    .line 42
    const/4 p0, 0x0

    .line 43
    invoke-virtual {p2, v1, p0}, Lko/f;->writeToParcel(Landroid/os/Parcel;I)V

    .line 44
    .line 45
    .line 46
    const/16 p0, 0x33

    .line 47
    .line 48
    invoke-virtual {p1, v1, p0}, Lxo/k;->b(Landroid/os/Parcel;I)V

    .line 49
    .line 50
    .line 51
    return-void
.end method

.method public b(Lb0/h1;)V
    .locals 0

    .line 1
    return-void
.end method

.method public c(Lsp/k;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Luu/x;

    .line 4
    .line 5
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_3

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Luu/s0;

    .line 22
    .line 23
    instance-of v1, v0, Luu/k1;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    move-object v1, v0

    .line 28
    check-cast v1, Luu/k1;

    .line 29
    .line 30
    iget-object v2, v1, Luu/k1;->c:Luu/l1;

    .line 31
    .line 32
    iget-object v1, v1, Luu/k1;->b:Lsp/k;

    .line 33
    .line 34
    invoke-virtual {v1, p1}, Lsp/k;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    invoke-virtual {p1}, Lsp/k;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const-string v1, "getPosition(...)"

    .line 45
    .line 46
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const/4 v1, 0x1

    .line 50
    invoke-virtual {v2, v1}, Luu/l1;->a(Z)V

    .line 51
    .line 52
    .line 53
    iget-object v1, v2, Luu/l1;->a:Ll2/j1;

    .line 54
    .line 55
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Luu/p;->d:Luu/p;

    .line 59
    .line 60
    iget-object v1, v2, Luu/l1;->c:Ll2/j1;

    .line 61
    .line 62
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_0

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    instance-of v1, v0, Luu/v;

    .line 77
    .line 78
    if-eqz v1, :cond_0

    .line 79
    .line 80
    check-cast v0, Luu/v;

    .line 81
    .line 82
    iget-object v0, v0, Luu/v;->k:Ll2/j1;

    .line 83
    .line 84
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Lay0/k;

    .line 89
    .line 90
    if-eqz v0, :cond_2

    .line 91
    .line 92
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    goto :goto_0

    .line 103
    :cond_2
    const/4 v0, 0x0

    .line 104
    :goto_0
    if-eqz v0, :cond_0

    .line 105
    .line 106
    :cond_3
    :goto_1
    return-void
.end method

.method public d(Lsp/k;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Luu/x;

    .line 4
    .line 5
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_3

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Luu/s0;

    .line 22
    .line 23
    instance-of v1, v0, Luu/k1;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    move-object v1, v0

    .line 28
    check-cast v1, Luu/k1;

    .line 29
    .line 30
    iget-object v2, v1, Luu/k1;->c:Luu/l1;

    .line 31
    .line 32
    iget-object v1, v1, Luu/k1;->b:Lsp/k;

    .line 33
    .line 34
    invoke-virtual {v1, p1}, Lsp/k;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    invoke-virtual {p1}, Lsp/k;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const-string v1, "getPosition(...)"

    .line 45
    .line 46
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const/4 v1, 0x1

    .line 50
    invoke-virtual {v2, v1}, Luu/l1;->a(Z)V

    .line 51
    .line 52
    .line 53
    iget-object v1, v2, Luu/l1;->a:Ll2/j1;

    .line 54
    .line 55
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    sget-object v0, Luu/p;->e:Luu/p;

    .line 59
    .line 60
    iget-object v1, v2, Luu/l1;->c:Ll2/j1;

    .line 61
    .line 62
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_0

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    instance-of v1, v0, Luu/v;

    .line 77
    .line 78
    if-eqz v1, :cond_0

    .line 79
    .line 80
    check-cast v0, Luu/v;

    .line 81
    .line 82
    iget-object v0, v0, Luu/v;->i:Ll2/j1;

    .line 83
    .line 84
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Lay0/k;

    .line 89
    .line 90
    if-eqz v0, :cond_2

    .line 91
    .line 92
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 97
    .line 98
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    goto :goto_0

    .line 103
    :cond_2
    const/4 v0, 0x0

    .line 104
    :goto_0
    if-eqz v0, :cond_0

    .line 105
    .line 106
    :cond_3
    :goto_1
    return-void
.end method

.method public e()F
    .locals 0

    .line 1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    return p0
.end method

.method public f()V
    .locals 0

    .line 1
    return-void
.end method

.method public g()F
    .locals 2

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lv/b;

    .line 4
    .line 5
    sget-object v0, Landroid/hardware/camera2/CameraCharacteristics;->SCALER_AVAILABLE_MAX_DIGITAL_ZOOM:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Float;

    .line 12
    .line 13
    const/high16 v0, 0x3f800000    # 1.0f

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    return v0

    .line 18
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    cmpg-float v1, v1, v0

    .line 23
    .line 24
    if-gez v1, :cond_1

    .line 25
    .line 26
    return v0

    .line 27
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0
.end method

.method public h(Lb0/x1;)V
    .locals 6

    .line 1
    invoke-static {}, Llp/k1;->c()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lw0/i;

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v1, Lno/nordicsemi/android/ble/o0;

    .line 20
    .line 21
    const/16 v2, 0x16

    .line 22
    .line 23
    invoke-direct {v1, v2, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_0
    const-string v0, "PreviewView"

    .line 31
    .line 32
    const-string v1, "Surface requested by Preview."

    .line 33
    .line 34
    invoke-static {v0, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p1, Lb0/x1;->d:Lh0/b0;

    .line 38
    .line 39
    iget-object v1, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lw0/i;

    .line 42
    .line 43
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    iput-object v2, v1, Lw0/i;->l:Lh0/z;

    .line 48
    .line 49
    iget-object v1, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Lw0/i;

    .line 52
    .line 53
    iget-object v1, v1, Lw0/i;->k:Lw0/j;

    .line 54
    .line 55
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-interface {v2}, Lh0/z;->g()Landroid/graphics/Rect;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    new-instance v3, Landroid/util/Rational;

    .line 67
    .line 68
    invoke-virtual {v2}, Landroid/graphics/Rect;->width()I

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    invoke-virtual {v2}, Landroid/graphics/Rect;->height()I

    .line 73
    .line 74
    .line 75
    move-result v5

    .line 76
    invoke-direct {v3, v4, v5}, Landroid/util/Rational;-><init>(II)V

    .line 77
    .line 78
    .line 79
    monitor-enter v1

    .line 80
    :try_start_0
    iput-object v2, v1, Lw0/j;->b:Landroid/graphics/Rect;

    .line 81
    .line 82
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 83
    iget-object v1, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v1, Lw0/i;

    .line 86
    .line 87
    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-virtual {v1}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    new-instance v2, Lbb/i;

    .line 96
    .line 97
    const/16 v3, 0xc

    .line 98
    .line 99
    invoke-direct {v2, p0, v0, p1, v3}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, v1, v2}, Lb0/x1;->b(Ljava/util/concurrent/Executor;Lb0/w1;)V

    .line 103
    .line 104
    .line 105
    iget-object v1, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v1, Lw0/i;

    .line 108
    .line 109
    iget-object v2, v1, Lw0/i;->e:Landroidx/core/app/a0;

    .line 110
    .line 111
    iget-object v1, v1, Lw0/i;->d:Lw0/f;

    .line 112
    .line 113
    instance-of v2, v2, Lw0/p;

    .line 114
    .line 115
    if-eqz v2, :cond_1

    .line 116
    .line 117
    invoke-static {p1, v1}, Lw0/i;->b(Lb0/x1;Lw0/f;)Z

    .line 118
    .line 119
    .line 120
    move-result v1

    .line 121
    if-nez v1, :cond_1

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_1
    iget-object v1, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 125
    .line 126
    check-cast v1, Lw0/i;

    .line 127
    .line 128
    iget-object v2, v1, Lw0/i;->d:Lw0/f;

    .line 129
    .line 130
    invoke-static {p1, v2}, Lw0/i;->b(Lb0/x1;Lw0/f;)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-eqz v2, :cond_2

    .line 135
    .line 136
    new-instance v2, Lw0/r;

    .line 137
    .line 138
    iget-object v3, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v3, Lw0/i;

    .line 141
    .line 142
    iget-object v4, v3, Lw0/i;->g:Lw0/d;

    .line 143
    .line 144
    invoke-direct {v2, v3, v4}, Landroidx/core/app/a0;-><init>(Landroid/widget/FrameLayout;Lw0/d;)V

    .line 145
    .line 146
    .line 147
    const/4 v3, 0x0

    .line 148
    iput-boolean v3, v2, Lw0/r;->i:Z

    .line 149
    .line 150
    new-instance v3, Ljava/util/concurrent/atomic/AtomicReference;

    .line 151
    .line 152
    invoke-direct {v3}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 153
    .line 154
    .line 155
    iput-object v3, v2, Lw0/r;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_2
    new-instance v2, Lw0/p;

    .line 159
    .line 160
    iget-object v3, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast v3, Lw0/i;

    .line 163
    .line 164
    iget-object v4, v3, Lw0/i;->g:Lw0/d;

    .line 165
    .line 166
    invoke-direct {v2, v3, v4}, Lw0/p;-><init>(Landroid/widget/FrameLayout;Lw0/d;)V

    .line 167
    .line 168
    .line 169
    :goto_0
    iput-object v2, v1, Lw0/i;->e:Landroidx/core/app/a0;

    .line 170
    .line 171
    :goto_1
    new-instance v1, Lw0/c;

    .line 172
    .line 173
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 174
    .line 175
    .line 176
    move-result-object v2

    .line 177
    iget-object v3, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v3, Lw0/i;

    .line 180
    .line 181
    iget-object v4, v3, Lw0/i;->i:Landroidx/lifecycle/i0;

    .line 182
    .line 183
    iget-object v3, v3, Lw0/i;->e:Landroidx/core/app/a0;

    .line 184
    .line 185
    invoke-direct {v1, v2, v4, v3}, Lw0/c;-><init>(Lh0/z;Landroidx/lifecycle/i0;Landroidx/core/app/a0;)V

    .line 186
    .line 187
    .line 188
    iget-object v2, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v2, Lw0/i;

    .line 191
    .line 192
    iget-object v2, v2, Lw0/i;->j:Ljava/util/concurrent/atomic/AtomicReference;

    .line 193
    .line 194
    invoke-virtual {v2, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    invoke-interface {v0}, Lh0/b0;->c()Lh0/m1;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    iget-object v3, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v3, Lw0/i;

    .line 204
    .line 205
    invoke-virtual {v3}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 206
    .line 207
    .line 208
    move-result-object v3

    .line 209
    invoke-virtual {v3}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 210
    .line 211
    .line 212
    move-result-object v3

    .line 213
    invoke-interface {v2, v3, v1}, Lh0/m1;->m(Ljava/util/concurrent/Executor;Lh0/l1;)V

    .line 214
    .line 215
    .line 216
    iget-object v2, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v2, Lw0/i;

    .line 219
    .line 220
    iget-object v2, v2, Lw0/i;->e:Landroidx/core/app/a0;

    .line 221
    .line 222
    new-instance v3, Lbb/i;

    .line 223
    .line 224
    const/16 v4, 0xd

    .line 225
    .line 226
    invoke-direct {v3, p0, v1, v0, v4}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v2, p1, v3}, Landroidx/core/app/a0;->g(Lb0/x1;Lbb/i;)V

    .line 230
    .line 231
    .line 232
    iget-object p1, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast p1, Lw0/i;

    .line 235
    .line 236
    iget-object v0, p1, Lw0/i;->f:Lw0/m;

    .line 237
    .line 238
    invoke-virtual {p1, v0}, Landroid/view/ViewGroup;->indexOfChild(Landroid/view/View;)I

    .line 239
    .line 240
    .line 241
    move-result p1

    .line 242
    const/4 v0, -0x1

    .line 243
    if-ne p1, v0, :cond_3

    .line 244
    .line 245
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 246
    .line 247
    check-cast p0, Lw0/i;

    .line 248
    .line 249
    iget-object p1, p0, Lw0/i;->f:Lw0/m;

    .line 250
    .line 251
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 252
    .line 253
    .line 254
    :cond_3
    return-void

    .line 255
    :catchall_0
    move-exception p0

    .line 256
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 257
    throw p0
.end method

.method public i(Lsp/k;)V
    .locals 4

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Luu/x;

    .line 4
    .line 5
    iget-object p0, p0, Luu/x;->k:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_3

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Luu/s0;

    .line 22
    .line 23
    instance-of v1, v0, Luu/k1;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    move-object v1, v0

    .line 29
    check-cast v1, Luu/k1;

    .line 30
    .line 31
    iget-object v3, v1, Luu/k1;->c:Luu/l1;

    .line 32
    .line 33
    iget-object v1, v1, Luu/k1;->b:Lsp/k;

    .line 34
    .line 35
    invoke-virtual {v1, p1}, Lsp/k;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_1

    .line 40
    .line 41
    invoke-virtual {p1}, Lsp/k;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    const-string v1, "getPosition(...)"

    .line 46
    .line 47
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const/4 v1, 0x1

    .line 51
    invoke-virtual {v3, v1}, Luu/l1;->a(Z)V

    .line 52
    .line 53
    .line 54
    iget-object v1, v3, Luu/l1;->a:Ll2/j1;

    .line 55
    .line 56
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v2}, Luu/l1;->a(Z)V

    .line 60
    .line 61
    .line 62
    sget-object v0, Luu/p;->f:Luu/p;

    .line 63
    .line 64
    iget-object v1, v3, Luu/l1;->c:Ll2/j1;

    .line 65
    .line 66
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_0

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_1
    instance-of v1, v0, Luu/v;

    .line 81
    .line 82
    if-eqz v1, :cond_0

    .line 83
    .line 84
    check-cast v0, Luu/v;

    .line 85
    .line 86
    iget-object v0, v0, Luu/v;->j:Ll2/j1;

    .line 87
    .line 88
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    check-cast v0, Lay0/k;

    .line 93
    .line 94
    if-eqz v0, :cond_2

    .line 95
    .line 96
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    :cond_2
    if-eqz v2, :cond_0

    .line 107
    .line 108
    :cond_3
    :goto_0
    return-void
.end method

.method public j()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public k(Lv3/h0;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "DepthSortedSet.add called on an unattached node"

    .line 8
    .line 9
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lv3/y1;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public l(IZ)V
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb6/f;

    .line 4
    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lb6/f;->h(I)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public m()Lpv/g;
    .locals 2

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lm1/t;

    .line 4
    .line 5
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v0, Lpv/g;

    .line 10
    .line 11
    const/16 v1, 0x17

    .line 12
    .line 13
    invoke-direct {v0, p0, v1}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public n(Lv3/h0;)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Lv3/h0;->I()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "DepthSortedSet.remove called on an unattached node"

    .line 8
    .line 9
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lv3/y1;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0
.end method

.method public o()V
    .locals 5

    .line 1
    iget-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/k3;

    .line 4
    .line 5
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lvp/g1;

    .line 11
    .line 12
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 13
    .line 14
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v0, Lvp/g1;->n:Lto/a;

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 23
    .line 24
    .line 25
    move-result-wide v3

    .line 26
    invoke-virtual {v1, v3, v4}, Lvp/w0;->k0(J)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_0

    .line 31
    .line 32
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 33
    .line 34
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 35
    .line 36
    .line 37
    iget-object v1, v1, Lvp/w0;->p:Lvp/v0;

    .line 38
    .line 39
    const/4 v3, 0x1

    .line 40
    invoke-virtual {v1, v3}, Lvp/v0;->b(Z)V

    .line 41
    .line 42
    .line 43
    new-instance v1, Landroid/app/ActivityManager$RunningAppProcessInfo;

    .line 44
    .line 45
    invoke-direct {v1}, Landroid/app/ActivityManager$RunningAppProcessInfo;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-static {v1}, Landroid/app/ActivityManager;->getMyMemoryState(Landroid/app/ActivityManager$RunningAppProcessInfo;)V

    .line 49
    .line 50
    .line 51
    iget v1, v1, Landroid/app/ActivityManager$RunningAppProcessInfo;->importance:I

    .line 52
    .line 53
    const/16 v3, 0x64

    .line 54
    .line 55
    if-ne v1, v3, :cond_0

    .line 56
    .line 57
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 58
    .line 59
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 63
    .line 64
    const-string v1, "Detected application was in foreground"

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 73
    .line 74
    .line 75
    move-result-wide v0

    .line 76
    invoke-virtual {p0, v0, v1}, Lt1/j0;->s(J)V

    .line 77
    .line 78
    .line 79
    :cond_0
    return-void
.end method

.method public open(Ljava/lang/String;)Lua/a;
    .locals 3

    .line 1
    const-string v0, "fileName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 9
    .line 10
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "\' was requested."

    .line 15
    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    const-string v0, ":memory:"

    .line 19
    .line 20
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const-string p0, "This driver is configured to open an in-memory database but a file-based named \'"

    .line 28
    .line 29
    invoke-static {p0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p1

    .line 43
    :cond_1
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-nez v2, :cond_3

    .line 48
    .line 49
    const/16 v2, 0x2f

    .line 50
    .line 51
    invoke-static {v2, v0, v0}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-static {v2, p1, p1}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_2

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    const-string v2, "This driver is configured to open a database named \'"

    .line 69
    .line 70
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string p0, "\' but \'"

    .line 81
    .line 82
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 96
    .line 97
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p1

    .line 105
    :cond_3
    :goto_0
    new-instance p1, Lxa/a;

    .line 106
    .line 107
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteOpenHelper;->getWritableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-direct {p1, p0}, Lxa/a;-><init>(Landroidx/sqlite/db/SupportSQLiteDatabase;)V

    .line 112
    .line 113
    .line 114
    return-object p1
.end method

.method public p()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 6
    .line 7
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lvp/p0;->k0()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const/4 v0, 0x3

    .line 15
    invoke-static {p0, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public q(J)V
    .locals 4

    .line 1
    iget-object v0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/k3;

    .line 4
    .line 5
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/k3;->e0()V

    .line 9
    .line 10
    .line 11
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 16
    .line 17
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p1, p2}, Lvp/w0;->k0(J)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 27
    .line 28
    .line 29
    iget-object v2, v1, Lvp/w0;->p:Lvp/v0;

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    invoke-virtual {v2, v3}, Lvp/v0;->b(Z)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-virtual {v0}, Lvp/h0;->f0()V

    .line 40
    .line 41
    .line 42
    :cond_0
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 43
    .line 44
    .line 45
    iget-object v0, v1, Lvp/w0;->t:La8/s1;

    .line 46
    .line 47
    invoke-virtual {v0, p1, p2}, La8/s1;->h(J)V

    .line 48
    .line 49
    .line 50
    iget-object v0, v1, Lvp/w0;->p:Lvp/v0;

    .line 51
    .line 52
    invoke-virtual {v0}, Lvp/v0;->a()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_1

    .line 57
    .line 58
    invoke-virtual {p0, p1, p2}, Lt1/j0;->s(J)V

    .line 59
    .line 60
    .line 61
    :cond_1
    return-void
.end method

.method public r(Lvp/r1;I)V
    .locals 1

    .line 1
    const/16 v0, -0x1e

    .line 2
    .line 3
    if-eq p2, v0, :cond_3

    .line 4
    .line 5
    const/16 v0, -0x14

    .line 6
    .line 7
    if-eq p2, v0, :cond_2

    .line 8
    .line 9
    const/16 v0, -0xa

    .line 10
    .line 11
    if-eq p2, v0, :cond_1

    .line 12
    .line 13
    if-eqz p2, :cond_2

    .line 14
    .line 15
    const/16 v0, 0x1e

    .line 16
    .line 17
    if-eq p2, v0, :cond_0

    .line 18
    .line 19
    sget-object p2, Lvp/i;->e:Lvp/i;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    sget-object p2, Lvp/i;->i:Lvp/i;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    sget-object p2, Lvp/i;->h:Lvp/i;

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_2
    sget-object p2, Lvp/i;->j:Lvp/i;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_3
    sget-object p2, Lvp/i;->k:Lvp/i;

    .line 32
    .line 33
    :goto_0
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Ljava/util/EnumMap;

    .line 36
    .line 37
    invoke-virtual {p0, p1, p2}, Ljava/util/EnumMap;->put(Ljava/lang/Enum;Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public s(J)V
    .locals 13

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/k3;

    .line 4
    .line 5
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lvp/g1;

    .line 11
    .line 12
    invoke-virtual {p0}, Lvp/g1;->a()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    goto/16 :goto_0

    .line 19
    .line 20
    :cond_0
    iget-object v0, p0, Lvp/g1;->h:Lvp/w0;

    .line 21
    .line 22
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 23
    .line 24
    .line 25
    iget-object v1, v0, Lvp/w0;->t:La8/s1;

    .line 26
    .line 27
    invoke-virtual {v1, p1, p2}, La8/s1;->h(J)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Lvp/g1;->n:Lto/a;

    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    iget-object v3, p0, Lvp/g1;->i:Lvp/p0;

    .line 40
    .line 41
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 42
    .line 43
    .line 44
    iget-object v3, v3, Lvp/p0;->r:Lvp/n0;

    .line 45
    .line 46
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    const-string v2, "Session started, time"

    .line 51
    .line 52
    invoke-virtual {v3, v1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    const-wide/16 v1, 0x3e8

    .line 56
    .line 57
    div-long v1, p1, v1

    .line 58
    .line 59
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 60
    .line 61
    .line 62
    move-result-object v6

    .line 63
    iget-object v7, p0, Lvp/g1;->p:Lvp/j2;

    .line 64
    .line 65
    invoke-static {v7}, Lvp/g1;->i(Lvp/b0;)V

    .line 66
    .line 67
    .line 68
    move-object v3, v7

    .line 69
    const-string v7, "auto"

    .line 70
    .line 71
    const-string v8, "_sid"

    .line 72
    .line 73
    move-wide v4, p1

    .line 74
    invoke-virtual/range {v3 .. v8}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    move-wide v8, v4

    .line 78
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 79
    .line 80
    .line 81
    iget-object p0, v0, Lvp/w0;->u:La8/s1;

    .line 82
    .line 83
    invoke-virtual {p0, v1, v2}, La8/s1;->h(J)V

    .line 84
    .line 85
    .line 86
    iget-object p0, v0, Lvp/w0;->p:Lvp/v0;

    .line 87
    .line 88
    const/4 p1, 0x0

    .line 89
    invoke-virtual {p0, p1}, Lvp/v0;->b(Z)V

    .line 90
    .line 91
    .line 92
    new-instance v10, Landroid/os/Bundle;

    .line 93
    .line 94
    invoke-direct {v10}, Landroid/os/Bundle;-><init>()V

    .line 95
    .line 96
    .line 97
    const-string p0, "_sid"

    .line 98
    .line 99
    invoke-virtual {v10, p0, v1, v2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 100
    .line 101
    .line 102
    invoke-static {v3}, Lvp/g1;->i(Lvp/b0;)V

    .line 103
    .line 104
    .line 105
    const-string v11, "auto"

    .line 106
    .line 107
    const-string v12, "_s"

    .line 108
    .line 109
    move-object v7, v3

    .line 110
    invoke-virtual/range {v7 .. v12}, Lvp/j2;->i0(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    iget-object p0, v0, Lvp/w0;->z:La8/b;

    .line 114
    .line 115
    invoke-virtual {p0}, La8/b;->t()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 120
    .line 121
    .line 122
    move-result p1

    .line 123
    if-nez p1, :cond_1

    .line 124
    .line 125
    new-instance v10, Landroid/os/Bundle;

    .line 126
    .line 127
    invoke-direct {v10}, Landroid/os/Bundle;-><init>()V

    .line 128
    .line 129
    .line 130
    const-string p1, "_ffr"

    .line 131
    .line 132
    invoke-virtual {v10, p1, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    invoke-static {v3}, Lvp/g1;->i(Lvp/b0;)V

    .line 136
    .line 137
    .line 138
    const-string v11, "auto"

    .line 139
    .line 140
    const-string v12, "_ssr"

    .line 141
    .line 142
    move-object v7, v3

    .line 143
    invoke-virtual/range {v7 .. v12}, Lvp/j2;->i0(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    :cond_1
    :goto_0
    return-void
.end method

.method public t(Lvp/r1;Lvp/i;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/EnumMap;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ljava/util/EnumMap;->put(Ljava/lang/Enum;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget v0, p0, Lt1/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "1"

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lvp/r1;->values()[Lvp/r1;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    array-length v2, v1

    .line 23
    const/4 v3, 0x0

    .line 24
    :goto_0
    if-ge v3, v2, :cond_1

    .line 25
    .line 26
    aget-object v4, v1, v3

    .line 27
    .line 28
    iget-object v5, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v5, Ljava/util/EnumMap;

    .line 31
    .line 32
    invoke-virtual {v5, v4}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Lvp/i;

    .line 37
    .line 38
    if-nez v4, :cond_0

    .line 39
    .line 40
    sget-object v4, Lvp/i;->e:Lvp/i;

    .line 41
    .line 42
    :cond_0
    iget-char v4, v4, Lvp/i;->d:C

    .line 43
    .line 44
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    add-int/lit8 v3, v3, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_1
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Lv3/y1;

    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    return-object p0

    .line 64
    nop

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
