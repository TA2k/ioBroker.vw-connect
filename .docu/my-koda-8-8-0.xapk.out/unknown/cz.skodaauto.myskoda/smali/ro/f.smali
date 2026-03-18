.class public final synthetic Lro/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/n;
.implements Landroidx/sqlite/db/SupportSQLiteQuery;
.implements Llo/l;
.implements Lxw/j;
.implements Ly9/i0;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lro/f;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    const-class p1, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;

    .line 9
    sget-object v0, Lx/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    .line 10
    check-cast p1, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;

    iput-object p1, p0, Lro/f;->e:Ljava/lang/Object;

    return-void

    .line 11
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    sget-object p1, Lz81/p;->a:Lyy0/c2;

    .line 13
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lz81/q;

    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Lz81/f;->e:Lz81/f;

    .line 15
    iput-object p1, p0, Lro/f;->e:Ljava/lang/Object;

    return-void

    .line 16
    :sswitch_1
    const-class p1, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 17
    sget-object v0, Lx/a;->a:Ld01/x;

    invoke-virtual {v0, p1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object p1

    .line 18
    check-cast p1, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    iput-object p1, p0, Lro/f;->e:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x13 -> :sswitch_1
        0x17 -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lro/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/res/Resources;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Lro/f;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    iput-object p1, p0, Lro/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/hardware/camera2/CameraCaptureSession;)V
    .locals 2

    const/4 v0, 0x5

    iput v0, p0, Lro/f;->d:I

    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    new-instance v0, Lb81/c;

    const/4 v1, 0x0

    .line 23
    invoke-direct {v0, p1, v1}, Lb81/c;-><init>(Landroid/hardware/camera2/CameraCaptureSession;Llp/ra;)V

    .line 24
    iput-object v0, p0, Lro/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lro/f;->d:I

    iput-object p1, p0, Lro/f;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lro/h;Lro/a;)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, Lro/f;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lro/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ltl/m;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lro/f;->d:I

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    iget-object p1, p1, Ltl/m;->d:Ljava/util/Map;

    .line 27
    invoke-static {p1}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    move-result-object p1

    iput-object p1, p0, Lro/f;->e:Ljava/lang/Object;

    return-void
.end method

.method public static t(Ljava/lang/String;)Lro/f;
    .locals 2

    .line 1
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x1

    .line 12
    if-le v0, v1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p0}, Lvp/s1;->e(C)Lvp/p1;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    goto :goto_1

    .line 25
    :cond_1
    :goto_0
    sget-object p0, Lvp/p1;->e:Lvp/p1;

    .line 26
    .line 27
    :goto_1
    new-instance v0, Lro/f;

    .line 28
    .line 29
    const/4 v1, 0x7

    .line 30
    invoke-direct {v0, p0, v1}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method


# virtual methods
.method public Q()V
    .locals 0

    .line 1
    return-void
.end method

.method public a(Ljava/lang/String;)Ljava/lang/String;
    .locals 6

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [[Ljava/lang/String;

    .line 4
    .line 5
    array-length v0, p0

    .line 6
    const/4 v1, 0x0

    .line 7
    move v2, v1

    .line 8
    :goto_0
    if-ge v2, v0, :cond_0

    .line 9
    .line 10
    aget-object v3, p0, v2

    .line 11
    .line 12
    aget-object v4, v3, v1

    .line 13
    .line 14
    const/4 v5, 0x1

    .line 15
    aget-object v3, v3, v5

    .line 16
    .line 17
    invoke-virtual {p1, v4, v3}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    add-int/lit8 v2, v2, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    return-object p1
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lro/i;

    .line 2
    .line 3
    check-cast p2, Laq/k;

    .line 4
    .line 5
    new-instance v0, Lro/g;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, v1, p2}, Lro/g;-><init>(ILaq/k;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lro/e;

    .line 16
    .line 17
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lro/a;

    .line 20
    .line 21
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    iget-object v1, p1, Lbp/a;->e:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {p2, v1}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    sget v1, Lcp/a;->a:I

    .line 31
    .line 32
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 33
    .line 34
    .line 35
    invoke-static {p2, p0}, Lcp/a;->c(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    invoke-virtual {p1, p2, p0}, Lbp/a;->a(Landroid/os/Parcel;I)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public b(Lwq/d;)Lwq/d;
    .locals 1

    .line 1
    instance-of v0, p1, Lwq/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object p1

    .line 6
    :cond_0
    new-instance v0, Lwq/b;

    .line 7
    .line 8
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lwq/i;

    .line 11
    .line 12
    invoke-virtual {p0}, Lwq/i;->h()F

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    neg-float p0, p0

    .line 17
    invoke-direct {v0, p0, p1}, Lwq/b;-><init>(FLwq/d;)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public c()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lxa/e;

    .line 4
    .line 5
    iget-object p0, p0, Lxa/f;->e:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0
.end method

.method public d(Lt7/o;)Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p1, Lt7/o;->d:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p1, Lt7/o;->b:Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const-string v3, ""

    .line 10
    .line 11
    if-nez v2, :cond_1

    .line 12
    .line 13
    const-string v2, "und"

    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-static {v0}, Ljava/util/Locale;->forLanguageTag(Ljava/lang/String;)Ljava/util/Locale;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 27
    .line 28
    sget-object v2, Ljava/util/Locale$Category;->DISPLAY:Ljava/util/Locale$Category;

    .line 29
    .line 30
    invoke-static {v2}, Ljava/util/Locale;->getDefault(Ljava/util/Locale$Category;)Ljava/util/Locale;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    invoke-virtual {v0, v2}, Ljava/util/Locale;->getDisplayName(Ljava/util/Locale;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    if-eqz v4, :cond_2

    .line 43
    .line 44
    :cond_1
    :goto_0
    move-object v0, v3

    .line 45
    goto :goto_1

    .line 46
    :cond_2
    const/4 v4, 0x1

    .line 47
    const/4 v5, 0x0

    .line 48
    :try_start_0
    invoke-virtual {v0, v5, v4}, Ljava/lang/String;->offsetByCodePoints(II)I

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    new-instance v6, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, v5, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    invoke-virtual {v5, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 79
    :catch_0
    :goto_1
    invoke-virtual {p0, p1}, Lro/f;->e(Lt7/o;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    filled-new-array {v0, p1}, [Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-virtual {p0, p1}, Lro/f;->l([Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-eqz p1, :cond_4

    .line 96
    .line 97
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-eqz p0, :cond_3

    .line 102
    .line 103
    move-object v1, v3

    .line 104
    :cond_3
    move-object p0, v1

    .line 105
    :cond_4
    return-object p0
.end method

.method public e(Lt7/o;)Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/res/Resources;

    .line 4
    .line 5
    iget v1, p1, Lt7/o;->f:I

    .line 6
    .line 7
    iget p1, p1, Lt7/o;->f:I

    .line 8
    .line 9
    and-int/lit8 v1, v1, 0x2

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    const v1, 0x7f1202f2

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const-string v1, ""

    .line 22
    .line 23
    :goto_0
    and-int/lit8 v2, p1, 0x4

    .line 24
    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    const v2, 0x7f1202f5

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {p0, v1}, Lro/f;->l([Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    :cond_1
    and-int/lit8 v2, p1, 0x8

    .line 43
    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const v2, 0x7f1202f4

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {p0, v1}, Lro/f;->l([Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    :cond_2
    and-int/lit16 p1, p1, 0x440

    .line 62
    .line 63
    if-eqz p1, :cond_3

    .line 64
    .line 65
    const p1, 0x7f1202f3

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    filled-new-array {v1, p1}, [Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-virtual {p0, p1}, Lro/f;->l([Ljava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    return-object p0

    .line 81
    :cond_3
    return-object v1
.end method

.method public f(Lva/a;)V
    .locals 5

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lxa/e;

    .line 4
    .line 5
    iget-object v0, p0, Lxa/e;->g:[I

    .line 6
    .line 7
    array-length v0, v0

    .line 8
    const/4 v1, 0x1

    .line 9
    move v2, v1

    .line 10
    :goto_0
    if-ge v2, v0, :cond_5

    .line 11
    .line 12
    iget-object v3, p0, Lxa/e;->g:[I

    .line 13
    .line 14
    aget v3, v3, v2

    .line 15
    .line 16
    if-eq v3, v1, :cond_4

    .line 17
    .line 18
    const/4 v4, 0x2

    .line 19
    if-eq v3, v4, :cond_3

    .line 20
    .line 21
    const/4 v4, 0x3

    .line 22
    if-eq v3, v4, :cond_2

    .line 23
    .line 24
    const/4 v4, 0x4

    .line 25
    if-eq v3, v4, :cond_1

    .line 26
    .line 27
    const/4 v4, 0x5

    .line 28
    if-eq v3, v4, :cond_0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    invoke-interface {p1, v2}, Lva/a;->bindNull(I)V

    .line 32
    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iget-object v3, p0, Lxa/e;->k:[[B

    .line 36
    .line 37
    aget-object v3, v3, v2

    .line 38
    .line 39
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-interface {p1, v2, v3}, Lva/a;->bindBlob(I[B)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    iget-object v3, p0, Lxa/e;->j:[Ljava/lang/String;

    .line 47
    .line 48
    aget-object v3, v3, v2

    .line 49
    .line 50
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p1, v2, v3}, Lva/a;->bindString(ILjava/lang/String;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    iget-object v3, p0, Lxa/e;->i:[D

    .line 58
    .line 59
    aget-wide v3, v3, v2

    .line 60
    .line 61
    invoke-interface {p1, v2, v3, v4}, Lva/a;->bindDouble(ID)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_4
    iget-object v3, p0, Lxa/e;->h:[J

    .line 66
    .line 67
    aget-wide v3, v3, v2

    .line 68
    .line 69
    invoke-interface {p1, v2, v3, v4}, Lva/a;->bindLong(IJ)V

    .line 70
    .line 71
    .line 72
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_5
    return-void
.end method

.method public g(B)V
    .locals 0

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Parcel;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeByte(B)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public h(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Parcel;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeFloat(F)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public i(J)V
    .locals 8

    .line 1
    invoke-static {p1, p2}, Lt4/o;->b(J)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    invoke-static {v0, v1, v2, v3}, Lt4/p;->a(JJ)Z

    .line 8
    .line 9
    .line 10
    move-result v4

    .line 11
    const/4 v5, 0x0

    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const-wide v6, 0x100000000L

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1, v6, v7}, Lt4/p;->a(JJ)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_1

    .line 25
    .line 26
    const/4 v5, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const-wide v6, 0x200000000L

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1, v6, v7}, Lt4/p;->a(JJ)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    const/4 v5, 0x2

    .line 40
    :cond_2
    :goto_0
    invoke-virtual {p0, v5}, Lro/f;->g(B)V

    .line 41
    .line 42
    .line 43
    invoke-static {p1, p2}, Lt4/o;->b(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    invoke-static {v0, v1, v2, v3}, Lt4/p;->a(JJ)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_3

    .line 52
    .line 53
    invoke-static {p1, p2}, Lt4/o;->c(J)F

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    invoke-virtual {p0, p1}, Lro/f;->h(F)V

    .line 58
    .line 59
    .line 60
    :cond_3
    return-void
.end method

.method public j(J)V
    .locals 4

    .line 1
    const-wide/16 v0, 0x3f

    .line 2
    .line 3
    and-long/2addr v0, p1

    .line 4
    const-wide/16 v2, 0x10

    .line 5
    .line 6
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    if-gez v2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-wide/16 v2, -0x40

    .line 14
    .line 15
    and-long/2addr p1, v2

    .line 16
    const-wide/16 v2, 0x1

    .line 17
    .line 18
    sub-long/2addr v0, v2

    .line 19
    or-long/2addr p1, v0

    .line 20
    :goto_0
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Landroid/os/Parcel;

    .line 23
    .line 24
    invoke-virtual {p0, p1, p2}, Landroid/os/Parcel;->writeLong(J)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public k(Lt7/o;)Ljava/lang/String;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lro/f;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Landroid/content/res/Resources;

    .line 8
    .line 9
    iget-object v3, v1, Lt7/o;->n:Ljava/lang/String;

    .line 10
    .line 11
    iget v4, v1, Lt7/o;->j:I

    .line 12
    .line 13
    iget v5, v1, Lt7/o;->F:I

    .line 14
    .line 15
    iget v6, v1, Lt7/o;->v:I

    .line 16
    .line 17
    iget v7, v1, Lt7/o;->u:I

    .line 18
    .line 19
    iget-object v8, v1, Lt7/o;->k:Ljava/lang/String;

    .line 20
    .line 21
    invoke-static {v3}, Lt7/d0;->h(Ljava/lang/String;)I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    const/4 v9, 0x2

    .line 26
    const/4 v10, 0x1

    .line 27
    const/4 v11, -0x1

    .line 28
    if-eq v3, v11, :cond_0

    .line 29
    .line 30
    goto/16 :goto_6

    .line 31
    .line 32
    :cond_0
    const/4 v3, 0x0

    .line 33
    const/4 v12, 0x0

    .line 34
    if-nez v8, :cond_2

    .line 35
    .line 36
    :cond_1
    move-object/from16 v16, v12

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    invoke-static {v8}, Lw7/w;->M(Ljava/lang/String;)[Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v13

    .line 43
    array-length v14, v13

    .line 44
    move v15, v3

    .line 45
    :goto_0
    if-ge v15, v14, :cond_1

    .line 46
    .line 47
    aget-object v16, v13, v15

    .line 48
    .line 49
    invoke-static/range {v16 .. v16}, Lt7/d0;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v16

    .line 53
    if-eqz v16, :cond_3

    .line 54
    .line 55
    invoke-static/range {v16 .. v16}, Lt7/d0;->l(Ljava/lang/String;)Z

    .line 56
    .line 57
    .line 58
    move-result v17

    .line 59
    if-eqz v17, :cond_3

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    add-int/lit8 v15, v15, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :goto_1
    if-eqz v16, :cond_5

    .line 66
    .line 67
    :cond_4
    :goto_2
    move v3, v9

    .line 68
    goto :goto_6

    .line 69
    :cond_5
    if-nez v8, :cond_6

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_6
    invoke-static {v8}, Lw7/w;->M(Ljava/lang/String;)[Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v8

    .line 76
    array-length v13, v8

    .line 77
    :goto_3
    if-ge v3, v13, :cond_8

    .line 78
    .line 79
    aget-object v14, v8, v3

    .line 80
    .line 81
    invoke-static {v14}, Lt7/d0;->d(Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v14

    .line 85
    if-eqz v14, :cond_7

    .line 86
    .line 87
    invoke-static {v14}, Lt7/d0;->i(Ljava/lang/String;)Z

    .line 88
    .line 89
    .line 90
    move-result v15

    .line 91
    if-eqz v15, :cond_7

    .line 92
    .line 93
    move-object v12, v14

    .line 94
    goto :goto_4

    .line 95
    :cond_7
    add-int/lit8 v3, v3, 0x1

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_8
    :goto_4
    if-eqz v12, :cond_a

    .line 99
    .line 100
    :cond_9
    :goto_5
    move v3, v10

    .line 101
    goto :goto_6

    .line 102
    :cond_a
    if-ne v7, v11, :cond_4

    .line 103
    .line 104
    if-eq v6, v11, :cond_b

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_b
    if-ne v5, v11, :cond_9

    .line 108
    .line 109
    iget v3, v1, Lt7/o;->G:I

    .line 110
    .line 111
    if-eq v3, v11, :cond_c

    .line 112
    .line 113
    goto :goto_5

    .line 114
    :cond_c
    move v3, v11

    .line 115
    :goto_6
    const v8, 0x49742400    # 1000000.0f

    .line 116
    .line 117
    .line 118
    const v12, 0x7f1202ef

    .line 119
    .line 120
    .line 121
    const-string v13, ""

    .line 122
    .line 123
    if-ne v3, v9, :cond_10

    .line 124
    .line 125
    invoke-virtual/range {p0 .. p1}, Lro/f;->e(Lt7/o;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    if-eq v7, v11, :cond_e

    .line 130
    .line 131
    if-ne v6, v11, :cond_d

    .line 132
    .line 133
    goto :goto_7

    .line 134
    :cond_d
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    filled-new-array {v5, v6}, [Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v5

    .line 146
    const v6, 0x7f1202f1

    .line 147
    .line 148
    .line 149
    invoke-virtual {v2, v6, v5}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v5

    .line 153
    goto :goto_8

    .line 154
    :cond_e
    :goto_7
    move-object v5, v13

    .line 155
    :goto_8
    if-ne v4, v11, :cond_f

    .line 156
    .line 157
    goto :goto_9

    .line 158
    :cond_f
    int-to-float v4, v4

    .line 159
    div-float/2addr v4, v8

    .line 160
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    invoke-virtual {v2, v12, v4}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v13

    .line 172
    :goto_9
    filled-new-array {v3, v5, v13}, [Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    invoke-virtual {v0, v3}, Lro/f;->l([Ljava/lang/String;)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    goto :goto_d

    .line 181
    :cond_10
    if-ne v3, v10, :cond_18

    .line 182
    .line 183
    invoke-virtual/range {p0 .. p1}, Lro/f;->d(Lt7/o;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    if-eq v5, v11, :cond_16

    .line 188
    .line 189
    if-ge v5, v10, :cond_11

    .line 190
    .line 191
    goto :goto_a

    .line 192
    :cond_11
    if-eq v5, v10, :cond_15

    .line 193
    .line 194
    if-eq v5, v9, :cond_14

    .line 195
    .line 196
    const/4 v6, 0x6

    .line 197
    if-eq v5, v6, :cond_13

    .line 198
    .line 199
    const/4 v6, 0x7

    .line 200
    if-eq v5, v6, :cond_13

    .line 201
    .line 202
    const/16 v6, 0x8

    .line 203
    .line 204
    if-eq v5, v6, :cond_12

    .line 205
    .line 206
    const v5, 0x7f1202fa

    .line 207
    .line 208
    .line 209
    invoke-virtual {v2, v5}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v5

    .line 213
    goto :goto_b

    .line 214
    :cond_12
    const v5, 0x7f1202fc

    .line 215
    .line 216
    .line 217
    invoke-virtual {v2, v5}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object v5

    .line 221
    goto :goto_b

    .line 222
    :cond_13
    const v5, 0x7f1202fb

    .line 223
    .line 224
    .line 225
    invoke-virtual {v2, v5}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v5

    .line 229
    goto :goto_b

    .line 230
    :cond_14
    const v5, 0x7f1202f9

    .line 231
    .line 232
    .line 233
    invoke-virtual {v2, v5}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v5

    .line 237
    goto :goto_b

    .line 238
    :cond_15
    const v5, 0x7f1202f0

    .line 239
    .line 240
    .line 241
    invoke-virtual {v2, v5}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v5

    .line 245
    goto :goto_b

    .line 246
    :cond_16
    :goto_a
    move-object v5, v13

    .line 247
    :goto_b
    if-ne v4, v11, :cond_17

    .line 248
    .line 249
    goto :goto_c

    .line 250
    :cond_17
    int-to-float v4, v4

    .line 251
    div-float/2addr v4, v8

    .line 252
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v4

    .line 260
    invoke-virtual {v2, v12, v4}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v13

    .line 264
    :goto_c
    filled-new-array {v3, v5, v13}, [Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    invoke-virtual {v0, v3}, Lro/f;->l([Ljava/lang/String;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    goto :goto_d

    .line 273
    :cond_18
    invoke-virtual/range {p0 .. p1}, Lro/f;->d(Lt7/o;)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v0

    .line 277
    :goto_d
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 278
    .line 279
    .line 280
    move-result v3

    .line 281
    if-nez v3, :cond_19

    .line 282
    .line 283
    return-object v0

    .line 284
    :cond_19
    iget-object v0, v1, Lt7/o;->d:Ljava/lang/String;

    .line 285
    .line 286
    if-eqz v0, :cond_1b

    .line 287
    .line 288
    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 293
    .line 294
    .line 295
    move-result v1

    .line 296
    if-eqz v1, :cond_1a

    .line 297
    .line 298
    goto :goto_e

    .line 299
    :cond_1a
    const v1, 0x7f1202fe

    .line 300
    .line 301
    .line 302
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    invoke-virtual {v2, v1, v0}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    return-object v0

    .line 311
    :cond_1b
    :goto_e
    const v0, 0x7f1202fd

    .line 312
    .line 313
    .line 314
    invoke-virtual {v2, v0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    return-object v0
.end method

.method public varargs l([Ljava/lang/String;)Ljava/lang/String;
    .locals 6

    .line 1
    array-length v0, p1

    .line 2
    const-string v1, ""

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    :goto_0
    if-ge v2, v0, :cond_2

    .line 6
    .line 7
    aget-object v3, p1, v2

    .line 8
    .line 9
    invoke-virtual {v3}, Ljava/lang/String;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v4

    .line 13
    if-nez v4, :cond_1

    .line 14
    .line 15
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    move-object v1, v3

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    iget-object v4, p0, Lro/f;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v4, Landroid/content/res/Resources;

    .line 26
    .line 27
    const v5, 0x7f1202ee

    .line 28
    .line 29
    .line 30
    filled-new-array {v1, v3}, [Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v4, v5, v1}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    :cond_1
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    return-object v1
.end method

.method public m(Lil/g;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lqn/s;

    .line 4
    .line 5
    iput-object p1, p0, Lqn/s;->a:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object p1, p0, Lqn/s;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p1, Ljava/util/LinkedList;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lyo/f;

    .line 26
    .line 27
    invoke-interface {v0}, Lyo/f;->b()V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object p1, p0, Lqn/s;->c:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p1, Ljava/util/LinkedList;

    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/util/LinkedList;->clear()V

    .line 36
    .line 37
    .line 38
    const/4 p1, 0x0

    .line 39
    iput-object p1, p0, Lqn/s;->b:Ljava/lang/Object;

    .line 40
    .line 41
    return-void
.end method

.method public n(Lorg/json/JSONObject;)Lus/a;
    .locals 3

    .line 1
    const-string v0, "settings_version"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x3

    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "Could not determine SettingsJsonTransform for settings version "

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v0, ". Using default settings values."

    .line 21
    .line 22
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const/4 v1, 0x0

    .line 30
    const-string v2, "FirebaseCrashlytics"

    .line 31
    .line 32
    invoke-static {v2, v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 33
    .line 34
    .line 35
    new-instance v0, La61/a;

    .line 36
    .line 37
    const/16 v1, 0xf

    .line 38
    .line 39
    invoke-direct {v0, v1}, La61/a;-><init>(I)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    new-instance v0, Ldv/a;

    .line 44
    .line 45
    const/16 v1, 0xf

    .line 46
    .line 47
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 48
    .line 49
    .line 50
    :goto_0
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lwe0/b;

    .line 53
    .line 54
    invoke-interface {v0, p0, p1}, Lus/b;->m(Lwe0/b;Lorg/json/JSONObject;)Lus/a;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public o(Lxr/b;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/internal/measurement/k1;

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/k1;->c:Ljava/util/ArrayList;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    const/4 v1, 0x0

    .line 9
    :goto_0
    :try_start_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-ge v1, v2, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Landroid/util/Pair;

    .line 20
    .line 21
    iget-object v2, v2, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 22
    .line 23
    invoke-virtual {p1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    const-string p0, "FA"

    .line 30
    .line 31
    const-string p1, "OnEventListener already registered."

    .line 32
    .line 33
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 34
    .line 35
    .line 36
    monitor-exit v0

    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    new-instance v1, Lcom/google/android/gms/internal/measurement/h1;

    .line 44
    .line 45
    invoke-direct {v1, p1}, Lcom/google/android/gms/internal/measurement/h1;-><init>(Lxr/b;)V

    .line 46
    .line 47
    .line 48
    new-instance v2, Landroid/util/Pair;

    .line 49
    .line 50
    invoke-direct {v2, p1, v1}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 58
    .line 59
    if-eqz p1, :cond_2

    .line 60
    .line 61
    :try_start_1
    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 62
    .line 63
    invoke-interface {p1, v1}, Lcom/google/android/gms/internal/measurement/k0;->registerOnMeasurementEventListener(Lcom/google/android/gms/internal/measurement/r0;)V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Landroid/os/BadParcelableException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Landroid/os/NetworkOnMainThreadException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :catch_0
    const-string p1, "FA"

    .line 68
    .line 69
    const-string v0, "Failed to register event listener on calling thread. Trying again on the dynamite thread."

    .line 70
    .line 71
    invoke-static {p1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    :cond_2
    new-instance p1, Lcom/google/android/gms/internal/measurement/y0;

    .line 75
    .line 76
    const/4 v0, 0x4

    .line 77
    invoke-direct {p1, p0, v1, v0}, Lcom/google/android/gms/internal/measurement/y0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/Object;I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :goto_1
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 85
    throw p0
.end method

.method public p(ILjava/lang/String;Ljava/util/List;ZZ)V
    .locals 3

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/a1;

    .line 4
    .line 5
    add-int/lit8 p1, p1, -0x1

    .line 6
    .line 7
    const/4 v0, 0x3

    .line 8
    const/4 v1, 0x1

    .line 9
    if-eqz p1, :cond_7

    .line 10
    .line 11
    if-eq p1, v1, :cond_4

    .line 12
    .line 13
    if-eq p1, v0, :cond_3

    .line 14
    .line 15
    const/4 v2, 0x4

    .line 16
    if-eq p1, v2, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lvp/g1;

    .line 21
    .line 22
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 23
    .line 24
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lvp/p0;->p:Lvp/n0;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    if-eqz p4, :cond_1

    .line 31
    .line 32
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Lvp/g1;

    .line 35
    .line 36
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 37
    .line 38
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lvp/p0;->n:Lvp/n0;

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    if-nez p5, :cond_2

    .line 45
    .line 46
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lvp/g1;

    .line 49
    .line 50
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 51
    .line 52
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p0, Lvp/g1;

    .line 61
    .line 62
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 63
    .line 64
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 65
    .line 66
    .line 67
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_3
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lvp/g1;

    .line 73
    .line 74
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 75
    .line 76
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_4
    if-eqz p4, :cond_5

    .line 83
    .line 84
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p0, Lvp/g1;

    .line 87
    .line 88
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 89
    .line 90
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lvp/p0;->k:Lvp/n0;

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_5
    if-nez p5, :cond_6

    .line 97
    .line 98
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Lvp/g1;

    .line 101
    .line 102
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 103
    .line 104
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 105
    .line 106
    .line 107
    iget-object p0, p0, Lvp/p0;->l:Lvp/n0;

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_6
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast p0, Lvp/g1;

    .line 113
    .line 114
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 115
    .line 116
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_7
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p0, Lvp/g1;

    .line 125
    .line 126
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 127
    .line 128
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 129
    .line 130
    .line 131
    iget-object p0, p0, Lvp/p0;->q:Lvp/n0;

    .line 132
    .line 133
    :goto_0
    invoke-interface {p3}, Ljava/util/List;->size()I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    const/4 p4, 0x0

    .line 138
    if-eq p1, v1, :cond_a

    .line 139
    .line 140
    const/4 p5, 0x2

    .line 141
    if-eq p1, p5, :cond_9

    .line 142
    .line 143
    if-eq p1, v0, :cond_8

    .line 144
    .line 145
    invoke-virtual {p0, p2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_8
    invoke-interface {p3, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-interface {p3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p4

    .line 157
    invoke-interface {p3, p5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p3

    .line 161
    invoke-virtual {p0, p2, p1, p4, p3}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    return-void

    .line 165
    :cond_9
    invoke-interface {p3, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-interface {p3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p3

    .line 173
    invoke-virtual {p0, p1, p3, p2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    return-void

    .line 177
    :cond_a
    invoke-interface {p3, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    return-void
.end method

.method public bridge synthetic q(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lxo/f;

    .line 4
    .line 5
    check-cast p1, Lj51/b;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Lxo/f;->c(Lj51/b;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public r(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 8

    .line 1
    iget v0, p0, Lro/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvp/z3;

    .line 9
    .line 10
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    iget-object p0, v0, Lvp/z3;->o:Lvp/g1;

    .line 17
    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 21
    .line 22
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 26
    .line 27
    const-string p1, "AppId not known when logging event"

    .line 28
    .line 29
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {v0}, Lvp/z3;->f()Lvp/e1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    new-instance v1, Ld6/z0;

    .line 38
    .line 39
    const/16 v2, 0xc

    .line 40
    .line 41
    const/4 v7, 0x0

    .line 42
    move-object v3, p0

    .line 43
    move-object v4, p1

    .line 44
    move-object v5, p2

    .line 45
    move-object v6, p3

    .line 46
    invoke-direct/range {v1 .. v7}, Ld6/z0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 50
    .line 51
    .line 52
    :cond_1
    :goto_0
    return-void

    .line 53
    :pswitch_0
    move-object v3, p0

    .line 54
    move-object v4, p1

    .line 55
    move-object v6, p3

    .line 56
    iget-object p0, v3, Lro/f;->e:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v0, p0

    .line 59
    check-cast v0, Lvp/j2;

    .line 60
    .line 61
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_2

    .line 66
    .line 67
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, Lvp/g1;

    .line 70
    .line 71
    iget-object p0, p0, Lvp/g1;->n:Lto/a;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    move-object v3, v6

    .line 77
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 78
    .line 79
    .line 80
    move-result-wide v6

    .line 81
    const-string v1, "auto"

    .line 82
    .line 83
    const-string v2, "_err"

    .line 84
    .line 85
    const/4 v4, 0x1

    .line 86
    const/4 v5, 0x1

    .line 87
    invoke-virtual/range {v0 .. v7}, Lvp/j2;->f0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;ZZJ)V

    .line 88
    .line 89
    .line 90
    return-void

    .line 91
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 95
    .line 96
    const-string p1, "Unexpected call on client side"

    .line 97
    .line 98
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method

.method public s(Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 4

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    iget-object v0, p0, Lvp/g1;->j:Lvp/e1;

    .line 6
    .line 7
    iget-object v1, p0, Lvp/g1;->h:Lvp/w0;

    .line 8
    .line 9
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lvp/g1;->a()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_3

    .line 20
    .line 21
    invoke-virtual {p2}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    const/4 v0, 0x1

    .line 30
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-ne v0, v2, :cond_1

    .line 35
    .line 36
    const-string p1, "auto"

    .line 37
    .line 38
    :cond_1
    new-instance v0, Landroid/net/Uri$Builder;

    .line 39
    .line 40
    invoke-direct {v0}, Landroid/net/Uri$Builder;-><init>()V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, p1}, Landroid/net/Uri$Builder;->path(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p2}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_2

    .line 59
    .line 60
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {p2, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-virtual {v0, v2, v3}, Landroid/net/Uri$Builder;->appendQueryParameter(Ljava/lang/String;Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    invoke-virtual {v0}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    :goto_1
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 83
    .line 84
    .line 85
    move-result p2

    .line 86
    if-nez p2, :cond_3

    .line 87
    .line 88
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 89
    .line 90
    .line 91
    iget-object p2, v1, Lvp/w0;->A:La8/b;

    .line 92
    .line 93
    invoke-virtual {p2, p1}, La8/b;->u(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    iget-object p1, v1, Lvp/w0;->B:La8/s1;

    .line 97
    .line 98
    iget-object p0, p0, Lvp/g1;->n:Lto/a;

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 104
    .line 105
    .line 106
    move-result-wide v0

    .line 107
    invoke-virtual {p1, v0, v1}, La8/s1;->h(J)V

    .line 108
    .line 109
    .line 110
    :cond_3
    return-void
.end method

.method public u()Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Lro/f;->v()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lvp/g1;

    .line 11
    .line 12
    iget-object v0, p0, Lvp/g1;->n:Lto/a;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    iget-object v2, p0, Lvp/g1;->h:Lvp/w0;

    .line 22
    .line 23
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 24
    .line 25
    .line 26
    iget-object v2, v2, Lvp/w0;->B:La8/s1;

    .line 27
    .line 28
    invoke-virtual {v2}, La8/s1;->g()J

    .line 29
    .line 30
    .line 31
    move-result-wide v2

    .line 32
    sub-long/2addr v0, v2

    .line 33
    iget-object p0, p0, Lvp/g1;->g:Lvp/h;

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    sget-object v3, Lvp/z;->j0:Lvp/y;

    .line 37
    .line 38
    invoke-virtual {p0, v2, v3}, Lvp/h;->h0(Ljava/lang/String;Lvp/y;)J

    .line 39
    .line 40
    .line 41
    move-result-wide v2

    .line 42
    cmp-long p0, v0, v2

    .line 43
    .line 44
    if-lez p0, :cond_1

    .line 45
    .line 46
    const/4 p0, 0x1

    .line 47
    return p0

    .line 48
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 49
    return p0
.end method

.method public v()Z
    .locals 4

    .line 1
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    iget-object p0, p0, Lvp/g1;->h:Lvp/w0;

    .line 6
    .line 7
    invoke-static {p0}, Lvp/g1;->g(Lap0/o;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lvp/w0;->B:La8/s1;

    .line 11
    .line 12
    invoke-virtual {p0}, La8/s1;->g()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    const-wide/16 v2, 0x0

    .line 17
    .line 18
    cmp-long p0, v0, v2

    .line 19
    .line 20
    if-lez p0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method
