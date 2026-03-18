.class public final Lu/u0;
.super Lu/c0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lu/u0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lu/u0;

    .line 2
    .line 3
    new-instance v1, La61/a;

    .line 4
    .line 5
    const/16 v2, 0x1b

    .line 6
    .line 7
    invoke-direct {v1, v2}, La61/a;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lu/u0;->b:Lu/u0;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(Lh0/o2;Lb0/n1;)V
    .locals 2

    .line 1
    invoke-super {p0, p1, p2}, Lu/c0;->a(Lh0/o2;Lb0/n1;)V

    .line 2
    .line 3
    .line 4
    instance-of p0, p1, Lh0/y0;

    .line 5
    .line 6
    if-eqz p0, :cond_4

    .line 7
    .line 8
    check-cast p1, Lh0/y0;

    .line 9
    .line 10
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v0, Lh0/y0;->e:Lh0/g;

    .line 15
    .line 16
    invoke-interface {p1, v0}, Lh0/t1;->j(Lh0/g;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_3

    .line 21
    .line 22
    invoke-interface {p1, v0}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    check-cast p1, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    const-class v0, Landroidx/camera/camera2/internal/compat/quirk/ImageCapturePixelHDRPlusQuirk;

    .line 33
    .line 34
    sget-object v1, Lx/a;->a:Ld01/x;

    .line 35
    .line 36
    invoke-virtual {v1, v0}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Landroidx/camera/camera2/internal/compat/quirk/ImageCapturePixelHDRPlusQuirk;

    .line 41
    .line 42
    if-nez v0, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    if-eqz p1, :cond_2

    .line 46
    .line 47
    const/4 v0, 0x1

    .line 48
    if-eq p1, v0, :cond_1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    sget-object p1, Landroid/hardware/camera2/CaptureRequest;->CONTROL_ENABLE_ZSL:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 52
    .line 53
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 54
    .line 55
    invoke-static {p1}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    sget-object p1, Landroid/hardware/camera2/CaptureRequest;->CONTROL_ENABLE_ZSL:Landroid/hardware/camera2/CaptureRequest$Key;

    .line 64
    .line 65
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 66
    .line 67
    invoke-static {p1}, Lt/a;->X(Landroid/hardware/camera2/CaptureRequest$Key;)Lh0/g;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-virtual {p0, p1, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    :cond_3
    :goto_0
    new-instance p1, Lt/a;

    .line 75
    .line 76
    invoke-static {p0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const/4 v0, 0x0

    .line 81
    invoke-direct {p1, p0, v0}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p2, p1}, Lb0/n1;->i(Lh0/q0;)V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 89
    .line 90
    const-string p1, "config is not ImageCaptureConfig"

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0
.end method
