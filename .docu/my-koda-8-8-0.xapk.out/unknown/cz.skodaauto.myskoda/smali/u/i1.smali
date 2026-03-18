.class public final Lu/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lu/m;

.field public final b:Landroidx/lifecycle/i0;

.field public final c:Landroidx/lifecycle/i0;

.field public d:Z

.field public final e:I

.field public f:Ly4/h;

.field public g:Z


# direct methods
.method public constructor <init>(Lu/m;Lv/b;Lj0/h;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu/i1;->a:Lu/m;

    .line 5
    .line 6
    new-instance p3, Lrx/b;

    .line 7
    .line 8
    const/4 v0, 0x5

    .line 9
    invoke-direct {p3, p2, v0}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p3}, Llp/nf;->b(Lrx/b;)Z

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    invoke-virtual {p2}, Lv/b;->d()Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v1, 0x0

    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 24
    .line 25
    const/16 v2, 0x23

    .line 26
    .line 27
    if-lt v0, v2, :cond_2

    .line 28
    .line 29
    invoke-virtual {p2}, Lv/b;->d()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    if-lt v0, v2, :cond_0

    .line 36
    .line 37
    invoke-static {}, Lf8/a;->l()Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {p2, v0}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    check-cast v0, Ljava/lang/Integer;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 v0, 0x0

    .line 49
    :goto_0
    const/4 v2, 0x1

    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    move v0, v2

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    :goto_1
    if-le v0, v2, :cond_2

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    move v2, v1

    .line 62
    :goto_2
    if-eqz p3, :cond_3

    .line 63
    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    invoke-virtual {p2}, Lv/b;->b()I

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    move p2, v1

    .line 72
    :goto_3
    iput p2, p0, Lu/i1;->e:I

    .line 73
    .line 74
    new-instance p3, Landroidx/lifecycle/i0;

    .line 75
    .line 76
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-direct {p3, v0}, Landroidx/lifecycle/g0;-><init>(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iput-object p3, p0, Lu/i1;->b:Landroidx/lifecycle/i0;

    .line 84
    .line 85
    new-instance p3, Landroidx/lifecycle/i0;

    .line 86
    .line 87
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    invoke-direct {p3, p2}, Landroidx/lifecycle/g0;-><init>(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iput-object p3, p0, Lu/i1;->c:Landroidx/lifecycle/i0;

    .line 95
    .line 96
    new-instance p2, Lu/h1;

    .line 97
    .line 98
    invoke-direct {p2, p0}, Lu/h1;-><init>(Lu/i1;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p1, p2}, Lu/m;->h(Lu/l;)V

    .line 102
    .line 103
    .line 104
    return-void
.end method
