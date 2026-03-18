.class public final Lut/a;
.super Lut/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lst/a;


# instance fields
.field public final b:Lau/g;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lut/a;->c:Lst/a;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Lau/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lut/a;->b:Lau/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 2

    .line 1
    sget-object v0, Lut/a;->c:Lst/a;

    .line 2
    .line 3
    iget-object p0, p0, Lut/a;->b:Lau/g;

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const-string p0, "ApplicationInfo is null"

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0}, Lau/g;->C()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_1

    .line 18
    .line 19
    const-string p0, "GoogleAppId is null"

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-virtual {p0}, Lau/g;->A()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_2

    .line 30
    .line 31
    const-string p0, "AppInstanceId is null"

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_2
    invoke-virtual {p0}, Lau/g;->B()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_3

    .line 42
    .line 43
    const-string p0, "ApplicationProcessState is null"

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    invoke-virtual {p0}, Lau/g;->z()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_5

    .line 54
    .line 55
    invoke-virtual {p0}, Lau/g;->x()Lau/b;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v1}, Lau/b;->w()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-nez v1, :cond_4

    .line 64
    .line 65
    const-string p0, "AndroidAppInfo.packageName is null"

    .line 66
    .line 67
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_4
    invoke-virtual {p0}, Lau/g;->x()Lau/b;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-virtual {p0}, Lau/b;->x()Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-nez p0, :cond_5

    .line 80
    .line 81
    const-string p0, "AndroidAppInfo.sdkVersion is null"

    .line 82
    .line 83
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    :goto_0
    const-string p0, "ApplicationInfo is invalid"

    .line 87
    .line 88
    invoke-virtual {v0, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    const/4 p0, 0x0

    .line 92
    return p0

    .line 93
    :cond_5
    const/4 p0, 0x1

    .line 94
    return p0
.end method
