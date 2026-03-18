.class public final Lorg/altbeacon/beacon/utils/PermissionsInspector;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/beacon/utils/PermissionsInspector$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\u0018\u0000 \r2\u00020\u0001:\u0001\rB\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004J\u0006\u0010\u0005\u001a\u00020\u0006J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0008\u001a\u00020\t2\n\u0008\u0002\u0010\n\u001a\u0004\u0018\u00010\u000b\u00a2\u0006\u0002\u0010\u000cR\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u000e"
    }
    d2 = {
        "Lorg/altbeacon/beacon/utils/PermissionsInspector;",
        "",
        "context",
        "Landroid/content/Context;",
        "(Landroid/content/Context;)V",
        "hasDeclaredBluetoothScanPermissions",
        "",
        "hasPermission",
        "permission",
        "",
        "permissionFlag",
        "",
        "(Ljava/lang/String;Ljava/lang/Integer;)Z",
        "Companion",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lorg/altbeacon/beacon/utils/PermissionsInspector$Companion;

.field private static final TAG:Ljava/lang/String;


# instance fields
.field private final context:Landroid/content/Context;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/utils/PermissionsInspector$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->Companion:Lorg/altbeacon/beacon/utils/PermissionsInspector$Companion;

    .line 8
    .line 9
    const-string v0, "PermissionsInspector"

    .line 10
    .line 11
    sput-object v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->context:Landroid/content/Context;

    .line 10
    .line 11
    return-void
.end method

.method public static synthetic hasPermission$default(Lorg/altbeacon/beacon/utils/PermissionsInspector;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Z
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    :cond_0
    invoke-virtual {p0, p1, p2}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission(Ljava/lang/String;Ljava/lang/Integer;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method


# virtual methods
.method public final hasDeclaredBluetoothScanPermissions()Z
    .locals 6

    .line 1
    const-string v0, "android.permission.BLUETOOTH"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    invoke-static {p0, v0, v1, v2, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission$default(Lorg/altbeacon/beacon/utils/PermissionsInspector;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v3, 0x0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    sget-object v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const-string v4, "BLUETOOTH permission not declared in AndroidManifest.xml.  Will not be able to scan for bluetooth beacons"

    .line 15
    .line 16
    new-array v5, v3, [Ljava/lang/Object;

    .line 17
    .line 18
    invoke-static {v0, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    move v0, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x1

    .line 24
    :goto_0
    const-string v4, "android.permission.BLUETOOTH_ADMIN"

    .line 25
    .line 26
    invoke-static {p0, v4, v1, v2, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission$default(Lorg/altbeacon/beacon/utils/PermissionsInspector;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-nez v4, :cond_1

    .line 31
    .line 32
    sget-object v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 33
    .line 34
    const-string v4, "BLUETOOTH_ADMIN permission not declared in AndroidManifest.xml.  Will not be able to scan for bluetooth beacons"

    .line 35
    .line 36
    new-array v5, v3, [Ljava/lang/Object;

    .line 37
    .line 38
    invoke-static {v0, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move v0, v3

    .line 42
    :cond_1
    const-string v4, "android.permission.ACCESS_FINE_LOCATION"

    .line 43
    .line 44
    invoke-static {p0, v4, v1, v2, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission$default(Lorg/altbeacon/beacon/utils/PermissionsInspector;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-nez v4, :cond_2

    .line 49
    .line 50
    const-string v4, "android.permission.ACCESS_COARSE_LOCATION"

    .line 51
    .line 52
    invoke-static {p0, v4, v1, v2, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission$default(Lorg/altbeacon/beacon/utils/PermissionsInspector;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-nez v4, :cond_2

    .line 57
    .line 58
    sget-object v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 59
    .line 60
    const-string v4, "Neither ACCESS_FINE_LOCATION nor ACCESS_COARSE_LOCATION permission declared in AndroidManifest.xml.  Will not be able to scan for bluetooth beacons"

    .line 61
    .line 62
    new-array v5, v3, [Ljava/lang/Object;

    .line 63
    .line 64
    invoke-static {v0, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    move v0, v3

    .line 68
    :cond_2
    const/high16 v4, 0x10000

    .line 69
    .line 70
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    const-string v5, "android.permission.BLUETOOTH_SCAN"

    .line 75
    .line 76
    invoke-virtual {p0, v5, v4}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission(Ljava/lang/String;Ljava/lang/Integer;)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eqz v4, :cond_3

    .line 81
    .line 82
    sget-object v0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 83
    .line 84
    const-string v4, "The neverForLocation permission flag is attached to BLUETOOTH_SCAN permission AndroidManifest.xml.  This will block detection of bluetooth beacons.  Please remove this from your AndroidManifest.xml, and if you don\'t see it, check the merged manifest in Android Studio, because it may have been added by another library you are using."

    .line 85
    .line 86
    new-array v5, v3, [Ljava/lang/Object;

    .line 87
    .line 88
    invoke-static {v0, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move v0, v3

    .line 92
    :cond_3
    const-string v4, "android.permission.ACCESS_BACKGROUND_LOCATION"

    .line 93
    .line 94
    invoke-static {p0, v4, v1, v2, v1}, Lorg/altbeacon/beacon/utils/PermissionsInspector;->hasPermission$default(Lorg/altbeacon/beacon/utils/PermissionsInspector;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    if-nez p0, :cond_4

    .line 99
    .line 100
    sget-object p0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 101
    .line 102
    const-string v1, "ACCESS_BACKGROUND_LOCATION permission not declared in AndroidManifest.xml.  Will not be able to scan for bluetooth beacons"

    .line 103
    .line 104
    new-array v2, v3, [Ljava/lang/Object;

    .line 105
    .line 106
    invoke-static {p0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_4
    return v0
.end method

.method public final hasPermission(Ljava/lang/String;Ljava/lang/Integer;)Z
    .locals 5

    .line 1
    const-string v0, "permission"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->context:Landroid/content/Context;

    .line 8
    .line 9
    invoke-virtual {v1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object p0, p0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->context:Landroid/content/Context;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/16 v2, 0x1000

    .line 20
    .line 21
    invoke-virtual {v1, p0, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const-string v1, "context.getPackageManage\u2026PERMISSIONS\n            )"

    .line 26
    .line 27
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Landroid/content/pm/PackageInfo;->requestedPermissions:[Ljava/lang/String;

    .line 31
    .line 32
    if-eqz v1, :cond_4

    .line 33
    .line 34
    const-string v2, "info.requestedPermissions"

    .line 35
    .line 36
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    array-length v2, v1

    .line 40
    move v3, v0

    .line 41
    :goto_0
    if-ge v3, v2, :cond_4

    .line 42
    .line 43
    aget-object v4, v1, v3

    .line 44
    .line 45
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_3

    .line 50
    .line 51
    const/4 p1, 0x1

    .line 52
    if-eqz p2, :cond_2

    .line 53
    .line 54
    iget-object p0, p0, Landroid/content/pm/PackageInfo;->requestedPermissionsFlags:[I

    .line 55
    .line 56
    const-string v1, "info.requestedPermissionsFlags"

    .line 57
    .line 58
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    array-length v1, p0

    .line 62
    move v2, v0

    .line 63
    :goto_1
    if-ge v2, v1, :cond_1

    .line 64
    .line 65
    aget v3, p0, v2

    .line 66
    .line 67
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 68
    .line 69
    .line 70
    move-result v4
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    and-int/2addr v3, v4

    .line 72
    if-eqz v3, :cond_0

    .line 73
    .line 74
    return p1

    .line 75
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    return v0

    .line 79
    :cond_2
    return p1

    .line 80
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :catch_0
    sget-object p0, Lorg/altbeacon/beacon/utils/PermissionsInspector;->TAG:Ljava/lang/String;

    .line 84
    .line 85
    const-string p1, "Can\'t read permissions"

    .line 86
    .line 87
    new-array p2, v0, [Ljava/lang/Object;

    .line 88
    .line 89
    invoke-static {p0, p1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    :cond_4
    return v0
.end method
