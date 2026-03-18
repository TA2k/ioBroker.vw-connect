.class public final Lhu/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhu/l0;

.field public static final b:Lbu/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lhu/l0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhu/l0;->a:Lhu/l0;

    .line 7
    .line 8
    new-instance v0, Lbt/d;

    .line 9
    .line 10
    invoke-direct {v0}, Lbt/d;-><init>()V

    .line 11
    .line 12
    .line 13
    const-class v1, Lhu/k0;

    .line 14
    .line 15
    sget-object v2, Lhu/g;->a:Lhu/g;

    .line 16
    .line 17
    invoke-virtual {v0, v1, v2}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 18
    .line 19
    .line 20
    const-class v1, Lhu/q0;

    .line 21
    .line 22
    sget-object v2, Lhu/h;->a:Lhu/h;

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 25
    .line 26
    .line 27
    const-class v1, Lhu/k;

    .line 28
    .line 29
    sget-object v2, Lhu/e;->a:Lhu/e;

    .line 30
    .line 31
    invoke-virtual {v0, v1, v2}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 32
    .line 33
    .line 34
    const-class v1, Lhu/b;

    .line 35
    .line 36
    sget-object v2, Lhu/d;->a:Lhu/d;

    .line 37
    .line 38
    invoke-virtual {v0, v1, v2}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 39
    .line 40
    .line 41
    const-class v1, Lhu/a;

    .line 42
    .line 43
    sget-object v2, Lhu/c;->a:Lhu/c;

    .line 44
    .line 45
    invoke-virtual {v0, v1, v2}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 46
    .line 47
    .line 48
    const-class v1, Lhu/b0;

    .line 49
    .line 50
    sget-object v2, Lhu/f;->a:Lhu/f;

    .line 51
    .line 52
    invoke-virtual {v0, v1, v2}, Lbt/d;->a(Ljava/lang/Class;Lzs/d;)Lat/a;

    .line 53
    .line 54
    .line 55
    const/4 v1, 0x1

    .line 56
    iput-boolean v1, v0, Lbt/d;->g:Z

    .line 57
    .line 58
    new-instance v1, Lbu/c;

    .line 59
    .line 60
    const/4 v2, 0x6

    .line 61
    invoke-direct {v1, v0, v2}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    sput-object v1, Lhu/l0;->b:Lbu/c;

    .line 65
    .line 66
    return-void
.end method

.method public static a(Lsr/f;)Lhu/b;
    .locals 10

    .line 1
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lsr/f;->a:Landroid/content/Context;

    .line 5
    .line 6
    const-string v1, "getApplicationContext(...)"

    .line 7
    .line 8
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v3, v2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Landroid/content/pm/PackageInfo;->getLongVersionCode()J

    .line 25
    .line 26
    .line 27
    move-result-wide v4

    .line 28
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    new-instance v8, Lhu/b;

    .line 33
    .line 34
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 35
    .line 36
    .line 37
    iget-object v2, p0, Lsr/f;->c:Lsr/i;

    .line 38
    .line 39
    iget-object v9, v2, Lsr/i;->b:Ljava/lang/String;

    .line 40
    .line 41
    const-string v2, "getApplicationId(...)"

    .line 42
    .line 43
    invoke-static {v9, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    sget-object v2, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 47
    .line 48
    const-string v4, "MODEL"

    .line 49
    .line 50
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sget-object v2, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 54
    .line 55
    const-string v4, "RELEASE"

    .line 56
    .line 57
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    sget-object v2, Lhu/v;->e:Lhu/v;

    .line 61
    .line 62
    new-instance v2, Lhu/a;

    .line 63
    .line 64
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iget-object v1, v1, Landroid/content/pm/PackageInfo;->versionName:Ljava/lang/String;

    .line 68
    .line 69
    if-nez v1, :cond_0

    .line 70
    .line 71
    move-object v4, v5

    .line 72
    goto :goto_0

    .line 73
    :cond_0
    move-object v4, v1

    .line 74
    :goto_0
    sget-object v1, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 75
    .line 76
    const-string v6, "MANUFACTURER"

    .line 77
    .line 78
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 82
    .line 83
    .line 84
    invoke-static {v0}, Lhu/r;->b(Landroid/content/Context;)Lhu/b0;

    .line 85
    .line 86
    .line 87
    move-result-object v6

    .line 88
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 89
    .line 90
    .line 91
    invoke-static {v0}, Lhu/r;->a(Landroid/content/Context;)Ljava/util/ArrayList;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    invoke-direct/range {v2 .. v7}, Lhu/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhu/b0;Ljava/util/ArrayList;)V

    .line 96
    .line 97
    .line 98
    invoke-direct {v8, v9, v2}, Lhu/b;-><init>(Ljava/lang/String;Lhu/a;)V

    .line 99
    .line 100
    .line 101
    return-object v8
.end method
