.class public final Lqb/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lyy0/c2;

.field public final c:Le/g;

.field public final d:Le/g;


# direct methods
.method public constructor <init>(Le/h;Landroid/content/Context;)V
    .locals 5

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lqb/c;->a:Landroid/content/Context;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iput-object v1, p0, Lqb/c;->b:Lyy0/c2;

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    new-instance v2, Landroidx/fragment/app/d1;

    .line 21
    .line 22
    const/4 v3, 0x3

    .line 23
    invoke-direct {v2, v3}, Landroidx/fragment/app/d1;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Lqb/b;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-direct {v3, p0, v4}, Lqb/b;-><init>(Lqb/c;I)V

    .line 30
    .line 31
    .line 32
    const-string v4, "CameraPermissions#"

    .line 33
    .line 34
    invoke-virtual {p1, v4, v2, v3}, Le/h;->d(Ljava/lang/String;Lf/a;Le/b;)Le/g;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move-object v2, v0

    .line 40
    :goto_0
    iput-object v2, p0, Lqb/c;->c:Le/g;

    .line 41
    .line 42
    if-eqz p1, :cond_1

    .line 43
    .line 44
    new-instance v2, Landroidx/fragment/app/d1;

    .line 45
    .line 46
    const/4 v3, 0x4

    .line 47
    invoke-direct {v2, v3}, Landroidx/fragment/app/d1;-><init>(I)V

    .line 48
    .line 49
    .line 50
    new-instance v3, Lqb/b;

    .line 51
    .line 52
    const/4 v4, 0x1

    .line 53
    invoke-direct {v3, p0, v4}, Lqb/b;-><init>(Lqb/c;I)V

    .line 54
    .line 55
    .line 56
    const-string v4, "OpenSettingsDetail#"

    .line 57
    .line 58
    invoke-virtual {p1, v4, v2, v3}, Le/h;->d(Ljava/lang/String;Lf/a;Le/b;)Le/g;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    move-object p1, v0

    .line 64
    :goto_1
    iput-object p1, p0, Lqb/c;->d:Le/g;

    .line 65
    .line 66
    const-string p0, "android.permission.CAMERA"

    .line 67
    .line 68
    invoke-static {p2, p0}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    if-nez p1, :cond_2

    .line 73
    .line 74
    sget-object p0, Lqb/d;->c:Lqb/d;

    .line 75
    .line 76
    goto :goto_5

    .line 77
    :cond_2
    :goto_2
    instance-of p1, p2, Landroid/content/ContextWrapper;

    .line 78
    .line 79
    if-eqz p1, :cond_4

    .line 80
    .line 81
    instance-of p1, p2, Landroid/app/Activity;

    .line 82
    .line 83
    if-eqz p1, :cond_3

    .line 84
    .line 85
    check-cast p2, Landroid/app/Activity;

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_3
    check-cast p2, Landroid/content/ContextWrapper;

    .line 89
    .line 90
    invoke-virtual {p2}, Landroid/content/ContextWrapper;->getBaseContext()Landroid/content/Context;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    const-string p1, "getBaseContext(...)"

    .line 95
    .line 96
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_4
    move-object p2, v0

    .line 101
    :goto_3
    if-nez p2, :cond_5

    .line 102
    .line 103
    const/4 p0, 0x0

    .line 104
    goto :goto_4

    .line 105
    :cond_5
    invoke-static {p2, p0}, Landroidx/core/app/b;->f(Landroid/app/Activity;Ljava/lang/String;)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    :goto_4
    if-eqz p0, :cond_6

    .line 110
    .line 111
    sget-object p0, Lqb/d;->e:Lqb/d;

    .line 112
    .line 113
    goto :goto_5

    .line 114
    :cond_6
    sget-object p0, Lqb/d;->d:Lqb/d;

    .line 115
    .line 116
    :goto_5
    invoke-virtual {v1, v0, p0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    return-void
.end method
