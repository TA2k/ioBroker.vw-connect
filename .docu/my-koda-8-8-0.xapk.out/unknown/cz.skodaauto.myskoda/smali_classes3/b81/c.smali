.class public final Lb81/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/k;
.implements Llo/n;
.implements Lju/b;
.implements Lkw/b;
.implements Lua/b;
.implements Lrl/g;
.implements Lqp/a;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 6

    iput p1, p0, Lb81/c;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    .line 7
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 8
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 9
    iput-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void

    .line 10
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    invoke-static {}, Lorg/xmlpull/v1/XmlPullParserFactory;->newInstance()Lorg/xmlpull/v1/XmlPullParserFactory;

    move-result-object p1

    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 12
    const-string v4, "many"

    const-string v5, "other"

    const-string v0, "zero"

    const-string v1, "one"

    const-string v2, "two"

    const-string v3, "few"

    filled-new-array/range {v0 .. v5}, [Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void

    .line 13
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 15
    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void

    .line 16
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    .line 17
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 18
    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0xa -> :sswitch_2
        0x17 -> :sswitch_1
        0x1c -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(ILhm/g;)V
    .locals 1

    const/16 v0, 0x16

    iput v0, p0, Lb81/c;->d:I

    .line 45
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 46
    iput-object p2, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 47
    new-instance p2, Lrl/e;

    invoke-direct {p2, p1, p0}, Lrl/e;-><init>(ILb81/c;)V

    iput-object p2, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb81/c;->d:I

    iput-object p2, p0, Lb81/c;->e:Ljava/lang/Object;

    iput-object p3, p0, Lb81/c;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 2
    iput p1, p0, Lb81/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Lb81/c;->d:I

    .line 73
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 74
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 75
    new-instance v0, Lca/d;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Lca/d;-><init>(Landroid/content/Context;Z)V

    iput-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/hardware/camera2/CameraCaptureSession;Llp/ra;)V
    .locals 1

    const/16 v0, 0x1a

    iput v0, p0, Lb81/c;->d:I

    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 28
    iput-object p2, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lb81/d;)V
    .locals 5

    const/16 v0, 0xc

    iput v0, p0, Lb81/c;->d:I

    .line 51
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 52
    iget-object p1, p1, Lb81/d;->e:Ljava/lang/Object;

    check-cast p1, Landroid/content/Context;

    .line 53
    const-string v0, "com.google.firebase.crashlytics.unity_version"

    const-string v1, "string"

    invoke-static {p1, v0, v1}, Lms/f;->d(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)I

    move-result v0

    const/4 v1, 0x2

    .line 54
    const-string v2, "FirebaseCrashlytics"

    const/4 v3, 0x0

    if-eqz v0, :cond_0

    .line 55
    const-string v4, "Unity"

    iput-object v4, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 56
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p1

    invoke-virtual {p1, v0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 57
    const-string p0, "Unity Editor version is: "

    .line 58
    invoke-static {p0, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 59
    invoke-static {v2, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result p1

    if-eqz p1, :cond_3

    .line 60
    invoke-static {v2, p0, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    goto :goto_1

    .line 61
    :cond_0
    const-string v0, "flutter_assets/NOTICES.Z"

    .line 62
    invoke-virtual {p1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object v4

    if-nez v4, :cond_1

    goto :goto_0

    .line 63
    :cond_1
    :try_start_0
    invoke-virtual {p1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object p1

    invoke-virtual {p1, v0}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    move-result-object p1

    if-eqz p1, :cond_2

    .line 64
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 65
    :cond_2
    const-string p1, "Flutter"

    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 66
    iput-object v3, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 67
    invoke-static {v2, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result p0

    if-eqz p0, :cond_3

    .line 68
    const-string p0, "Development platform is: Flutter"

    invoke-static {v2, p0, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    goto :goto_1

    .line 69
    :catch_0
    :goto_0
    iput-object v3, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 70
    iput-object v3, p0, Lb81/c;->f:Ljava/lang/Object;

    :cond_3
    :goto_1
    return-void
.end method

.method public constructor <init>(Lh0/k0;)V
    .locals 2

    const/16 v0, 0x18

    iput v0, p0, Lb81/c;->d:I

    .line 32
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 33
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 34
    new-instance p1, Landroidx/lifecycle/i0;

    .line 35
    invoke-direct {p1}, Landroidx/lifecycle/g0;-><init>()V

    .line 36
    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 37
    new-instance p0, Lb0/d;

    const/4 v0, 0x5

    const/4 v1, 0x0

    invoke-direct {p0, v0, v1}, Lb0/d;-><init>(ILb0/e;)V

    .line 38
    invoke-virtual {p1, p0}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;)V
    .locals 1

    const/16 v0, 0x13

    iput v0, p0, Lb81/c;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    new-instance p1, Ljava/util/ArrayList;

    .line 4
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Lb81/c;->d:I

    .line 42
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 43
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 44
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lka/e1;)V
    .locals 1

    const/16 v0, 0xd

    iput v0, p0, Lb81/c;->d:I

    .line 76
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 77
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 78
    new-instance p1, Li9/d;

    .line 79
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 80
    iput v0, p1, Li9/d;->a:I

    .line 81
    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lkw/d;)V
    .locals 1

    const/16 v0, 0xe

    iput v0, p0, Lb81/c;->d:I

    .line 71
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 72
    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ll20/c;)V
    .locals 1

    const/16 p1, 0x11

    iput p1, p0, Lb81/c;->d:I

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 21
    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ll71/w;Ll71/z;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb81/c;->d:I

    const-string v0, "dependencies"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "trajectoryConfig"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 40
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 41
    iput-object p2, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lla/r;Lua/b;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Lb81/c;->d:I

    .line 48
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 49
    const-string v0, "actual"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    iput-object p2, p0, Lb81/c;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqp/h;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lb81/c;->d:I

    const-string v0, "mapView"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 24
    iput-object p2, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lss/b;Lvy0/l;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lb81/c;->d:I

    const-string v0, "requestData"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    iput-object p1, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 31
    iput-object p2, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/a1;Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0x1b

    iput v0, p0, Lb81/c;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lb81/c;->e:Ljava/lang/Object;

    iput-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    return-void
.end method

.method public static d(Lorg/xmlpull/v1/XmlPullParser;)Ljava/lang/String;
    .locals 11

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    :cond_0
    :goto_0
    if-eqz v1, :cond_a

    .line 8
    .line 9
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->nextToken()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/16 v3, 0x3e

    .line 14
    .line 15
    packed-switch v2, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :pswitch_0
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->getText()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :pswitch_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v3, "<![CDATA["

    .line 30
    .line 31
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->getText()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v3, "]]>"

    .line 42
    .line 43
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :pswitch_2
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->getText()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    const-string v3, "parser.text"

    .line 59
    .line 60
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const/16 v3, 0x22

    .line 64
    .line 65
    invoke-static {v2, v3}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    const/16 v5, 0x5c

    .line 70
    .line 71
    const/4 v6, 0x0

    .line 72
    if-nez v4, :cond_1

    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_1
    new-instance v4, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 78
    .line 79
    .line 80
    move v7, v6

    .line 81
    move v8, v7

    .line 82
    :goto_1
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 83
    .line 84
    .line 85
    move-result v9

    .line 86
    if-ge v7, v9, :cond_4

    .line 87
    .line 88
    invoke-virtual {v2, v7}, Ljava/lang/String;->charAt(I)C

    .line 89
    .line 90
    .line 91
    move-result v9

    .line 92
    add-int/lit8 v10, v8, 0x1

    .line 93
    .line 94
    if-ne v9, v3, :cond_2

    .line 95
    .line 96
    if-eqz v8, :cond_3

    .line 97
    .line 98
    add-int/lit8 v8, v8, -0x1

    .line 99
    .line 100
    invoke-virtual {v2, v8}, Ljava/lang/String;->charAt(I)C

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    if-ne v8, v5, :cond_3

    .line 105
    .line 106
    :cond_2
    invoke-virtual {v4, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 107
    .line 108
    .line 109
    :cond_3
    add-int/lit8 v7, v7, 0x1

    .line 110
    .line 111
    move v8, v10

    .line 112
    goto :goto_1

    .line 113
    :cond_4
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    const-string v3, "filterIndexedTo(StringBu\u2026(), predicate).toString()"

    .line 118
    .line 119
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    :goto_2
    invoke-static {v2, v5}, Lly0/p;->B(Ljava/lang/CharSequence;C)Z

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-nez v3, :cond_5

    .line 127
    .line 128
    goto :goto_5

    .line 129
    :cond_5
    sget-object v3, Lx01/a;->a:Ly01/a;

    .line 130
    .line 131
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    :try_start_0
    new-instance v4, Ljava/io/StringWriter;

    .line 135
    .line 136
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    mul-int/lit8 v5, v5, 0x2

    .line 141
    .line 142
    invoke-direct {v4, v5}, Ljava/io/StringWriter;-><init>(I)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    move v7, v6

    .line 150
    :cond_6
    :goto_3
    if-ge v7, v5, :cond_9

    .line 151
    .line 152
    invoke-virtual {v3, v2, v7, v4}, Ly01/a;->a(Ljava/lang/String;ILjava/io/StringWriter;)I

    .line 153
    .line 154
    .line 155
    move-result v8

    .line 156
    if-nez v8, :cond_8

    .line 157
    .line 158
    invoke-virtual {v2, v7}, Ljava/lang/String;->charAt(I)C

    .line 159
    .line 160
    .line 161
    move-result v8

    .line 162
    invoke-virtual {v4, v8}, Ljava/io/Writer;->write(I)V

    .line 163
    .line 164
    .line 165
    add-int/lit8 v9, v7, 0x1

    .line 166
    .line 167
    invoke-static {v8}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 168
    .line 169
    .line 170
    move-result v8

    .line 171
    if-eqz v8, :cond_7

    .line 172
    .line 173
    if-ge v9, v5, :cond_7

    .line 174
    .line 175
    invoke-virtual {v2, v9}, Ljava/lang/String;->charAt(I)C

    .line 176
    .line 177
    .line 178
    move-result v8

    .line 179
    invoke-static {v8}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 180
    .line 181
    .line 182
    move-result v10

    .line 183
    if-eqz v10, :cond_7

    .line 184
    .line 185
    invoke-virtual {v4, v8}, Ljava/io/Writer;->write(I)V

    .line 186
    .line 187
    .line 188
    add-int/lit8 v7, v7, 0x2

    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_7
    move v7, v9

    .line 192
    goto :goto_3

    .line 193
    :cond_8
    move v9, v6

    .line 194
    :goto_4
    if-ge v9, v8, :cond_6

    .line 195
    .line 196
    invoke-static {v2, v7}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 197
    .line 198
    .line 199
    move-result v10

    .line 200
    invoke-static {v10}, Ljava/lang/Character;->charCount(I)I

    .line 201
    .line 202
    .line 203
    move-result v10

    .line 204
    add-int/2addr v7, v10

    .line 205
    add-int/lit8 v9, v9, 0x1

    .line 206
    .line 207
    goto :goto_4

    .line 208
    :cond_9
    invoke-virtual {v4}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v2
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 212
    const-string v3, "unescapeJava(s)"

    .line 213
    .line 214
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    :goto_5
    const-string v3, "\n"

    .line 218
    .line 219
    const-string v4, "<br/>"

    .line 220
    .line 221
    invoke-static {v6, v2, v3, v4}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 226
    .line 227
    .line 228
    goto/16 :goto_0

    .line 229
    .line 230
    :catch_0
    move-exception p0

    .line 231
    new-instance v0, Ljava/io/UncheckedIOException;

    .line 232
    .line 233
    invoke-direct {v0, p0}, Ljava/io/UncheckedIOException;-><init>(Ljava/io/IOException;)V

    .line 234
    .line 235
    .line 236
    throw v0

    .line 237
    :pswitch_3
    add-int/lit8 v1, v1, -0x1

    .line 238
    .line 239
    if-lez v1, :cond_0

    .line 240
    .line 241
    new-instance v2, Ljava/lang/StringBuilder;

    .line 242
    .line 243
    const-string v4, "</"

    .line 244
    .line 245
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 256
    .line 257
    .line 258
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v2

    .line 262
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 263
    .line 264
    .line 265
    goto/16 :goto_0

    .line 266
    .line 267
    :pswitch_4
    add-int/lit8 v1, v1, 0x1

    .line 268
    .line 269
    new-instance v2, Ljava/lang/StringBuilder;

    .line 270
    .line 271
    const-string v4, "<"

    .line 272
    .line 273
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v4

    .line 280
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 284
    .line 285
    .line 286
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 291
    .line 292
    .line 293
    goto/16 :goto_0

    .line 294
    .line 295
    :pswitch_5
    new-instance p0, Ljava/io/EOFException;

    .line 296
    .line 297
    const-string v0, "Got unexpected EOF"

    .line 298
    .line 299
    invoke-direct {p0, v0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    throw p0

    .line 303
    :cond_a
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object p0

    .line 307
    const-string v0, "sb.toString()"

    .line 308
    .line 309
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    return-object p0

    .line 313
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static varargs u([Ljava/lang/String;)Lb81/c;
    .locals 12

    .line 1
    :try_start_0
    array-length v0, p0

    .line 2
    new-array v0, v0, [Lu01/i;

    .line 3
    .line 4
    new-instance v1, Lu01/f;

    .line 5
    .line 6
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    array-length v4, p0

    .line 12
    if-ge v3, v4, :cond_7

    .line 13
    .line 14
    aget-object v4, p0, v3

    .line 15
    .line 16
    sget-object v5, Lfn/a;->h:[Ljava/lang/String;

    .line 17
    .line 18
    const/16 v6, 0x22

    .line 19
    .line 20
    invoke-virtual {v1, v6}, Lu01/f;->h0(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 24
    .line 25
    .line 26
    move-result v7

    .line 27
    move v8, v2

    .line 28
    move v9, v8

    .line 29
    :goto_1
    if-ge v8, v7, :cond_5

    .line 30
    .line 31
    invoke-virtual {v4, v8}, Ljava/lang/String;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result v10

    .line 35
    const/16 v11, 0x80

    .line 36
    .line 37
    if-ge v10, v11, :cond_0

    .line 38
    .line 39
    aget-object v10, v5, v10

    .line 40
    .line 41
    if-nez v10, :cond_2

    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_0
    const/16 v11, 0x2028

    .line 45
    .line 46
    if-ne v10, v11, :cond_1

    .line 47
    .line 48
    const-string v10, "\\u2028"

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_1
    const/16 v11, 0x2029

    .line 52
    .line 53
    if-ne v10, v11, :cond_4

    .line 54
    .line 55
    const-string v10, "\\u2029"

    .line 56
    .line 57
    :cond_2
    :goto_2
    if-ge v9, v8, :cond_3

    .line 58
    .line 59
    invoke-virtual {v1, v9, v8, v4}, Lu01/f;->r0(IILjava/lang/String;)V

    .line 60
    .line 61
    .line 62
    :cond_3
    invoke-virtual {v1, v10}, Lu01/f;->x0(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    add-int/lit8 v9, v8, 0x1

    .line 66
    .line 67
    :cond_4
    :goto_3
    add-int/lit8 v8, v8, 0x1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_5
    if-ge v9, v7, :cond_6

    .line 71
    .line 72
    invoke-virtual {v1, v9, v7, v4}, Lu01/f;->r0(IILjava/lang/String;)V

    .line 73
    .line 74
    .line 75
    :cond_6
    invoke-virtual {v1, v6}, Lu01/f;->h0(I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1}, Lu01/f;->readByte()B

    .line 79
    .line 80
    .line 81
    iget-wide v4, v1, Lu01/f;->e:J

    .line 82
    .line 83
    invoke-virtual {v1, v4, v5}, Lu01/f;->S(J)Lu01/i;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    aput-object v4, v0, v3

    .line 88
    .line 89
    add-int/lit8 v3, v3, 0x1

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_7
    new-instance v1, Lb81/c;

    .line 93
    .line 94
    invoke-virtual {p0}, [Ljava/lang/String;->clone()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    check-cast p0, [Ljava/lang/String;

    .line 99
    .line 100
    invoke-static {v0}, Lu01/b;->f([Lu01/i;)Lu01/w;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    const/4 v2, 0x6

    .line 105
    invoke-direct {v1, v2, p0, v0}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 106
    .line 107
    .line 108
    return-object v1

    .line 109
    :catch_0
    move-exception p0

    .line 110
    new-instance v0, Ljava/lang/AssertionError;

    .line 111
    .line 112
    invoke-direct {v0, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    throw v0
.end method


# virtual methods
.method public a(Lrl/a;)Lrl/b;
    .locals 1

    .line 1
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lrl/e;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lrl/d;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    new-instance p1, Lrl/b;

    .line 14
    .line 15
    iget-object v0, p0, Lrl/d;->a:Landroid/graphics/Bitmap;

    .line 16
    .line 17
    iget-object p0, p0, Lrl/d;->b:Ljava/util/Map;

    .line 18
    .line 19
    invoke-direct {p1, v0, p0}, Lrl/b;-><init>(Landroid/graphics/Bitmap;Ljava/util/Map;)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return-object p0
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb81/c;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v1, p2

    .line 11
    .line 12
    check-cast v1, Laq/k;

    .line 13
    .line 14
    move-object/from16 v4, p1

    .line 15
    .line 16
    check-cast v4, Lxo/i;

    .line 17
    .line 18
    invoke-virtual {v4}, Lno/e;->r()Landroid/os/IInterface;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    check-cast v4, Lxo/k;

    .line 23
    .line 24
    new-instance v5, Lxo/e;

    .line 25
    .line 26
    sget-object v6, Lip/v;->o:Lip/v;

    .line 27
    .line 28
    invoke-direct {v5, v1, v6}, Lxo/e;-><init>(Laq/k;Lxo/a;)V

    .line 29
    .line 30
    .line 31
    invoke-static {}, Lkp/b8;->b()Lko/f;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    iget-object v6, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v6, Ljava/util/List;

    .line 38
    .line 39
    iget-object v0, v0, Lb81/c;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lxo/c;

    .line 42
    .line 43
    invoke-virtual {v4}, Lxo/k;->a()Landroid/os/Parcel;

    .line 44
    .line 45
    .line 46
    move-result-object v7

    .line 47
    invoke-virtual {v7, v6}, Landroid/os/Parcel;->writeStringList(Ljava/util/List;)V

    .line 48
    .line 49
    .line 50
    sget v6, Lfp/a;->a:I

    .line 51
    .line 52
    invoke-virtual {v7, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v7, v5}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v7, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v7, v2}, Lko/f;->writeToParcel(Landroid/os/Parcel;I)V

    .line 62
    .line 63
    .line 64
    const/16 v0, 0x2c

    .line 65
    .line 66
    invoke-virtual {v4, v7, v0}, Lxo/k;->b(Landroid/os/Parcel;I)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :pswitch_0
    move-object/from16 v1, p2

    .line 71
    .line 72
    check-cast v1, Laq/k;

    .line 73
    .line 74
    move-object/from16 v4, p1

    .line 75
    .line 76
    check-cast v4, Lgp/f;

    .line 77
    .line 78
    iget-object v5, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v10, v5

    .line 81
    check-cast v10, Landroid/app/PendingIntent;

    .line 82
    .line 83
    iget-object v0, v0, Lb81/c;->f:Ljava/lang/Object;

    .line 84
    .line 85
    move-object v12, v0

    .line 86
    check-cast v12, Lcom/google/android/gms/location/LocationRequest;

    .line 87
    .line 88
    invoke-virtual {v4}, Lno/e;->k()[Ljo/d;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    const/4 v5, 0x0

    .line 93
    if-eqz v0, :cond_3

    .line 94
    .line 95
    :goto_0
    array-length v6, v0

    .line 96
    if-ge v2, v6, :cond_1

    .line 97
    .line 98
    aget-object v6, v0, v2

    .line 99
    .line 100
    const-string v7, "location_updates_with_callback"

    .line 101
    .line 102
    iget-object v8, v6, Ljo/d;->d:Ljava/lang/String;

    .line 103
    .line 104
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v7

    .line 108
    if-eqz v7, :cond_0

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_1
    move-object v6, v5

    .line 115
    :goto_1
    if-nez v6, :cond_2

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_2
    invoke-virtual {v6}, Ljo/d;->x0()J

    .line 119
    .line 120
    .line 121
    move-result-wide v6

    .line 122
    const-wide/16 v8, 0x1

    .line 123
    .line 124
    cmp-long v0, v6, v8

    .line 125
    .line 126
    if-ltz v0, :cond_3

    .line 127
    .line 128
    invoke-virtual {v4}, Lno/e;->r()Landroid/os/IInterface;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    check-cast v0, Lgp/v;

    .line 133
    .line 134
    new-instance v6, Lgp/h;

    .line 135
    .line 136
    const/4 v9, 0x0

    .line 137
    const/4 v11, 0x0

    .line 138
    const/4 v7, 0x3

    .line 139
    const/4 v8, 0x0

    .line 140
    invoke-direct/range {v6 .. v11}, Lgp/h;-><init>(ILandroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    new-instance v2, Lbp/r;

    .line 144
    .line 145
    invoke-direct {v2, v5, v1, v3}, Lbp/r;-><init>(Ljava/lang/Object;Laq/k;I)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    invoke-static {v1, v6}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 153
    .line 154
    .line 155
    invoke-static {v1, v12}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 159
    .line 160
    .line 161
    const/16 v2, 0x58

    .line 162
    .line 163
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 164
    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_3
    :goto_2
    invoke-virtual {v4}, Lno/e;->r()Landroid/os/IInterface;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    check-cast v0, Lgp/v;

    .line 172
    .line 173
    new-instance v8, Lgp/i;

    .line 174
    .line 175
    const/16 v17, 0x0

    .line 176
    .line 177
    const-wide v18, 0x7fffffffffffffffL

    .line 178
    .line 179
    .line 180
    .line 181
    .line 182
    const/4 v13, 0x0

    .line 183
    const/4 v14, 0x0

    .line 184
    const/4 v15, 0x0

    .line 185
    const/16 v16, 0x0

    .line 186
    .line 187
    move-object v11, v8

    .line 188
    invoke-direct/range {v11 .. v19}, Lgp/i;-><init>(Lcom/google/android/gms/location/LocationRequest;Ljava/util/ArrayList;ZZZZJ)V

    .line 189
    .line 190
    .line 191
    new-instance v12, Lgp/c;

    .line 192
    .line 193
    invoke-direct {v12, v5, v1}, Lgp/c;-><init>(Ljava/lang/Boolean;Laq/k;)V

    .line 194
    .line 195
    .line 196
    new-instance v6, Lgp/j;

    .line 197
    .line 198
    invoke-virtual {v10}, Landroid/app/PendingIntent;->hashCode()I

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v2

    .line 206
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    new-instance v3, Ljava/lang/StringBuilder;

    .line 211
    .line 212
    add-int/lit8 v2, v2, 0xe

    .line 213
    .line 214
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 215
    .line 216
    .line 217
    const-string v2, "PendingIntent@"

    .line 218
    .line 219
    invoke-static {v1, v2, v3}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v13

    .line 223
    const/4 v7, 0x1

    .line 224
    const/4 v9, 0x0

    .line 225
    move-object v11, v10

    .line 226
    const/4 v10, 0x0

    .line 227
    invoke-direct/range {v6 .. v13}, Lgp/j;-><init>(ILgp/i;Landroid/os/IBinder;Landroid/os/IBinder;Landroid/app/PendingIntent;Landroid/os/IBinder;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    invoke-static {v1, v6}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 235
    .line 236
    .line 237
    const/16 v2, 0x3b

    .line 238
    .line 239
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 240
    .line 241
    .line 242
    :goto_3
    return-void

    .line 243
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;Le5/f;)V
    .locals 9

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x0

    .line 3
    const-string v2, "plurals"

    .line 4
    .line 5
    invoke-interface {p1, v0, v1, v2}, Lorg/xmlpull/v1/XmlPullParser;->require(ILjava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    :goto_0
    invoke-interface {p1}, Lorg/xmlpull/v1/XmlPullParser;->nextTag()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const/4 v4, 0x3

    .line 13
    if-eq v3, v4, :cond_3

    .line 14
    .line 15
    invoke-interface {p1}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-ne v3, v0, :cond_0

    .line 20
    .line 21
    const-string v3, "item"

    .line 22
    .line 23
    invoke-interface {p1, v0, v1, v3}, Lorg/xmlpull/v1/XmlPullParser;->require(ILjava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v5, "quantity"

    .line 27
    .line 28
    invoke-interface {p1, v1, v5}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    iget-object v7, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v7, [Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v6, v7}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    if-eqz v7, :cond_2

    .line 41
    .line 42
    invoke-static {p1}, Lb81/c;->d(Lorg/xmlpull/v1/XmlPullParser;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v7

    .line 46
    invoke-static {v6, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    iget-object v5, p3, Le5/f;->c:Ljava/util/HashMap;

    .line 50
    .line 51
    invoke-virtual {v5, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    check-cast v8, Ljava/util/HashMap;

    .line 56
    .line 57
    if-nez v8, :cond_1

    .line 58
    .line 59
    new-instance v8, Ljava/util/HashMap;

    .line 60
    .line 61
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v5, p2, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    :cond_1
    invoke-interface {v8, v6, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    invoke-interface {p1, v4, v1, v3}, Lorg/xmlpull/v1/XmlPullParser;->require(ILjava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_2
    new-instance p0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 75
    .line 76
    const-string p1, "Unknown quantity qualifier: "

    .line 77
    .line 78
    invoke-static {p1, v6}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-direct {p0, p1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_3
    invoke-interface {p1, v4, v1, v2}, Lorg/xmlpull/v1/XmlPullParser;->require(ILjava/lang/String;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    return-void
.end method

.method public c(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const-string v0, "="

    .line 6
    .line 7
    invoke-static {p2, v0, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public e(Lsp/k;)Landroid/view/View;
    .locals 5

    .line 1
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lqp/h;

    .line 4
    .line 5
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Luu/k1;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-object v1, p0, Luu/k1;->i:Lay0/o;

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    :goto_0
    const/4 p0, 0x0

    .line 23
    return-object p0

    .line 24
    :cond_1
    new-instance v2, Lw3/g1;

    .line 25
    .line 26
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    const-string v4, "getContext(...)"

    .line 31
    .line 32
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {v2, v3}, Lw3/g1;-><init>(Landroid/content/Context;)V

    .line 36
    .line 37
    .line 38
    new-instance v3, Luu/n;

    .line 39
    .line 40
    const/4 v4, 0x0

    .line 41
    invoke-direct {v3, v1, p1, v4}, Luu/n;-><init>(Lay0/o;Lsp/k;I)V

    .line 42
    .line 43
    .line 44
    new-instance p1, Lt2/b;

    .line 45
    .line 46
    const/4 v1, 0x1

    .line 47
    const v4, 0x59e7bc27

    .line 48
    .line 49
    .line 50
    invoke-direct {p1, v3, v1, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2, p1}, Lw3/g1;->setContent(Lay0/n;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Luu/k1;->a:Ll2/r;

    .line 57
    .line 58
    invoke-static {v0, v2, p0}, Llp/ga;->a(Lqp/h;Lw3/g1;Ll2/r;)V

    .line 59
    .line 60
    .line 61
    return-object v2
.end method

.method public f(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lrl/e;

    .line 4
    .line 5
    const/16 v0, 0x28

    .line 6
    .line 7
    if-lt p1, v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Landroidx/collection/w;->evictAll()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    const/16 v0, 0xa

    .line 14
    .line 15
    if-gt v0, p1, :cond_1

    .line 16
    .line 17
    const/16 v0, 0x14

    .line 18
    .line 19
    if-ge p1, v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0}, Landroidx/collection/w;->size()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    div-int/lit8 p1, p1, 0x2

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Landroidx/collection/w;->trimToSize(I)V

    .line 28
    .line 29
    .line 30
    :cond_1
    return-void
.end method

.method public g(Lsp/k;)Landroid/view/View;
    .locals 5

    .line 1
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lqp/h;

    .line 4
    .line 5
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Luu/k1;

    .line 14
    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-object v1, p0, Luu/k1;->h:Lay0/o;

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    :goto_0
    const/4 p0, 0x0

    .line 23
    return-object p0

    .line 24
    :cond_1
    new-instance v2, Lw3/g1;

    .line 25
    .line 26
    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    const-string v4, "getContext(...)"

    .line 31
    .line 32
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {v2, v3}, Lw3/g1;-><init>(Landroid/content/Context;)V

    .line 36
    .line 37
    .line 38
    new-instance v3, Luu/n;

    .line 39
    .line 40
    const/4 v4, 0x1

    .line 41
    invoke-direct {v3, v1, p1, v4}, Luu/n;-><init>(Lay0/o;Lsp/k;I)V

    .line 42
    .line 43
    .line 44
    new-instance p1, Lt2/b;

    .line 45
    .line 46
    const/4 v1, 0x1

    .line 47
    const v4, -0x2c3fb683

    .line 48
    .line 49
    .line 50
    invoke-direct {p1, v3, v1, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2, p1}, Lw3/g1;->setContent(Lay0/n;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Luu/k1;->a:Ll2/r;

    .line 57
    .line 58
    invoke-static {v0, v2, p0}, Llp/ga;->a(Lqp/h;Lw3/g1;Ll2/r;)V

    .line 59
    .line 60
    .line 61
    return-object v2
.end method

.method public get()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lj1/a;

    .line 4
    .line 5
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Landroid/content/Context;

    .line 8
    .line 9
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lkx0/a;

    .line 12
    .line 13
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lpx0/g;

    .line 18
    .line 19
    const-string v1, "appContext"

    .line 20
    .line 21
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string v1, "blockingDispatcher"

    .line 25
    .line 26
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lb3/g;

    .line 30
    .line 31
    new-instance v2, Lh70/f;

    .line 32
    .line 33
    const/4 v3, 0x6

    .line 34
    invoke-direct {v2, v3}, Lh70/f;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-direct {v1, v2}, Lb3/g;-><init>(Lay0/k;)V

    .line 38
    .line 39
    .line 40
    invoke-static {p0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    new-instance v2, Laa/x;

    .line 45
    .line 46
    const/4 v3, 0x1

    .line 47
    invoke-direct {v2, v0, v3}, Laa/x;-><init>(Landroid/content/Context;I)V

    .line 48
    .line 49
    .line 50
    sget-object v0, Lku/h;->a:Lku/h;

    .line 51
    .line 52
    invoke-static {v0, v1, p0, v2}, Lhu/o;->b(Lm6/u0;Lb3/g;Lpw0/a;Lay0/a;)Lm6/w;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public h()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 7
    .line 8
    .line 9
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    monitor-exit p0

    .line 13
    const/4 p0, 0x0

    .line 14
    return p0

    .line 15
    :cond_0
    :try_start_1
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    .line 21
    .line 22
    monitor-exit p0

    .line 23
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :catchall_0
    move-exception v0

    .line 26
    monitor-exit p0

    .line 27
    throw v0
.end method

.method public i()V
    .locals 2

    .line 1
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    :try_start_0
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lss/b;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    new-instance v1, Ljava/io/File;

    .line 13
    .line 14
    iget-object p0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ljava/io/File;

    .line 17
    .line 18
    invoke-direct {v1, p0, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/io/File;->createNewFile()Z
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :catch_0
    move-exception p0

    .line 26
    const-string v1, "Error creating marker: "

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const-string v1, "FirebaseCrashlytics"

    .line 33
    .line 34
    invoke-static {v1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public j()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lua/b;

    .line 4
    .line 5
    invoke-interface {p0}, Lua/b;->j()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public k(Landroid/os/Handler;La8/f0;La8/f0;La8/f0;La8/f0;)[La8/f;
    .locals 12

    .line 1
    move-object/from16 v0, p5

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object v2, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v2, Landroid/content/Context;

    .line 11
    .line 12
    new-instance v3, Lm8/i;

    .line 13
    .line 14
    invoke-direct {v3, v2}, Lm8/i;-><init>(Landroid/content/Context;)V

    .line 15
    .line 16
    .line 17
    iget-object v4, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 18
    .line 19
    move-object v7, v4

    .line 20
    check-cast v7, Lca/d;

    .line 21
    .line 22
    iput-object v7, v3, Lm8/i;->c:Lf8/l;

    .line 23
    .line 24
    const-wide/16 v4, 0x1388

    .line 25
    .line 26
    iput-wide v4, v3, Lm8/i;->d:J

    .line 27
    .line 28
    iput-object p1, v3, Lm8/i;->e:Landroid/os/Handler;

    .line 29
    .line 30
    iput-object p2, v3, Lm8/i;->f:La8/f0;

    .line 31
    .line 32
    const/16 p2, 0x32

    .line 33
    .line 34
    iput p2, v3, Lm8/i;->g:I

    .line 35
    .line 36
    iget-boolean p2, v3, Lm8/i;->b:Z

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    xor-int/2addr p2, v4

    .line 40
    invoke-static {p2}, Lw7/a;->j(Z)V

    .line 41
    .line 42
    .line 43
    iget-object p2, v3, Lm8/i;->e:Landroid/os/Handler;

    .line 44
    .line 45
    const/4 v11, 0x0

    .line 46
    if-nez p2, :cond_0

    .line 47
    .line 48
    iget-object v5, v3, Lm8/i;->f:La8/f0;

    .line 49
    .line 50
    if-eqz v5, :cond_1

    .line 51
    .line 52
    :cond_0
    if-eqz p2, :cond_2

    .line 53
    .line 54
    iget-object p2, v3, Lm8/i;->f:La8/f0;

    .line 55
    .line 56
    if-eqz p2, :cond_2

    .line 57
    .line 58
    :cond_1
    move p2, v4

    .line 59
    goto :goto_0

    .line 60
    :cond_2
    move p2, v11

    .line 61
    :goto_0
    invoke-static {p2}, Lw7/a;->j(Z)V

    .line 62
    .line 63
    .line 64
    iput-boolean v4, v3, Lm8/i;->b:Z

    .line 65
    .line 66
    new-instance p2, Lm8/l;

    .line 67
    .line 68
    invoke-direct {p2, v3}, Lm8/l;-><init>(Lm8/i;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    new-instance p2, Lc8/s;

    .line 75
    .line 76
    invoke-direct {p2, v2}, Lc8/s;-><init>(Landroid/content/Context;)V

    .line 77
    .line 78
    .line 79
    iget-boolean v3, p2, Lc8/s;->d:Z

    .line 80
    .line 81
    xor-int/2addr v3, v4

    .line 82
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 83
    .line 84
    .line 85
    iput-boolean v4, p2, Lc8/s;->d:Z

    .line 86
    .line 87
    iget-object v3, p2, Lc8/s;->c:Lgw0/c;

    .line 88
    .line 89
    if-nez v3, :cond_3

    .line 90
    .line 91
    new-instance v3, Lgw0/c;

    .line 92
    .line 93
    new-array v4, v11, [Lu7/f;

    .line 94
    .line 95
    invoke-direct {v3, v4}, Lgw0/c;-><init>([Lu7/f;)V

    .line 96
    .line 97
    .line 98
    iput-object v3, p2, Lc8/s;->c:Lgw0/c;

    .line 99
    .line 100
    :cond_3
    iget-object v3, p2, Lc8/s;->g:Lc2/k;

    .line 101
    .line 102
    if-nez v3, :cond_4

    .line 103
    .line 104
    new-instance v3, Lc2/k;

    .line 105
    .line 106
    invoke-direct {v3, v2}, Lc2/k;-><init>(Landroid/content/Context;)V

    .line 107
    .line 108
    .line 109
    iput-object v3, p2, Lc8/s;->g:Lc2/k;

    .line 110
    .line 111
    :cond_4
    new-instance v10, Lc8/y;

    .line 112
    .line 113
    invoke-direct {v10, p2}, Lc8/y;-><init>(Lc8/s;)V

    .line 114
    .line 115
    .line 116
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 117
    .line 118
    move-object v6, p0

    .line 119
    check-cast v6, Landroid/content/Context;

    .line 120
    .line 121
    new-instance v5, Lc8/a0;

    .line 122
    .line 123
    move-object v8, p1

    .line 124
    move-object v9, p3

    .line 125
    invoke-direct/range {v5 .. v10}, Lc8/a0;-><init>(Landroid/content/Context;Lf8/l;Landroid/os/Handler;La8/f0;Lc8/y;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    new-instance p2, Li8/e;

    .line 136
    .line 137
    move-object/from16 v3, p4

    .line 138
    .line 139
    invoke-direct {p2, v3, p0}, Li8/e;-><init>(La8/f0;Landroid/os/Looper;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    invoke-virtual {p1}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    new-instance p1, Lg8/b;

    .line 150
    .line 151
    invoke-direct {p1, v0, p0}, Lg8/b;-><init>(La8/f0;Landroid/os/Looper;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    new-instance p1, Lg8/b;

    .line 158
    .line 159
    invoke-direct {p1, v0, p0}, Lg8/b;-><init>(La8/f0;Landroid/os/Looper;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    new-instance p0, Ln8/b;

    .line 166
    .line 167
    invoke-direct {p0}, Ln8/b;-><init>()V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    new-instance p0, Le8/f;

    .line 174
    .line 175
    new-instance p1, Lcq/r1;

    .line 176
    .line 177
    const/4 p2, 0x0

    .line 178
    invoke-direct {p1, v2, p2}, Lcq/r1;-><init>(Landroid/content/Context;Z)V

    .line 179
    .line 180
    .line 181
    invoke-direct {p0, p1}, Le8/f;-><init>(Lcq/r1;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    new-array p0, v11, [La8/f;

    .line 188
    .line 189
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    check-cast p0, [La8/f;

    .line 194
    .line 195
    return-object p0
.end method

.method public l(IIII)Landroid/view/View;
    .locals 8

    .line 1
    iget-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Li9/d;

    .line 4
    .line 5
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lka/e1;

    .line 8
    .line 9
    invoke-interface {p0}, Lka/e1;->c()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-interface {p0}, Lka/e1;->n()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-le p2, p1, :cond_0

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v3, -0x1

    .line 22
    :goto_0
    const/4 v4, 0x0

    .line 23
    :goto_1
    if-eq p1, p2, :cond_3

    .line 24
    .line 25
    invoke-interface {p0, p1}, Lka/e1;->r(I)Landroid/view/View;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    invoke-interface {p0, v5}, Lka/e1;->b(Landroid/view/View;)I

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    invoke-interface {p0, v5}, Lka/e1;->s(Landroid/view/View;)I

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    iput v1, v0, Li9/d;->b:I

    .line 38
    .line 39
    iput v2, v0, Li9/d;->c:I

    .line 40
    .line 41
    iput v6, v0, Li9/d;->d:I

    .line 42
    .line 43
    iput v7, v0, Li9/d;->e:I

    .line 44
    .line 45
    if-eqz p3, :cond_1

    .line 46
    .line 47
    iput p3, v0, Li9/d;->a:I

    .line 48
    .line 49
    invoke-virtual {v0}, Li9/d;->a()Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-eqz v6, :cond_1

    .line 54
    .line 55
    return-object v5

    .line 56
    :cond_1
    if-eqz p4, :cond_2

    .line 57
    .line 58
    iput p4, v0, Li9/d;->a:I

    .line 59
    .line 60
    invoke-virtual {v0}, Li9/d;->a()Z

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    if-eqz v6, :cond_2

    .line 65
    .line 66
    move-object v4, v5

    .line 67
    :cond_2
    add-int/2addr p1, v3

    .line 68
    goto :goto_1

    .line 69
    :cond_3
    return-object v4
.end method

.method public m()Lh0/y1;
    .locals 6

    .line 1
    new-instance v0, Lh0/y1;

    .line 2
    .line 3
    invoke-direct {v0}, Lh0/y1;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Ljava/util/Map$Entry;

    .line 34
    .line 35
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    check-cast v4, Lh0/l2;

    .line 40
    .line 41
    iget-boolean v5, v4, Lh0/l2;->f:Z

    .line 42
    .line 43
    if-eqz v5, :cond_0

    .line 44
    .line 45
    iget-boolean v5, v4, Lh0/l2;->e:Z

    .line 46
    .line 47
    if-eqz v5, :cond_0

    .line 48
    .line 49
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Ljava/lang/String;

    .line 54
    .line 55
    iget-object v4, v4, Lh0/l2;->a:Lh0/z1;

    .line 56
    .line 57
    invoke-virtual {v0, v4}, Lh0/y1;->a(Lh0/z1;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v3, "Active and attached use case: "

    .line 67
    .line 68
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v1, " for camera: "

    .line 75
    .line 76
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Ljava/lang/String;

    .line 82
    .line 83
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    const-string v1, "UseCaseAttachState"

    .line 91
    .line 92
    invoke-static {v1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-object v0
.end method

.method public n()Lh0/y1;
    .locals 6

    .line 1
    new-instance v0, Lh0/y1;

    .line 2
    .line 3
    invoke-direct {v0}, Lh0/y1;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v2, Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Ljava/util/Map$Entry;

    .line 34
    .line 35
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    check-cast v4, Lh0/l2;

    .line 40
    .line 41
    iget-boolean v5, v4, Lh0/l2;->e:Z

    .line 42
    .line 43
    if-eqz v5, :cond_0

    .line 44
    .line 45
    iget-object v4, v4, Lh0/l2;->a:Lh0/z1;

    .line 46
    .line 47
    invoke-virtual {v0, v4}, Lh0/y1;->a(Lh0/z1;)V

    .line 48
    .line 49
    .line 50
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    check-cast v3, Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 61
    .line 62
    const-string v3, "All use case: "

    .line 63
    .line 64
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, " for camera: "

    .line 71
    .line 72
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Ljava/lang/String;

    .line 78
    .line 79
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    const-string v1, "UseCaseAttachState"

    .line 87
    .line 88
    invoke-static {v1, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    return-object v0
.end method

.method public o(Lrl/a;Landroid/graphics/Bitmap;Ljava/util/Map;)V
    .locals 3

    .line 1
    invoke-static {p2}, Llp/ye;->b(Landroid/graphics/Bitmap;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lrl/e;

    .line 8
    .line 9
    invoke-virtual {v1}, Landroidx/collection/w;->maxSize()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    if-gt v0, v2, :cond_0

    .line 14
    .line 15
    new-instance p0, Lrl/d;

    .line 16
    .line 17
    invoke-direct {p0, p2, p3, v0}, Lrl/d;-><init>(Landroid/graphics/Bitmap;Ljava/util/Map;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p1, p0}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    invoke-virtual {v1, p1}, Landroidx/collection/w;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lhm/g;

    .line 30
    .line 31
    invoke-virtual {p0, p1, p2, p3, v0}, Lhm/g;->d(Lrl/a;Landroid/graphics/Bitmap;Ljava/util/Map;I)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public onFailure(Ld01/j;Ljava/io/IOException;)V
    .locals 3

    .line 1
    const-string v0, "call"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "e"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p1, Lvy0/l;

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    sget-object v0, Lvy0/l;->j:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 19
    .line 20
    invoke-virtual {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    instance-of v0, v0, Lvy0/m;

    .line 25
    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lss/b;

    .line 32
    .line 33
    instance-of v0, p2, Ldw0/h;

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-nez p0, :cond_1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    move-object p2, p0

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    instance-of v0, p2, Ljava/net/SocketTimeoutException;

    .line 47
    .line 48
    if-eqz v0, :cond_4

    .line 49
    .line 50
    invoke-virtual {p2}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-eqz v0, :cond_3

    .line 55
    .line 56
    const-string v1, "connect"

    .line 57
    .line 58
    const/4 v2, 0x1

    .line 59
    invoke-static {v0, v1, v2}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-ne v0, v2, :cond_3

    .line 64
    .line 65
    invoke-static {p0, p2}, Lfw0/a1;->a(Lss/b;Ljava/lang/Throwable;)Lew0/a;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    goto :goto_0

    .line 70
    :cond_3
    invoke-static {p0, p2}, Lfw0/a1;->b(Lss/b;Ljava/io/IOException;)Ljava/net/SocketTimeoutException;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    :cond_4
    :goto_0
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {p1, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method

.method public onResponse(Ld01/j;Ld01/t0;)V
    .locals 1

    .line 1
    const-string v0, "call"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "response"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Ld01/j;->isCanceled()Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lvy0/l;

    .line 20
    .line 21
    invoke-virtual {p0, p2}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public open(Ljava/lang/String;)Lua/a;
    .locals 7

    .line 1
    const-string v0, "fileName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lla/r;

    .line 9
    .line 10
    const-string v1, ":memory:"

    .line 11
    .line 12
    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-nez v2, :cond_0

    .line 17
    .line 18
    iget-object v2, v0, Lla/r;->c:Lla/b;

    .line 19
    .line 20
    iget-object v2, v2, Lla/b;->a:Landroid/content/Context;

    .line 21
    .line 22
    invoke-virtual {v2, p1}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    new-instance v2, Lma/a;

    .line 34
    .line 35
    iget-boolean v3, v0, Lla/a;->a:Z

    .line 36
    .line 37
    const/4 v4, 0x1

    .line 38
    const/4 v5, 0x0

    .line 39
    if-nez v3, :cond_1

    .line 40
    .line 41
    iget-boolean v3, v0, Lla/a;->b:Z

    .line 42
    .line 43
    if-nez v3, :cond_1

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_1

    .line 50
    .line 51
    move v1, v4

    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move v1, v5

    .line 54
    :goto_0
    invoke-direct {v2, p1, v1}, Lma/a;-><init>(Ljava/lang/String;Z)V

    .line 55
    .line 56
    .line 57
    iget-object v1, v2, Lma/a;->a:Ljava/util/concurrent/locks/ReentrantLock;

    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 60
    .line 61
    .line 62
    iget-object v2, v2, Lma/a;->b:Lb81/d;

    .line 63
    .line 64
    if-eqz v2, :cond_2

    .line 65
    .line 66
    :try_start_0
    invoke-virtual {v2}, Lb81/d;->o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :catchall_0
    move-exception p0

    .line 71
    move v4, v5

    .line 72
    goto/16 :goto_6

    .line 73
    .line 74
    :cond_2
    :goto_1
    const/4 v3, 0x0

    .line 75
    :try_start_1
    iget-boolean v6, v0, Lla/a;->b:Z

    .line 76
    .line 77
    if-nez v6, :cond_7

    .line 78
    .line 79
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Lua/b;

    .line 82
    .line 83
    invoke-interface {p0, p1}, Lua/b;->open(Ljava/lang/String;)Lua/a;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    iget-boolean v6, v0, Lla/a;->a:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 88
    .line 89
    if-nez v6, :cond_3

    .line 90
    .line 91
    :try_start_2
    iput-boolean v4, v0, Lla/a;->b:Z

    .line 92
    .line 93
    invoke-static {v0, p0}, Lla/a;->a(Lla/r;Lua/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 94
    .line 95
    .line 96
    :try_start_3
    iput-boolean v5, v0, Lla/a;->b:Z

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :catchall_1
    move-exception p0

    .line 100
    iput-boolean v5, v0, Lla/a;->b:Z

    .line 101
    .line 102
    throw p0

    .line 103
    :cond_3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    iget-object v5, v0, Lla/r;->c:Lla/b;

    .line 107
    .line 108
    iget-object v5, v5, Lla/b;->g:Lla/t;

    .line 109
    .line 110
    sget-object v6, Lla/t;->f:Lla/t;

    .line 111
    .line 112
    if-ne v5, v6, :cond_4

    .line 113
    .line 114
    const-string v5, "PRAGMA synchronous = NORMAL"

    .line 115
    .line 116
    invoke-static {p0, v5}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_4
    const-string v5, "PRAGMA synchronous = FULL"

    .line 121
    .line 122
    invoke-static {p0, v5}, Llp/k1;->b(Lua/a;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    :goto_2
    invoke-static {p0}, Lla/a;->b(Lua/a;)V

    .line 126
    .line 127
    .line 128
    iget-object v0, v0, Lla/r;->d:Lka/u;

    .line 129
    .line 130
    invoke-virtual {v0, p0}, Lka/u;->s(Lua/a;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 131
    .line 132
    .line 133
    :goto_3
    if-eqz v2, :cond_6

    .line 134
    .line 135
    :try_start_4
    iget-object v0, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v0, Ljava/nio/channels/FileChannel;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    .line 138
    .line 139
    if-nez v0, :cond_5

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_5
    :try_start_5
    invoke-virtual {v0}, Ljava/nio/channels/spi/AbstractInterruptibleChannel;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 143
    .line 144
    .line 145
    :try_start_6
    iput-object v3, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :catchall_2
    move-exception p0

    .line 149
    iput-object v3, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 150
    .line 151
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    .line 152
    :cond_6
    :goto_4
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 153
    .line 154
    .line 155
    return-object p0

    .line 156
    :cond_7
    :try_start_7
    const-string p0, "Recursive database initialization detected. Did you try to use the database instance during initialization? Maybe in one of the callbacks?"

    .line 157
    .line 158
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 159
    .line 160
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 164
    :catchall_3
    move-exception p0

    .line 165
    if-eqz v2, :cond_9

    .line 166
    .line 167
    :try_start_8
    iget-object v0, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v0, Ljava/nio/channels/FileChannel;
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 170
    .line 171
    if-nez v0, :cond_8

    .line 172
    .line 173
    goto :goto_5

    .line 174
    :cond_8
    :try_start_9
    invoke-virtual {v0}, Ljava/nio/channels/spi/AbstractInterruptibleChannel;->close()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 175
    .line 176
    .line 177
    :try_start_a
    iput-object v3, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 178
    .line 179
    goto :goto_5

    .line 180
    :catchall_4
    move-exception p0

    .line 181
    iput-object v3, v2, Lb81/d;->f:Ljava/lang/Object;

    .line 182
    .line 183
    throw p0

    .line 184
    :cond_9
    :goto_5
    throw p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 185
    :catchall_5
    move-exception p0

    .line 186
    :goto_6
    if-eqz v4, :cond_a

    .line 187
    .line 188
    :try_start_b
    throw p0

    .line 189
    :catchall_6
    move-exception p0

    .line 190
    goto :goto_7

    .line 191
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 192
    .line 193
    new-instance v2, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    const-string v3, "Unable to open database \'"

    .line 196
    .line 197
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    const-string p1, "\'. Was a proper path / name used in Room\'s database builder?"

    .line 204
    .line 205
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-direct {v0, p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 213
    .line 214
    .line 215
    throw v0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_6

    .line 216
    :goto_7
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 217
    .line 218
    .line 219
    throw p0
.end method

.method public p()Ljava/util/Collection;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Ljava/util/Map$Entry;

    .line 29
    .line 30
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lh0/l2;

    .line 35
    .line 36
    iget-boolean v2, v2, Lh0/l2;->e:Z

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lh0/l2;

    .line 45
    .line 46
    iget-object v1, v1, Lh0/l2;->a:Lh0/z1;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableCollection(Ljava/util/Collection;)Ljava/util/Collection;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public q(Lmw/j;Lnw/g;)V
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lb81/c;->e:Ljava/lang/Object;

    .line 8
    .line 9
    move-object v4, v3

    .line 10
    check-cast v4, Lc1/h2;

    .line 11
    .line 12
    if-eqz v4, :cond_e

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    goto/16 :goto_8

    .line 17
    .line 18
    :cond_0
    iget-object v3, v2, Lnw/g;->a:Ld3/a;

    .line 19
    .line 20
    const/4 v10, 0x0

    .line 21
    iput v10, v3, Ld3/a;->b:F

    .line 22
    .line 23
    iput v10, v3, Ld3/a;->c:F

    .line 24
    .line 25
    iput v10, v3, Ld3/a;->d:F

    .line 26
    .line 27
    iput v10, v3, Ld3/a;->e:F

    .line 28
    .line 29
    iget-object v5, v4, Lc1/h2;->e:Ljava/lang/Object;

    .line 30
    .line 31
    move-object v11, v5

    .line 32
    check-cast v11, Lkw/i;

    .line 33
    .line 34
    invoke-virtual {v2, v4, v11, v1, v3}, Lnw/g;->a(Lkw/g;Lkw/i;Ljava/lang/Object;Ld3/a;)V

    .line 35
    .line 36
    .line 37
    iget-object v5, v4, Lc1/h2;->d:Ljava/lang/Object;

    .line 38
    .line 39
    move-object v12, v5

    .line 40
    check-cast v12, Landroid/graphics/Canvas;

    .line 41
    .line 42
    iget-object v5, v4, Lc1/h2;->c:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v13, v5

    .line 45
    check-cast v13, Landroid/graphics/RectF;

    .line 46
    .line 47
    iget v5, v13, Landroid/graphics/RectF;->left:F

    .line 48
    .line 49
    iget-object v6, v4, Lc1/h2;->b:Ljava/lang/Object;

    .line 50
    .line 51
    move-object v14, v6

    .line 52
    check-cast v14, Lkw/g;

    .line 53
    .line 54
    invoke-interface {v14}, Lpw/f;->e()Z

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    if-eqz v6, :cond_1

    .line 59
    .line 60
    iget v6, v3, Ld3/a;->b:F

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    iget v6, v3, Ld3/a;->d:F

    .line 64
    .line 65
    :goto_0
    sub-float/2addr v5, v6

    .line 66
    iget v6, v13, Landroid/graphics/RectF;->top:F

    .line 67
    .line 68
    iget v8, v3, Ld3/a;->c:F

    .line 69
    .line 70
    sub-float/2addr v6, v8

    .line 71
    iget v8, v13, Landroid/graphics/RectF;->right:F

    .line 72
    .line 73
    invoke-interface {v14}, Lpw/f;->e()Z

    .line 74
    .line 75
    .line 76
    move-result v9

    .line 77
    if-eqz v9, :cond_2

    .line 78
    .line 79
    iget v9, v3, Ld3/a;->d:F

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_2
    iget v9, v3, Ld3/a;->b:F

    .line 83
    .line 84
    :goto_1
    add-float/2addr v9, v8

    .line 85
    iget v8, v13, Landroid/graphics/RectF;->bottom:F

    .line 86
    .line 87
    iget v3, v3, Ld3/a;->e:F

    .line 88
    .line 89
    add-float/2addr v8, v3

    .line 90
    invoke-virtual {v12}, Landroid/graphics/Canvas;->save()I

    .line 91
    .line 92
    .line 93
    move-result v15

    .line 94
    invoke-virtual {v12, v5, v6, v9, v8}, Landroid/graphics/Canvas;->clipRect(FFFF)Z

    .line 95
    .line 96
    .line 97
    iget-object v8, v2, Lnw/g;->i:Landroid/graphics/Canvas;

    .line 98
    .line 99
    iget-object v3, v2, Lnw/g;->g:Ljava/util/LinkedHashMap;

    .line 100
    .line 101
    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->clear()V

    .line 102
    .line 103
    .line 104
    iget-object v9, v2, Lnw/g;->h:Landroid/graphics/Path;

    .line 105
    .line 106
    invoke-virtual {v9}, Landroid/graphics/Path;->rewind()V

    .line 107
    .line 108
    .line 109
    iget-object v3, v1, Lmw/j;->h:Lrw/b;

    .line 110
    .line 111
    iget-object v5, v2, Lnw/g;->f:Lgv/a;

    .line 112
    .line 113
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    const-string v6, "key"

    .line 117
    .line 118
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    iget-object v6, v3, Lrw/b;->a:Ljava/util/LinkedHashMap;

    .line 122
    .line 123
    invoke-virtual {v6, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    if-nez v5, :cond_3

    .line 128
    .line 129
    const/4 v5, 0x0

    .line 130
    :cond_3
    check-cast v5, Lmw/g;

    .line 131
    .line 132
    iget-object v1, v1, Lmw/j;->b:Ljava/util/ArrayList;

    .line 133
    .line 134
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 135
    .line 136
    .line 137
    move-result-object v16

    .line 138
    const/4 v5, 0x0

    .line 139
    :goto_2
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->hasNext()Z

    .line 140
    .line 141
    .line 142
    move-result v6

    .line 143
    if-eqz v6, :cond_b

    .line 144
    .line 145
    invoke-interface/range {v16 .. v16}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    add-int/lit8 v17, v5, 0x1

    .line 150
    .line 151
    if-ltz v5, :cond_a

    .line 152
    .line 153
    move-object/from16 v18, v6

    .line 154
    .line 155
    check-cast v18, Ljava/util/List;

    .line 156
    .line 157
    invoke-virtual {v9}, Landroid/graphics/Path;->rewind()V

    .line 158
    .line 159
    .line 160
    iget-object v6, v2, Lnw/g;->b:Lnw/f;

    .line 161
    .line 162
    invoke-virtual {v6, v5, v3}, Lnw/f;->a(ILrw/b;)Lnw/e;

    .line 163
    .line 164
    .line 165
    move-result-object v6

    .line 166
    move/from16 v19, v5

    .line 167
    .line 168
    new-instance v5, Lkotlin/jvm/internal/c0;

    .line 169
    .line 170
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 171
    .line 172
    .line 173
    invoke-interface {v14}, Lpw/f;->e()Z

    .line 174
    .line 175
    .line 176
    move-result v1

    .line 177
    invoke-static {v13, v1}, Ljp/ae;->a(Landroid/graphics/RectF;Z)F

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    iput v1, v5, Lkotlin/jvm/internal/c0;->d:F

    .line 182
    .line 183
    move-object v1, v3

    .line 184
    move-object v3, v6

    .line 185
    new-instance v6, Lkotlin/jvm/internal/c0;

    .line 186
    .line 187
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 188
    .line 189
    .line 190
    iget v7, v13, Landroid/graphics/RectF;->bottom:F

    .line 191
    .line 192
    iput v7, v6, Lkotlin/jvm/internal/c0;->d:F

    .line 193
    .line 194
    invoke-interface {v14}, Lpw/f;->h()F

    .line 195
    .line 196
    .line 197
    move-result v7

    .line 198
    invoke-virtual {v11}, Lkw/i;->d()F

    .line 199
    .line 200
    .line 201
    move-result v21

    .line 202
    mul-float v21, v21, v7

    .line 203
    .line 204
    invoke-interface {v14}, Lpw/f;->e()Z

    .line 205
    .line 206
    .line 207
    move-result v7

    .line 208
    invoke-static {v13, v7}, Ljp/ae;->a(Landroid/graphics/RectF;Z)F

    .line 209
    .line 210
    .line 211
    move-result v7

    .line 212
    add-float v7, v7, v21

    .line 213
    .line 214
    iget v10, v4, Lc1/h2;->a:F

    .line 215
    .line 216
    sub-float/2addr v7, v10

    .line 217
    move-object v10, v1

    .line 218
    new-instance v1, Lnw/b;

    .line 219
    .line 220
    move-object/from16 p1, v10

    .line 221
    .line 222
    const/4 v10, 0x0

    .line 223
    invoke-direct/range {v1 .. v6}, Lnw/b;-><init>(Lnw/g;Lnw/e;Lc1/h2;Lkotlin/jvm/internal/c0;Lkotlin/jvm/internal/c0;)V

    .line 224
    .line 225
    .line 226
    move-object v6, v1

    .line 227
    move-object v1, v2

    .line 228
    move-object v2, v4

    .line 229
    move v4, v7

    .line 230
    const/4 v5, 0x0

    .line 231
    move-object v7, v3

    .line 232
    move-object/from16 v3, v18

    .line 233
    .line 234
    invoke-virtual/range {v1 .. v6}, Lnw/g;->c(Lc1/h2;Ljava/util/List;FLjava/util/Map;Lay0/q;)V

    .line 235
    .line 236
    .line 237
    move/from16 v18, v4

    .line 238
    .line 239
    move-object v4, v5

    .line 240
    iget-object v5, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast v5, Landroid/graphics/Canvas;

    .line 243
    .line 244
    const-string v6, "<this>"

    .line 245
    .line 246
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v5}, Landroid/graphics/Canvas;->getWidth()I

    .line 250
    .line 251
    .line 252
    move-result v4

    .line 253
    int-to-float v4, v4

    .line 254
    invoke-virtual {v5}, Landroid/graphics/Canvas;->getHeight()I

    .line 255
    .line 256
    .line 257
    move-result v10

    .line 258
    int-to-float v10, v10

    .line 259
    const/high16 v22, 0x437f0000    # 255.0f

    .line 260
    .line 261
    invoke-static/range {v22 .. v22}, Lcy0/a;->i(F)I

    .line 262
    .line 263
    .line 264
    move-result v27

    .line 265
    const/16 v23, 0x0

    .line 266
    .line 267
    const/16 v24, 0x0

    .line 268
    .line 269
    move/from16 v25, v4

    .line 270
    .line 271
    move-object/from16 v22, v5

    .line 272
    .line 273
    move/from16 v26, v10

    .line 274
    .line 275
    invoke-virtual/range {v22 .. v27}, Landroid/graphics/Canvas;->saveLayerAlpha(FFFFI)I

    .line 276
    .line 277
    .line 278
    iget-object v4, v1, Lnw/g;->j:Lfv/b;

    .line 279
    .line 280
    invoke-static/range {v19 .. v19}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object v5

    .line 284
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    invoke-static {v2, v4, v5}, Ljp/xd;->a(Lc1/h2;Lfv/b;[Ljava/lang/Object;)Landroid/graphics/Bitmap;

    .line 289
    .line 290
    .line 291
    move-result-object v10

    .line 292
    invoke-virtual {v8, v10}, Landroid/graphics/Canvas;->setBitmap(Landroid/graphics/Bitmap;)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 296
    .line 297
    .line 298
    const/high16 v4, 0x40000000    # 2.0f

    .line 299
    .line 300
    invoke-interface {v14, v4}, Lpw/f;->c(F)F

    .line 301
    .line 302
    .line 303
    move-result v4

    .line 304
    iget-object v5, v7, Lnw/e;->d:Landroid/graphics/Paint;

    .line 305
    .line 306
    invoke-virtual {v5, v4}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 307
    .line 308
    .line 309
    move-object/from16 v22, v3

    .line 310
    .line 311
    const/4 v3, 0x2

    .line 312
    int-to-float v3, v3

    .line 313
    div-float/2addr v4, v3

    .line 314
    iget-object v3, v7, Lnw/e;->b:Lnw/h;

    .line 315
    .line 316
    if-eqz v3, :cond_9

    .line 317
    .line 318
    move/from16 v23, v4

    .line 319
    .line 320
    iget-object v4, v3, Lnw/h;->c:Landroid/graphics/Path;

    .line 321
    .line 322
    move-object/from16 v24, v5

    .line 323
    .line 324
    iget-object v5, v3, Lnw/h;->d:Landroid/graphics/Path;

    .line 325
    .line 326
    move-object/from16 v25, v7

    .line 327
    .line 328
    iget-object v7, v3, Lnw/h;->e:Landroid/graphics/RectF;

    .line 329
    .line 330
    move-object/from16 v26, v8

    .line 331
    .line 332
    iget-object v8, v3, Lnw/h;->i:Landroid/graphics/Path;

    .line 333
    .line 334
    invoke-virtual {v8}, Landroid/graphics/Path;->rewind()V

    .line 335
    .line 336
    .line 337
    iget-object v8, v3, Lnw/h;->b:Landroid/graphics/RectF;

    .line 338
    .line 339
    move-object/from16 v27, v11

    .line 340
    .line 341
    const/4 v11, 0x0

    .line 342
    invoke-virtual {v9, v8, v11}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 343
    .line 344
    .line 345
    iget-object v11, v3, Lnw/h;->g:Lay0/k;

    .line 346
    .line 347
    move-object/from16 v28, v14

    .line 348
    .line 349
    const-string v14, "splitY"

    .line 350
    .line 351
    invoke-static {v11, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    invoke-interface/range {v28 .. v28}, Lkw/g;->j()Lmw/b;

    .line 355
    .line 356
    .line 357
    move-result-object v14

    .line 358
    const/4 v0, 0x0

    .line 359
    invoke-interface {v14, v0}, Lmw/b;->e(Llw/e;)Lmw/k;

    .line 360
    .line 361
    .line 362
    move-result-object v14

    .line 363
    iget v0, v13, Landroid/graphics/RectF;->bottom:F

    .line 364
    .line 365
    move/from16 v29, v0

    .line 366
    .line 367
    invoke-interface/range {v28 .. v28}, Lkw/g;->g()Lmw/a;

    .line 368
    .line 369
    .line 370
    move-result-object v0

    .line 371
    iget-object v0, v0, Lmw/a;->c:Lrw/b;

    .line 372
    .line 373
    invoke-interface {v11, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    check-cast v0, Ljava/lang/Number;

    .line 378
    .line 379
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    .line 380
    .line 381
    .line 382
    move-result-wide v30

    .line 383
    move-object v0, v12

    .line 384
    iget-wide v11, v14, Lmw/k;->a:D

    .line 385
    .line 386
    sub-double v30, v30, v11

    .line 387
    .line 388
    invoke-virtual {v14}, Lmw/k;->a()D

    .line 389
    .line 390
    .line 391
    move-result-wide v11

    .line 392
    div-double v11, v30, v11

    .line 393
    .line 394
    double-to-float v11, v11

    .line 395
    invoke-virtual {v13}, Landroid/graphics/RectF;->height()F

    .line 396
    .line 397
    .line 398
    move-result v12

    .line 399
    mul-float/2addr v12, v11

    .line 400
    sub-float v11, v29, v12

    .line 401
    .line 402
    float-to-double v11, v11

    .line 403
    invoke-static {v11, v12}, Ljava/lang/Math;->ceil(D)D

    .line 404
    .line 405
    .line 406
    move-result-wide v11

    .line 407
    double-to-float v11, v11

    .line 408
    invoke-static {v11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 409
    .line 410
    .line 411
    move-result-object v11

    .line 412
    iget v12, v13, Landroid/graphics/RectF;->top:F

    .line 413
    .line 414
    iget v14, v13, Landroid/graphics/RectF;->bottom:F

    .line 415
    .line 416
    move-object/from16 v29, v0

    .line 417
    .line 418
    new-instance v0, Lgy0/e;

    .line 419
    .line 420
    invoke-direct {v0, v12, v14}, Lgy0/e;-><init>(FF)V

    .line 421
    .line 422
    .line 423
    invoke-static {v11, v0}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    check-cast v0, Ljava/lang/Number;

    .line 428
    .line 429
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 430
    .line 431
    .line 432
    move-result v0

    .line 433
    add-float v0, v0, v23

    .line 434
    .line 435
    iget v11, v13, Landroid/graphics/RectF;->top:F

    .line 436
    .line 437
    cmpl-float v11, v0, v11

    .line 438
    .line 439
    if-lez v11, :cond_5

    .line 440
    .line 441
    invoke-virtual {v5}, Landroid/graphics/Path;->rewind()V

    .line 442
    .line 443
    .line 444
    iget v11, v13, Landroid/graphics/RectF;->left:F

    .line 445
    .line 446
    iget v12, v13, Landroid/graphics/RectF;->top:F

    .line 447
    .line 448
    iget v14, v13, Landroid/graphics/RectF;->right:F

    .line 449
    .line 450
    invoke-virtual {v7, v11, v12, v14, v0}, Landroid/graphics/RectF;->set(FFFF)V

    .line 451
    .line 452
    .line 453
    sget-object v11, Landroid/graphics/Path$Direction;->CW:Landroid/graphics/Path$Direction;

    .line 454
    .line 455
    invoke-virtual {v5, v7, v11}, Landroid/graphics/Path;->addRect(Landroid/graphics/RectF;Landroid/graphics/Path$Direction;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {v4, v9}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 459
    .line 460
    .line 461
    invoke-interface/range {v28 .. v28}, Lpw/f;->e()Z

    .line 462
    .line 463
    .line 464
    move-result v11

    .line 465
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    if-eqz v11, :cond_4

    .line 469
    .line 470
    iget v11, v8, Landroid/graphics/RectF;->right:F

    .line 471
    .line 472
    goto :goto_3

    .line 473
    :cond_4
    iget v11, v8, Landroid/graphics/RectF;->left:F

    .line 474
    .line 475
    :goto_3
    iget v12, v13, Landroid/graphics/RectF;->bottom:F

    .line 476
    .line 477
    invoke-virtual {v4, v11, v12}, Landroid/graphics/Path;->lineTo(FF)V

    .line 478
    .line 479
    .line 480
    invoke-interface/range {v28 .. v28}, Lpw/f;->e()Z

    .line 481
    .line 482
    .line 483
    move-result v11

    .line 484
    invoke-static {v8, v11}, Ljp/ae;->a(Landroid/graphics/RectF;Z)F

    .line 485
    .line 486
    .line 487
    move-result v11

    .line 488
    iget v12, v13, Landroid/graphics/RectF;->bottom:F

    .line 489
    .line 490
    invoke-virtual {v4, v11, v12}, Landroid/graphics/Path;->lineTo(FF)V

    .line 491
    .line 492
    .line 493
    invoke-virtual {v4}, Landroid/graphics/Path;->close()V

    .line 494
    .line 495
    .line 496
    sget-object v11, Landroid/graphics/Path$Op;->INTERSECT:Landroid/graphics/Path$Op;

    .line 497
    .line 498
    invoke-virtual {v4, v5, v11}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 499
    .line 500
    .line 501
    const-string v11, "context"

    .line 502
    .line 503
    invoke-static {v2, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 504
    .line 505
    .line 506
    const-string v11, "path"

    .line 507
    .line 508
    invoke-static {v4, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 509
    .line 510
    .line 511
    const-string v11, "fillBounds"

    .line 512
    .line 513
    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 514
    .line 515
    .line 516
    iget-object v11, v3, Lnw/h;->i:Landroid/graphics/Path;

    .line 517
    .line 518
    invoke-virtual {v11, v4}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;)V

    .line 519
    .line 520
    .line 521
    :cond_5
    iget v11, v13, Landroid/graphics/RectF;->bottom:F

    .line 522
    .line 523
    cmpg-float v11, v0, v11

    .line 524
    .line 525
    if-gez v11, :cond_7

    .line 526
    .line 527
    invoke-virtual {v5}, Landroid/graphics/Path;->rewind()V

    .line 528
    .line 529
    .line 530
    iget v11, v13, Landroid/graphics/RectF;->left:F

    .line 531
    .line 532
    iget v12, v13, Landroid/graphics/RectF;->right:F

    .line 533
    .line 534
    iget v14, v13, Landroid/graphics/RectF;->bottom:F

    .line 535
    .line 536
    invoke-virtual {v7, v11, v0, v12, v14}, Landroid/graphics/RectF;->set(FFFF)V

    .line 537
    .line 538
    .line 539
    sget-object v0, Landroid/graphics/Path$Direction;->CW:Landroid/graphics/Path$Direction;

    .line 540
    .line 541
    invoke-virtual {v5, v7, v0}, Landroid/graphics/Path;->addRect(Landroid/graphics/RectF;Landroid/graphics/Path$Direction;)V

    .line 542
    .line 543
    .line 544
    invoke-virtual {v4, v9}, Landroid/graphics/Path;->set(Landroid/graphics/Path;)V

    .line 545
    .line 546
    .line 547
    invoke-interface/range {v28 .. v28}, Lpw/f;->e()Z

    .line 548
    .line 549
    .line 550
    move-result v0

    .line 551
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    if-eqz v0, :cond_6

    .line 555
    .line 556
    iget v0, v8, Landroid/graphics/RectF;->right:F

    .line 557
    .line 558
    goto :goto_4

    .line 559
    :cond_6
    iget v0, v8, Landroid/graphics/RectF;->left:F

    .line 560
    .line 561
    :goto_4
    iget v6, v13, Landroid/graphics/RectF;->top:F

    .line 562
    .line 563
    invoke-virtual {v4, v0, v6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 564
    .line 565
    .line 566
    invoke-interface/range {v28 .. v28}, Lpw/f;->e()Z

    .line 567
    .line 568
    .line 569
    move-result v0

    .line 570
    invoke-static {v8, v0}, Ljp/ae;->a(Landroid/graphics/RectF;Z)F

    .line 571
    .line 572
    .line 573
    move-result v0

    .line 574
    iget v6, v13, Landroid/graphics/RectF;->top:F

    .line 575
    .line 576
    invoke-virtual {v4, v0, v6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 577
    .line 578
    .line 579
    invoke-virtual {v4}, Landroid/graphics/Path;->close()V

    .line 580
    .line 581
    .line 582
    sget-object v0, Landroid/graphics/Path$Op;->INTERSECT:Landroid/graphics/Path$Op;

    .line 583
    .line 584
    invoke-virtual {v4, v5, v0}, Landroid/graphics/Path;->op(Landroid/graphics/Path;Landroid/graphics/Path$Op;)Z

    .line 585
    .line 586
    .line 587
    const-string v0, "context"

    .line 588
    .line 589
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 590
    .line 591
    .line 592
    const-string v0, "path"

    .line 593
    .line 594
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 595
    .line 596
    .line 597
    const-string v0, "fillBounds"

    .line 598
    .line 599
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 600
    .line 601
    .line 602
    iget-object v0, v3, Lnw/h;->i:Landroid/graphics/Path;

    .line 603
    .line 604
    invoke-virtual {v0, v4}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;)V

    .line 605
    .line 606
    .line 607
    :cond_7
    invoke-virtual {v7, v13}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 608
    .line 609
    .line 610
    const-string v0, "context"

    .line 611
    .line 612
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 613
    .line 614
    .line 615
    const-string v0, "fillBounds"

    .line 616
    .line 617
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 618
    .line 619
    .line 620
    iget-object v0, v3, Lnw/h;->h:Landroid/graphics/Paint;

    .line 621
    .line 622
    iget-object v4, v3, Lnw/h;->f:Lpw/d;

    .line 623
    .line 624
    iget v5, v4, Lpw/d;->a:I

    .line 625
    .line 626
    invoke-virtual {v0, v5}, Landroid/graphics/Paint;->setColor(I)V

    .line 627
    .line 628
    .line 629
    iget-object v4, v4, Lpw/d;->b:Lsw/a;

    .line 630
    .line 631
    if-eqz v4, :cond_8

    .line 632
    .line 633
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 634
    .line 635
    .line 636
    const-string v5, "context"

    .line 637
    .line 638
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 639
    .line 640
    .line 641
    const-string v5, "bounds"

    .line 642
    .line 643
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 644
    .line 645
    .line 646
    iget v6, v7, Landroid/graphics/RectF;->left:F

    .line 647
    .line 648
    iget v5, v7, Landroid/graphics/RectF;->top:F

    .line 649
    .line 650
    iget v8, v7, Landroid/graphics/RectF;->right:F

    .line 651
    .line 652
    iget v7, v7, Landroid/graphics/RectF;->bottom:F

    .line 653
    .line 654
    move-object v12, v9

    .line 655
    move-object/from16 v20, v13

    .line 656
    .line 657
    move-object/from16 v14, v25

    .line 658
    .line 659
    move-object/from16 v11, v26

    .line 660
    .line 661
    const/4 v13, 0x0

    .line 662
    move v9, v7

    .line 663
    move v7, v5

    .line 664
    move-object v5, v2

    .line 665
    move-object/from16 v2, v24

    .line 666
    .line 667
    invoke-virtual/range {v4 .. v9}, Lsw/a;->a(Lc1/h2;FFFF)Landroid/graphics/Shader;

    .line 668
    .line 669
    .line 670
    move-result-object v4

    .line 671
    goto :goto_5

    .line 672
    :cond_8
    move-object v5, v2

    .line 673
    move-object v12, v9

    .line 674
    move-object/from16 v20, v13

    .line 675
    .line 676
    move-object/from16 v2, v24

    .line 677
    .line 678
    move-object/from16 v14, v25

    .line 679
    .line 680
    move-object/from16 v11, v26

    .line 681
    .line 682
    const/4 v13, 0x0

    .line 683
    const/4 v4, 0x0

    .line 684
    :goto_5
    invoke-virtual {v0, v4}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 685
    .line 686
    .line 687
    iget-object v4, v5, Lc1/h2;->d:Ljava/lang/Object;

    .line 688
    .line 689
    check-cast v4, Landroid/graphics/Canvas;

    .line 690
    .line 691
    iget-object v3, v3, Lnw/h;->i:Landroid/graphics/Path;

    .line 692
    .line 693
    invoke-virtual {v4, v3, v0}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 694
    .line 695
    .line 696
    goto :goto_6

    .line 697
    :cond_9
    move-object/from16 v20, v5

    .line 698
    .line 699
    move-object v5, v2

    .line 700
    move-object/from16 v2, v20

    .line 701
    .line 702
    move-object/from16 v27, v11

    .line 703
    .line 704
    move-object/from16 v29, v12

    .line 705
    .line 706
    move-object/from16 v20, v13

    .line 707
    .line 708
    move-object/from16 v28, v14

    .line 709
    .line 710
    const/4 v13, 0x0

    .line 711
    move-object v14, v7

    .line 712
    move-object v11, v8

    .line 713
    move-object v12, v9

    .line 714
    :goto_6
    invoke-virtual {v11, v12, v2}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 715
    .line 716
    .line 717
    iget-object v0, v5, Lc1/h2;->d:Ljava/lang/Object;

    .line 718
    .line 719
    check-cast v0, Landroid/graphics/Canvas;

    .line 720
    .line 721
    iput-object v11, v5, Lc1/h2;->d:Ljava/lang/Object;

    .line 722
    .line 723
    iget-object v2, v14, Lnw/e;->a:Lnw/i;

    .line 724
    .line 725
    iget-object v2, v2, Lnw/i;->b:Landroid/graphics/Paint;

    .line 726
    .line 727
    invoke-virtual {v2, v13}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 728
    .line 729
    .line 730
    iget-object v3, v5, Lc1/h2;->d:Ljava/lang/Object;

    .line 731
    .line 732
    check-cast v3, Landroid/graphics/Canvas;

    .line 733
    .line 734
    invoke-virtual {v3, v2}, Landroid/graphics/Canvas;->drawPaint(Landroid/graphics/Paint;)V

    .line 735
    .line 736
    .line 737
    const-string v2, "<set-?>"

    .line 738
    .line 739
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    iput-object v0, v5, Lc1/h2;->d:Ljava/lang/Object;

    .line 743
    .line 744
    const/4 v7, 0x0

    .line 745
    invoke-virtual {v0, v10, v7, v7, v13}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;FFLandroid/graphics/Paint;)V

    .line 746
    .line 747
    .line 748
    new-instance v6, Lnw/c;

    .line 749
    .line 750
    invoke-direct {v6, v1, v5, v10}, Lnw/c;-><init>(Lnw/g;Lc1/h2;Landroid/graphics/Bitmap;)V

    .line 751
    .line 752
    .line 753
    move-object v2, v5

    .line 754
    move-object v5, v13

    .line 755
    move/from16 v4, v18

    .line 756
    .line 757
    move-object/from16 v3, v22

    .line 758
    .line 759
    invoke-virtual/range {v1 .. v6}, Lnw/g;->c(Lc1/h2;Ljava/util/List;FLjava/util/Map;Lay0/q;)V

    .line 760
    .line 761
    .line 762
    new-instance v6, Lnw/d;

    .line 763
    .line 764
    move/from16 v0, v19

    .line 765
    .line 766
    invoke-direct {v6, v14, v0, v2, v1}, Lnw/d;-><init>(Lnw/e;ILc1/h2;Lnw/g;)V

    .line 767
    .line 768
    .line 769
    invoke-virtual/range {v1 .. v6}, Lnw/g;->c(Lc1/h2;Ljava/util/List;FLjava/util/Map;Lay0/q;)V

    .line 770
    .line 771
    .line 772
    iget-object v0, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 773
    .line 774
    check-cast v0, Landroid/graphics/Canvas;

    .line 775
    .line 776
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 777
    .line 778
    .line 779
    move-object/from16 v0, p0

    .line 780
    .line 781
    move-object/from16 v3, p1

    .line 782
    .line 783
    move-object v4, v2

    .line 784
    move v10, v7

    .line 785
    move-object v8, v11

    .line 786
    move-object v9, v12

    .line 787
    move/from16 v5, v17

    .line 788
    .line 789
    move-object/from16 v13, v20

    .line 790
    .line 791
    move-object/from16 v11, v27

    .line 792
    .line 793
    move-object/from16 v14, v28

    .line 794
    .line 795
    move-object/from16 v12, v29

    .line 796
    .line 797
    move-object v2, v1

    .line 798
    goto/16 :goto_2

    .line 799
    .line 800
    :cond_a
    const/4 v5, 0x0

    .line 801
    invoke-static {}, Ljp/k1;->r()V

    .line 802
    .line 803
    .line 804
    throw v5

    .line 805
    :cond_b
    move-object v1, v2

    .line 806
    move-object v0, v12

    .line 807
    invoke-virtual {v0, v15}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 808
    .line 809
    .line 810
    iget-object v0, v1, Lnw/g;->k:Ljava/util/LinkedHashMap;

    .line 811
    .line 812
    move-object/from16 v1, p0

    .line 813
    .line 814
    iget-object v1, v1, Lb81/c;->f:Ljava/lang/Object;

    .line 815
    .line 816
    check-cast v1, Lkw/d;

    .line 817
    .line 818
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 819
    .line 820
    .line 821
    move-result-object v0

    .line 822
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 823
    .line 824
    .line 825
    move-result-object v0

    .line 826
    :goto_7
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 827
    .line 828
    .line 829
    move-result v2

    .line 830
    if-eqz v2, :cond_d

    .line 831
    .line 832
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 833
    .line 834
    .line 835
    move-result-object v2

    .line 836
    check-cast v2, Ljava/util/Map$Entry;

    .line 837
    .line 838
    iget-object v3, v1, Lkw/d;->j:Ljava/util/TreeMap;

    .line 839
    .line 840
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 841
    .line 842
    .line 843
    move-result-object v4

    .line 844
    invoke-virtual {v3, v4}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v5

    .line 848
    if-nez v5, :cond_c

    .line 849
    .line 850
    new-instance v5, Ljava/util/ArrayList;

    .line 851
    .line 852
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 853
    .line 854
    .line 855
    invoke-virtual {v3, v4, v5}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 856
    .line 857
    .line 858
    :cond_c
    check-cast v5, Ljava/util/Collection;

    .line 859
    .line 860
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 861
    .line 862
    .line 863
    move-result-object v2

    .line 864
    check-cast v2, Ljava/lang/Iterable;

    .line 865
    .line 866
    invoke-static {v2, v5}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 867
    .line 868
    .line 869
    goto :goto_7

    .line 870
    :cond_d
    :goto_8
    return-void

    .line 871
    :cond_e
    const/4 v5, 0x0

    .line 872
    const-string v0, "context"

    .line 873
    .line 874
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    throw v5
.end method

.method public r()Ljava/util/Collection;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Ljava/util/Map$Entry;

    .line 29
    .line 30
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lh0/l2;

    .line 35
    .line 36
    iget-boolean v2, v2, Lh0/l2;->e:Z

    .line 37
    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lh0/l2;

    .line 45
    .line 46
    iget-object v1, v1, Lh0/l2;->b:Lh0/o2;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableCollection(Ljava/util/Collection;)Ljava/util/Collection;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public s(Ljava/lang/String;)Z
    .locals 1

    .line 1
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lh0/l2;

    .line 18
    .line 19
    iget-boolean p0, p0, Lh0/l2;->e:Z

    .line 20
    .line 21
    return p0
.end method

.method public t(Landroid/view/View;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Li9/d;

    .line 4
    .line 5
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lka/e1;

    .line 8
    .line 9
    invoke-interface {p0}, Lka/e1;->c()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-interface {p0}, Lka/e1;->n()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    invoke-interface {p0, p1}, Lka/e1;->b(Landroid/view/View;)I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    invoke-interface {p0, p1}, Lka/e1;->s(Landroid/view/View;)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    iput v1, v0, Li9/d;->b:I

    .line 26
    .line 27
    iput v2, v0, Li9/d;->c:I

    .line 28
    .line 29
    iput v3, v0, Li9/d;->d:I

    .line 30
    .line 31
    iput p0, v0, Li9/d;->e:I

    .line 32
    .line 33
    const/16 p0, 0x6003

    .line 34
    .line 35
    iput p0, v0, Li9/d;->a:I

    .line 36
    .line 37
    invoke-virtual {v0}, Li9/d;->a()Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget v0, p0, Lb81/c;->d:I

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
    const/16 v1, 0x64

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const/16 v1, 0x7b

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    const/4 v2, 0x0

    .line 45
    :goto_0
    if-ge v2, v1, :cond_1

    .line 46
    .line 47
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Ljava/lang/String;

    .line 52
    .line 53
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    add-int/lit8 v3, v1, -0x1

    .line 57
    .line 58
    if-ge v2, v3, :cond_0

    .line 59
    .line 60
    const-string v3, ", "

    .line 61
    .line 62
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_1
    const/16 p0, 0x7d

    .line 69
    .line 70
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x13
        :pswitch_0
    .end packed-switch
.end method

.method public v(Lsp/k;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ljava/util/HashMap;

    .line 15
    .line 16
    invoke-virtual {p0, v1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public w()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 14
    .line 15
    .line 16
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    if-ltz v0, :cond_0

    .line 18
    .line 19
    monitor-exit p0

    .line 20
    return-void

    .line 21
    :cond_0
    :try_start_1
    const-string v0, "Unbalanced call to unblock() detected."

    .line 22
    .line 23
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    :catchall_0
    move-exception v0

    .line 30
    monitor-exit p0

    .line 31
    throw v0
.end method

.method public x(Lh0/a0;Lb0/e;)V
    .locals 6

    .line 1
    const/4 v0, 0x5

    .line 2
    if-eqz p2, :cond_0

    .line 3
    .line 4
    iget v1, p2, Lb0/e;->a:I

    .line 5
    .line 6
    const/16 v2, 0x8

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    new-instance v1, Lb0/d;

    .line 11
    .line 12
    invoke-direct {v1, v0, p2}, Lb0/d;-><init>(ILb0/e;)V

    .line 13
    .line 14
    .line 15
    goto/16 :goto_2

    .line 16
    .line 17
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v2, 0x2

    .line 22
    packed-switch v1, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    new-instance p2, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v0, "Unknown internal camera state: "

    .line 30
    .line 31
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :pswitch_0
    new-instance v1, Lb0/d;

    .line 46
    .line 47
    const/4 v0, 0x3

    .line 48
    invoke-direct {v1, v0, p2}, Lb0/d;-><init>(ILb0/e;)V

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :pswitch_1
    new-instance v1, Lb0/d;

    .line 53
    .line 54
    invoke-direct {v1, v2, p2}, Lb0/d;-><init>(ILb0/e;)V

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :pswitch_2
    iget-object v0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Lh0/k0;

    .line 61
    .line 62
    iget-object v1, v0, Lh0/k0;->b:Ljava/lang/Object;

    .line 63
    .line 64
    monitor-enter v1

    .line 65
    :try_start_0
    iget-object v0, v0, Lh0/k0;->e:Ljava/util/HashMap;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    const/4 v4, 0x0

    .line 80
    if-eqz v3, :cond_2

    .line 81
    .line 82
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Ljava/util/Map$Entry;

    .line 87
    .line 88
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    check-cast v3, Lh0/j0;

    .line 93
    .line 94
    iget-object v3, v3, Lh0/j0;->a:Lh0/a0;

    .line 95
    .line 96
    sget-object v5, Lh0/a0;->i:Lh0/a0;

    .line 97
    .line 98
    if-ne v3, v5, :cond_1

    .line 99
    .line 100
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    new-instance v0, Lb0/d;

    .line 102
    .line 103
    invoke-direct {v0, v2, v4}, Lb0/d;-><init>(ILb0/e;)V

    .line 104
    .line 105
    .line 106
    :goto_0
    move-object v1, v0

    .line 107
    goto :goto_2

    .line 108
    :catchall_0
    move-exception p0

    .line 109
    goto :goto_1

    .line 110
    :cond_2
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 111
    new-instance v0, Lb0/d;

    .line 112
    .line 113
    const/4 v1, 0x1

    .line 114
    invoke-direct {v0, v1, v4}, Lb0/d;-><init>(ILb0/e;)V

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :goto_1
    :try_start_2
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 119
    throw p0

    .line 120
    :pswitch_3
    new-instance v1, Lb0/d;

    .line 121
    .line 122
    const/4 v0, 0x4

    .line 123
    invoke-direct {v1, v0, p2}, Lb0/d;-><init>(ILb0/e;)V

    .line 124
    .line 125
    .line 126
    goto :goto_2

    .line 127
    :pswitch_4
    new-instance v1, Lb0/d;

    .line 128
    .line 129
    invoke-direct {v1, v0, p2}, Lb0/d;-><init>(ILb0/e;)V

    .line 130
    .line 131
    .line 132
    :goto_2
    const-string v0, "CameraStateMachine"

    .line 133
    .line 134
    new-instance v2, Ljava/lang/StringBuilder;

    .line 135
    .line 136
    const-string v3, "New public camera state "

    .line 137
    .line 138
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    const-string v3, " from "

    .line 145
    .line 146
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string p1, " and "

    .line 153
    .line 154
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    invoke-static {v0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    iget-object p1, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast p1, Landroidx/lifecycle/i0;

    .line 170
    .line 171
    invoke-virtual {p1}, Landroidx/lifecycle/g0;->d()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    check-cast p1, Lb0/d;

    .line 176
    .line 177
    invoke-static {p1, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result p1

    .line 181
    if-nez p1, :cond_3

    .line 182
    .line 183
    const-string p1, "CameraStateMachine"

    .line 184
    .line 185
    new-instance p2, Ljava/lang/StringBuilder;

    .line 186
    .line 187
    const-string v0, "Publishing new public camera state "

    .line 188
    .line 189
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object p2

    .line 199
    invoke-static {p1, p2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast p0, Landroidx/lifecycle/i0;

    .line 205
    .line 206
    invoke-virtual {p0, v1}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    :cond_3
    return-void

    .line 210
    nop

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_4
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public y(Ljava/lang/String;Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance v0, Lh0/l2;

    .line 13
    .line 14
    invoke-direct {v0, p2, p3, p4, p5}, Lh0/l2;-><init>(Lh0/z1;Lh0/o2;Lh0/k;Ljava/util/List;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    check-cast p2, Lh0/l2;

    .line 22
    .line 23
    iget-boolean p3, p2, Lh0/l2;->e:Z

    .line 24
    .line 25
    iput-boolean p3, v0, Lh0/l2;->e:Z

    .line 26
    .line 27
    iget-boolean p2, p2, Lh0/l2;->f:Z

    .line 28
    .line 29
    iput-boolean p2, v0, Lh0/l2;->f:Z

    .line 30
    .line 31
    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    return-void
.end method
