.class public abstract Ln7/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/s1;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    const-class v1, Landroidx/lifecycle/x;

    .line 3
    .line 4
    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    const-string v2, "androidx.compose.ui.platform.AndroidCompositionLocals_androidKt"

    .line 12
    .line 13
    const-string v3, "getLocalLifecycleOwner"

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-virtual {v1, v3, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v1}, Ljava/lang/reflect/AccessibleObject;->getAnnotations()[Ljava/lang/annotation/Annotation;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    array-length v3, v2

    .line 28
    const/4 v4, 0x0

    .line 29
    :goto_0
    if-ge v4, v3, :cond_2

    .line 30
    .line 31
    aget-object v5, v2, v4

    .line 32
    .line 33
    instance-of v5, v5, Llx0/c;

    .line 34
    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    :cond_0
    move-object v1, v0

    .line 38
    goto :goto_2

    .line 39
    :cond_1
    add-int/lit8 v4, v4, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception v1

    .line 43
    goto :goto_1

    .line 44
    :cond_2
    invoke-virtual {v1, v0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    instance-of v2, v1, Ll2/s1;

    .line 49
    .line 50
    if-eqz v2, :cond_0

    .line 51
    .line 52
    check-cast v1, Ll2/s1;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :goto_1
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    :goto_2
    instance-of v2, v1, Llx0/n;

    .line 60
    .line 61
    if-eqz v2, :cond_3

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    move-object v0, v1

    .line 65
    :goto_3
    check-cast v0, Ll2/s1;

    .line 66
    .line 67
    if-nez v0, :cond_4

    .line 68
    .line 69
    new-instance v0, Lmz0/b;

    .line 70
    .line 71
    const/16 v1, 0xc

    .line 72
    .line 73
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 74
    .line 75
    .line 76
    new-instance v1, Ll2/u2;

    .line 77
    .line 78
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 79
    .line 80
    .line 81
    move-object v0, v1

    .line 82
    :cond_4
    sput-object v0, Ln7/c;->a:Ll2/s1;

    .line 83
    .line 84
    return-void
.end method
